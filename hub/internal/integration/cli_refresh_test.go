package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Real vey processes share their normal private credential file/flock. Their
// first API reads wait until every process has refreshed, reproducing the
// scheduling window seen on the VM without retrying any remote execution.
func TestCLIParallelRefreshKeepsEarlierProcessAccessValid(t *testing.T) {
	h := StartHarness(t)
	setup := registerUser(t, h, "parallel_cli", "parallel_cli@test.invalid", "ParallelCLI!Password123")
	secret := setupTOTP(t, h, setup)
	_, refresh := enableTOTP(t, h, secret, setup)
	user, err := h.Store.GetUserByUsername("parallel_cli")
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := url.Parse(fmt.Sprintf("http://%s", h.HTTPAddr))
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	const processes = 8
	allRotated := make(chan struct{})
	var rotations atomic.Int32
	var closeOnce sync.Once
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/servers" {
			select {
			case <-allRotated:
			case <-r.Context().Done():
				return
			}
		}
		proxy.ServeHTTP(w, r)
		if r.Method == http.MethodPost && r.URL.Path == "/api/auth/refresh" && rotations.Add(1) == processes {
			closeOnce.Do(func() { close(allRotated) })
		}
	}))
	t.Cleanup(front.Close)
	configRoot := t.TempDir()
	configDir := filepath.Join(configRoot, "vey")
	if err := os.Mkdir(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	credentials := map[string]map[string]any{front.URL: {"refresh_token": refresh, "username": user.Username, "role": user.Role, "obtained_at": time.Now()}}
	encoded, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "credentials.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := make(chan struct{})
	errs := make(chan error, processes)
	var workers sync.WaitGroup
	for range processes {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			cmd := exec.CommandContext(ctx, cliBinaryPath, "--hub", front.URL, "--json", "servers", "list", "--limit", "1")
			for _, variable := range os.Environ() {
				if !strings.HasPrefix(variable, "VEYPORT_TOKEN=") && !strings.HasPrefix(variable, "XDG_CONFIG_HOME=") && !strings.HasPrefix(variable, "DBUS_SESSION_BUS_ADDRESS=") {
					cmd.Env = append(cmd.Env, variable)
				}
			}
			cmd.Env = append(cmd.Env, "XDG_CONFIG_HOME="+configRoot, "DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent-vey-test-keyring")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				errs <- fmt.Errorf("CLI process failed: %T", err)
				return
			}
			var result struct {
				Total int `json:"total"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Total != 0 {
				errs <- fmt.Errorf("CLI result is not the empty server page")
				return
			}
			errs <- nil
		}()
	}
	close(start)
	workers.Wait()
	close(errs)
	closeOnce.Do(func() { close(allRotated) })
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if got := rotations.Load(); got != processes {
		t.Errorf("refresh requests=%d, want %d without access retries", got, processes)
	}
	after, err := h.Store.GetUserByID(user.ID)
	if err != nil || after.TokenGeneration != user.TokenGeneration {
		t.Fatalf("routine CLI refresh changed user revocation generation: err=%v", err)
	}
}
