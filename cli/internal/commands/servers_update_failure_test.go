package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

type remoteUpdatePoll func(int32, *http.Request) (api.AgentUpdate, int)
type remoteUpdateCLIFlow struct {
	server               *httptest.Server
	dir                  string
	check                map[string]any
	start                api.AgentUpdateStart
	checkCode, startCode int
	posts, polls         atomic.Int32
	poll                 atomic.Pointer[remoteUpdatePoll]
}

func (f *remoteUpdateCLIFlow) setPoll(p remoteUpdatePoll) { f.poll.Store(&p) }

func remoteUpdateFlow(t *testing.T) *remoteUpdateCLIFlow {
	t.Helper()
	mux, srv, dir := seedForServers(t, "token")
	artifact := api.AgentArtifact{Version: "2.0.1-prototype.4", Revision: strings.Repeat("f", 40), SHA256: strings.Repeat("a", 64)}
	f := &remoteUpdateCLIFlow{server: srv, dir: dir, check: map[string]any{"supported": true, "update_available": true, "target": artifact}, start: api.AgentUpdateStart{Operation: api.AgentUpdate{ID: "recorded-operation", NodeID: "node", State: "requested", Target: artifact}}}
	mux.HandleFunc("GET /api/servers/node", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(api.Server{ID: "node"}) })
	mux.HandleFunc("GET /api/servers/node/agent-update", func(w http.ResponseWriter, _ *http.Request) {
		if f.checkCode != 0 {
			w.WriteHeader(f.checkCode)
			json.NewEncoder(w).Encode(map[string]string{"error": "maintenance refused"})
			return
		}
		json.NewEncoder(w).Encode(f.check)
	})
	mux.HandleFunc("POST /api/servers/node/agent-update", func(w http.ResponseWriter, _ *http.Request) {
		f.posts.Add(1)
		if f.startCode != 0 {
			w.WriteHeader(f.startCode)
			json.NewEncoder(w).Encode(map[string]string{"error": "checked artifact changed"})
			return
		}
		json.NewEncoder(w).Encode(f.start)
	})
	mux.HandleFunc("GET /api/servers/node/agent-update/status", func(w http.ResponseWriter, r *http.Request) {
		count := f.polls.Add(1)
		if r.URL.Query().Get("operation_id") != "recorded-operation" {
			t.Error("poll changed recorded operation binding")
		}
		result, code := f.start.Operation, http.StatusOK
		if poll := f.poll.Load(); poll != nil {
			result, code = (*poll)(count, r)
		} else {
			result.State = "succeeded"
			result.ObservedVersion = result.Target.Version
			result.ObservedRevision = result.Target.Revision
			result.ObservedSHA256 = result.Target.SHA256
		}
		w.WriteHeader(code)
		if code != http.StatusOK {
			json.NewEncoder(w).Encode(map[string]string{"error": "status temporarily unavailable"})
		} else {
			json.NewEncoder(w).Encode(result)
		}
	})
	return f
}

func TestServersUpdatePollFailureRetainsOperationAndNeverStartsAgain(t *testing.T) {
	f := remoteUpdateFlow(t)
	f.setPoll(func(int32, *http.Request) (api.AgentUpdate, int) {
		return api.AgentUpdate{}, http.StatusServiceUnavailable
	})
	ctx, out, stderr := newCmdContext(f.server.URL, f.dir, true, []string{"update", "node"})
	if code := RunServers(ctx); code == 0 {
		t.Fatal("poll failure claimed verified success")
	}
	if f.posts.Load() != 1 || f.polls.Load() != 1 {
		t.Fatal("poll failure retried mutation", f.posts.Load(), f.polls.Load())
	}
	if out.Len() != 0 {
		t.Fatal("unconfirmed operation emitted a success payload", out.String())
	}
	if !strings.Contains(stderr.String(), "--status --operation recorded-operation") {
		t.Fatal("poll failure omitted exact resume command", stderr.String())
	}
}

func TestServersUpdateRefusesMismatchedResponsesAndMalformedBootstrapTicket(t *testing.T) {
	for _, phase := range []string{"missing-start-id", "wrong-start-node", "wrong-status-id", "wrong-status-node", "invalid-ticket"} {
		t.Run(phase, func(t *testing.T) {
			f := remoteUpdateFlow(t)
			switch phase {
			case "missing-start-id":
				f.start.Operation.ID = ""
			case "wrong-start-node":
				f.start.Operation.NodeID = "other-node"
			case "wrong-status-id", "wrong-status-node":
				f.setPoll(func(_ int32, _ *http.Request) (api.AgentUpdate, int) {
					result := f.start.Operation
					if phase == "wrong-status-id" {
						result.ID = "other-operation"
					} else {
						result.NodeID = "other-node"
					}
					result.State = "succeeded"
					return result, http.StatusOK
				})
			case "invalid-ticket":
				f.start.BootstrapTicket = "invalid"
			}
			ctx, out, stderr := newCmdContext(f.server.URL, f.dir, true, []string{"update", "node"})
			if code := RunServers(ctx); code == 0 {
				t.Fatal("mismatched update response accepted", phase)
			}
			if f.posts.Load() != 1 || out.Len() != 0 {
				t.Fatal("bad response retried or printed usable command", phase, out.String(), stderr.String())
			}
		})
	}
}

func TestServersUpdatePendingConfirmationCannotBeReportedAsCurrentSuccess(t *testing.T) {
	for _, state := range []string{"confirmation_pending", "rollback_confirmation_pending", "unknown"} {
		t.Run(state, func(t *testing.T) {
			f := remoteUpdateFlow(t)
			f.check["update_available"] = false
			f.check["operation"] = api.AgentUpdate{ID: "recorded-operation", State: state}
			ctx, out, stderr := newCmdContext(f.server.URL, f.dir, false, []string{"update", "node"})
			if code := RunServers(ctx); code == 0 || f.posts.Load() != 0 || out.Len() != 0 {
				t.Fatal("unconfirmed replacement was reported current", code, out.String())
			}
			if !strings.Contains(stderr.String(), "--status") {
				t.Fatal("pending confirmation omitted status guidance")
			}
		})
	}
}

func TestServersUpdateWaitsForSameOperationFinalAcknowledgement(t *testing.T) {
	f := remoteUpdateFlow(t)
	f.setPoll(func(count int32, _ *http.Request) (api.AgentUpdate, int) {
		result := f.start.Operation
		if count == 1 {
			result.State = "confirmation_pending"
		} else {
			result.State = "succeeded"
			result.ObservedVersion = result.Target.Version
			result.ObservedRevision = result.Target.Revision
			result.ObservedSHA256 = result.Target.SHA256
		}
		return result, http.StatusOK
	})
	ctx, out, stderr := newCmdContext(f.server.URL, f.dir, false, []string{"update", "node"})
	if code := RunServers(ctx); code != 0 || f.posts.Load() != 1 || f.polls.Load() != 2 {
		t.Fatal("did not wait for exact final acknowledgement", code, f.posts.Load(), f.polls.Load(), stderr.String())
	}
	if !strings.Contains(out.String(), "State: succeeded") {
		t.Fatal("verified final outcome missing", out.String())
	}
}

func TestServersUpdatePermissionAndStaleArtifactErrorsDoNotStartOrRetry(t *testing.T) {
	for _, phase := range []string{"check", "start"} {
		t.Run(phase, func(t *testing.T) {
			f := remoteUpdateFlow(t)
			if phase == "check" {
				f.checkCode = http.StatusForbidden
			} else {
				f.startCode = http.StatusConflict
			}
			ctx, out, stderr := newCmdContext(f.server.URL, f.dir, false, []string{"update", "node"})
			if code := RunServers(ctx); code == 0 || out.Len() != 0 {
				t.Fatal("refused request reported success", code, out.String())
			}
			want := int32(0)
			if phase == "start" {
				want = 1
			}
			if f.posts.Load() != want || f.polls.Load() != 0 {
				t.Fatal("refused request launched or retried an update", f.posts.Load(), f.polls.Load(), stderr.String())
			}
		})
	}
}

type remoteUpdateClosedWriter struct{}

func (remoteUpdateClosedWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }
func TestServersUpdateFailedTerminalOutputCannotReturnSuccess(t *testing.T) {
	f := remoteUpdateFlow(t)
	f.setPoll(func(int32, *http.Request) (api.AgentUpdate, int) {
		result := f.start.Operation
		result.State = "rolled_back"
		return result, http.StatusOK
	})
	ctx, _, stderr := newCmdContext(f.server.URL, f.dir, false, []string{"update", "node"})
	ctx.Printer = cmdutil.NewPrinter(remoteUpdateClosedWriter{}, stderr, false)
	if code := RunServers(ctx); code == 0 || f.posts.Load() != 1 {
		t.Fatal("failed terminal output claimed success or retried", code, stderr.String())
	}
}

func TestServersUpdateInvalidFlagsFailBeforeCredentialsOrNetwork(t *testing.T) {
	for _, args := range [][]string{{"node", "--check", "--check"}, {"node", "--status", "--status"}, {"node", "--operation"}, {"node", "--status", "--operation", "--check"}, {"node", "--status", "--operation", "a", "--operation", "b"}, {"node", "--acknowledge-recovery", "a", "--acknowledge-recovery", "b", "--verified-sha256", "hash"}, {"node", "--acknowledge-recovery", "a", "--verified-sha256", "one", "--verified-sha256", "two"}} {
		ctx, _, stderr := newCmdContext("", t.TempDir(), false, append([]string{"update"}, args...))
		if code := RunServers(ctx); code != cmdutil.ExitUsage {
			t.Fatal("invalid flags reached credentials or Hub", args, code, stderr.String())
		}
	}
	ctx, _, stderr := newCmdContext("", t.TempDir(), false, []string{"update", "node"})
	if code := RunServers(ctx); code != cmdutil.ExitUsage {
		t.Fatal("missing Hub did not fail locally", code, stderr.String())
	}
	t.Setenv("VEYPORT_TOKEN", "invalid-token-canary")
	ctx, _, stderr = newCmdContext("https://hub.invalid", t.TempDir(), false, []string{"update", "node"})
	if code := RunServers(ctx); code != cmdutil.ExitUsage || strings.Contains(stderr.String(), "canary") {
		t.Fatal("invalid credential was sent/disclosed", code, stderr.String())
	}
}

const remoteUpdateInterruptFixture = "VEYPORT_TEST_REMOTE_UPDATE_INTERRUPT"

// A real process receives SIGINT so the root test runner cannot accidentally
// consume the CLI's signal or terminate other tests.
func TestServersUpdateInterruptedProcessFixture(t *testing.T) {
	if os.Getenv(remoteUpdateInterruptFixture) != "1" {
		return
	}
	ctx, out, stderr := newCmdContext(os.Getenv("VEYPORT_TEST_REMOTE_UPDATE_URL"), os.Getenv("VEYPORT_TEST_REMOTE_UPDATE_DIR"), false, []string{"update", "node"})
	code := RunServers(ctx)
	fmt.Fprint(os.Stdout, out.String())
	fmt.Fprint(os.Stderr, stderr.String())
	fmt.Fprintf(os.Stdout, "remote-update-exit=%d\n", code)
	if code == 0 {
		t.Fatal("interrupted update claimed success")
	}
}
func TestServersUpdateInterruptedPollRetainsRecordedOperation(t *testing.T) {
	f := remoteUpdateFlow(t)
	polling := make(chan struct{}, 1)
	f.setPoll(func(_ int32, r *http.Request) (api.AgentUpdate, int) {
		polling <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		return api.AgentUpdate{}, http.StatusServiceUnavailable
	})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServersUpdateInterruptedProcessFixture$", "-test.timeout=7s")
	command.Env = append(os.Environ(), remoteUpdateInterruptFixture+"=1", "VEYPORT_TEST_REMOTE_UPDATE_URL="+f.server.URL, "VEYPORT_TEST_REMOTE_UPDATE_DIR="+f.dir)
	var out, stderr bytes.Buffer
	command.Stdout = &out
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if command.ProcessState == nil {
			command.Process.Kill()
			command.Wait()
		}
	}()
	select {
	case <-polling:
	case <-ctx.Done():
		t.Fatal("child did not reach recorded operation poll")
	}
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal("isolated CLI fixture failed", err, stderr.String())
	}
	if f.posts.Load() != 1 || !strings.Contains(stderr.String(), "--status --operation recorded-operation") || strings.Contains(out.String(), "remote-update-exit=0") {
		t.Fatal("interruption lost operation or repeated mutation", f.posts.Load(), out.String(), stderr.String())
	}
}
