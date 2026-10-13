package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/server"
	"github.com/wyiu/veyport/hub/internal/sshconfig"
	"github.com/wyiu/veyport/hub/internal/sshgw"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func nativeExecCredentials(t *testing.T, h *sshGWHarness) []string {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("native OpenSSH is unavailable")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := h.userCA.SignUserCert(signer.PublicKey(), sshGWUsername, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	certPath := keyPath + "-cert.pub"
	knownPath := filepath.Join(dir, "known_hosts")
	for path, data := range map[string][]byte{keyPath: pem.EncodeToMemory(block), certPath: ssh.MarshalAuthorizedKey(cert), knownPath: []byte(knownhosts.Line([]string{h.sshAddr}, h.hostKey.PublicKey()) + "\n")} {
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	host, port, err := net.SplitHostPort(h.sshAddr)
	if err != nil {
		t.Fatal(err)
	}
	return []string{"-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + knownPath, "-i", keyPath, "-o", "CertificateFile=" + certPath, "-p", port, sshGWUsername + "+" + sshGWServerName + "@" + host}
}

func nativeCommand(t *testing.T, args []string, command string, input []byte) ([]byte, []byte, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", append(append([]string(nil), args...), command)...)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("native SSH stalled: %s", stderr.String())
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	return stdout.Bytes(), stderr.Bytes(), code
}

func startRealExecutionAgent(t *testing.T, h *sshGWHarness) {
	t.Helper()
	processHarness := &TestHarness{GRPCAddr: h.grpcAddr, HubCAPin: h.caPin}
	stop := processHarness.StartAgentProcess(t, sshGWRegToken)
	t.Cleanup(stop)
	waitFor(t, "execution capability from enrolled real agent", func() bool { return h.executions.Supports(sshGWServerID) })
}

func TestNativeSSHExecutionStreamsEOFStatusAndIdentity(t *testing.T) {
	for _, provider := range []model.AuthProvider{model.AuthProviderLocal, model.AuthProviderLDAP} {
		t.Run(string(provider), func(t *testing.T) {
			h := startSSHGWHarness(t)
			actor := h.seedAuthorizedUser(t)
			actual, err := user.Current()
			if err != nil {
				t.Fatal(err)
			}
			role := model.RoleAdmin
			ldapUser := ""
			if provider == model.AuthProviderLDAP {
				role = model.RoleViewer
				ldapUser = actual.Username
			}
			if _, err = h.store.DB().Exec(`UPDATE users SET auth_provider=?,role=?,ldap_username=? WHERE id=?`, provider, role, ldapUser, actor); err != nil {
				t.Fatal(err)
			}
			startRealExecutionAgent(t, h)
			args := nativeExecCredentials(t, h)
			for _, test := range []struct {
				name, command         string
				input, stdout, stderr []byte
				code                  int
			}{
				{"quoting", `printf '%s' 'a b; "$(false)"'`, nil, []byte(`a b; "$(false)"`), nil, 0},
				{"binary", `printf '\000\001\377'; printf 'stderr-only' >&2`, nil, []byte{0, 1, 255}, []byte("stderr-only"), 0},
				{"piped-script", `sh -s`, []byte("printf 'script-output'; printf 'script-error' >&2\nexit 42\n"), []byte("script-output"), []byte("script-error"), 42},
				{"eof", `cat; printf 'after-eof'`, []byte("stdin"), []byte("stdinafter-eof"), nil, 0},
				{"remote255", `exit 255`, nil, nil, nil, 255},
				{"signalled", `kill -TERM $$`, nil, nil, nil, 255},
			} {
				t.Run(test.name, func(t *testing.T) {
					out, errout, code := nativeCommand(t, args, test.command, test.input)
					if !bytes.Equal(out, test.stdout) || !bytes.Equal(errout, test.stderr) || code != test.code {
						t.Fatalf("stdout=%q stderr=%q exit=%d, want %q/%q/%d", out, errout, code, test.stdout, test.stderr, test.code)
					}
				})
			}
			uid, _ := strconv.Atoi(actual.Uid)
			var count int
			if err = h.store.DB().QueryRow(`SELECT COUNT(*) FROM executions WHERE actor_id=? AND state='exited' AND json_extract(preparation,'$.identity.uid')=? AND json_extract(preparation,'$.identity.username')=?`, actor, uid, actual.Username).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 6 {
				t.Fatalf("actual identity/outcome snapshots=%d, want6", count)
			}
			if err = h.store.DB().QueryRow(`SELECT COUNT(*) FROM executions e JOIN audit_logs a ON a.correlation_id=e.id WHERE e.actor_id=? AND e.signal=? AND e.exit_code IS NULL AND a.action='execution.finished' AND a.outcome='failure'`, actor, syscall.SIGTERM.String()).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatal("signal termination lost its nullable exit/signal metadata or failure audit outcome")
			}
			var auditText string
			if err = h.store.DB().QueryRow(`SELECT COALESCE(group_concat(detail),'') FROM audit_logs WHERE action LIKE 'execution.%'`).Scan(&auditText); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(auditText, "script-output") || strings.Contains(auditText, "$(false)") {
				t.Fatal("raw command leaked into ordinary audit")
			}
			if !strings.Contains(auditText, "command_sha256=") {
				t.Fatal("ordinary execution audit missing")
			}
		})
	}
}

func TestNativeSSHExecutionDrainsTailBeforeStatus(t *testing.T) {
	h := startSSHGWHarness(t)
	actor := h.seedAuthorizedUser(t)
	if _, err := h.store.DB().Exec(`UPDATE users SET auth_provider='local',role='admin' WHERE id=?`, actor); err != nil {
		t.Fatal(err)
	}
	startRealExecutionAgent(t, h)
	args := nativeExecCredentials(t, h)
	for n := 0; n < 20; n++ {
		out, errout, code := nativeCommand(t, args, `head -c 200000 /dev/zero; head -c 150000 /dev/zero >&2; printf 'TAIL'; printf 'ERRTAIL' >&2; exit 42`, nil)
		if code != 42 || len(out) != 200004 || len(errout) != 150007 || !bytes.HasSuffix(out, []byte("TAIL")) || !bytes.HasSuffix(errout, []byte("ERRTAIL")) {
			t.Fatalf("iteration%d truncated result: stdout=%d stderr=%d code=%d", n, len(out), len(errout), code)
		}
	}
}

func TestNativeSSHExecutionClientLossCancelsProcessGroup(t *testing.T) {
	h := startSSHGWHarness(t)
	actor := h.seedAuthorizedUser(t)
	if _, err := h.store.DB().Exec(`UPDATE users SET auth_provider='local',role='admin' WHERE id=?`, actor); err != nil {
		t.Fatal(err)
	}
	startRealExecutionAgent(t, h)
	args := nativeExecCredentials(t, h)
	marker := filepath.Join(t.TempDir(), "late-effect")
	command := fmt.Sprintf("printf 'ready\\n'; sleep 3; touch '%s'", marker)
	cmd := exec.Command("ssh", append(args, command)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 6)
	if _, err = io.ReadFull(stdout, buffer); err != nil {
		t.Fatal(err)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	waitFor(t, "client-loss cancellation metadata", func() bool {
		var count int
		_ = h.store.DB().QueryRow(`SELECT COUNT(*) FROM executions WHERE actor_id=? AND state='cancelled'`, actor).Scan(&count)
		return count == 1
	})
	time.Sleep(3500 * time.Millisecond)
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("managed process survived SSH client loss")
	}
}

func TestExecutionSlowConsumerDoesNotTimeoutQuietConcurrentCommand(t *testing.T) {
	h := startSSHGWHarnessWithOptions(t, func(cfg *sshgw.Config) { cfg.ExecutionConsumerTimeout = 200 * time.Millisecond })
	actor := h.seedAuthorizedUser(t)
	if _, err := h.store.DB().Exec(`UPDATE users SET auth_provider='local',role='admin' WHERE id=?`, actor); err != nil {
		t.Fatal(err)
	}
	startRealExecutionAgent(t, h)
	client := h.dialSSH(t)
	slow, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = slow.StdoutPipe(); err != nil {
		t.Fatal(err)
	} // Deliberately leave the SSH window undrained.
	if err = slow.Start(`head -c 16000000 /dev/zero`); err != nil {
		t.Fatal(err)
	}
	args := nativeExecCredentials(t, h)
	out, errout, code := nativeCommand(t, args, `sleep 0.5; printf quiet`, nil)
	if code != 0 || string(out) != "quiet" || len(errout) != 0 {
		t.Fatalf("quiet concurrent command failed: %q/%q/%d", out, errout, code)
	}
	wait := make(chan error, 1)
	go func() { wait <- slow.Wait() }()
	select {
	case err = <-wait:
		if err == nil {
			t.Fatal("blocked consumer succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked consumer was not cancelled")
	}
	waitFor(t, "slow consumer outcome", func() bool {
		var n int
		_ = h.store.DB().QueryRow(`SELECT COUNT(*) FROM executions WHERE actor_id=? AND state='cancelled' AND reason='SSH output consumer stalled'`, actor).Scan(&n)
		return n == 1
	})
}

func TestNativeSSHFastExitReleasesExecutionWithUnconsumedInput(t *testing.T) {
	h := startSSHGWHarness(t)
	actor := h.seedAuthorizedUser(t)
	if _, err := h.store.DB().Exec(`UPDATE users SET auth_provider='local',role='admin' WHERE id=?`, actor); err != nil {
		t.Fatal(err)
	}
	startRealExecutionAgent(t, h)
	args := nativeExecCredentials(t, h)
	out, errout, code := nativeCommand(t, args, `exit 0`, bytes.Repeat([]byte("x"), 8*1024*1024))
	if code != 0 || len(out) != 0 || len(errout) != 0 {
		t.Fatalf("fast exit failed: stdout=%q stderr=%q exit=%d", out, errout, code)
	}
	waitFor(t, "fast exit releases reservation", func() bool { return len(h.terminals.ListByUser(actor)) == 0 })
}

func TestNativeSSHExecutionDisableCancelsRunningWork(t *testing.T) {
	h := startSSHGWHarness(t)
	actor := h.seedAuthorizedUser(t)
	actual, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.DB().Exec(`UPDATE users SET ldap_username=? WHERE id=?`, actual.Username, actor); err != nil {
		t.Fatal(err)
	}
	startRealExecutionAgent(t, h)
	client := h.dialSSH(t)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "unauthorized-effect")
	if err = sess.Start(fmt.Sprintf("printf ready; sleep 3; touch '%s'", marker)); err != nil {
		t.Fatal(err)
	}
	ready := make([]byte, 5)
	if _, err = io.ReadFull(stdout, ready); err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.DisableUser(actor, "administrator", time.Now()); err != nil {
		t.Fatal(err)
	}
	h.terminals.EndByUser(actor, -1, "account disabled")
	if err = sess.Wait(); err == nil {
		t.Fatal("disabled execution succeeded")
	}
	waitFor(t, "disable cancellation metadata", func() bool {
		var n int
		_ = h.store.DB().QueryRow(`SELECT COUNT(*) FROM executions WHERE actor_id=? AND state='cancelled'`, actor).Scan(&n)
		return n == 1
	})
	out, errout, code := nativeCommand(t, nativeExecCredentials(t, h), `touch '`+marker+`'`, nil)
	if code == 0 || len(out) != 0 || !strings.Contains(string(errout), "access required") {
		t.Fatalf("disabled actor accepted: %q/%q/%d", out, errout, code)
	}
	time.Sleep(3500 * time.Millisecond)
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("disabled process survived")
	}
}

func startExecutionREST(t *testing.T, h *sshGWHarness) (string, string) {
	t.Helper()
	jwt, err := server.InitJWTSecret(h.store)
	if err != nil {
		t.Fatal(err)
	}
	storageKey, err := server.InitStorageKey(h.store)
	if err != nil {
		t.Fatal(err)
	}
	listener := listenLoopback(t)
	httpServer := server.New(server.Config{Addr: listener.Addr().String(), Store: h.store, JWTSecret: jwt, StorageKey: storageKey, IsDev: true, ConnMgr: h.connMgr, Pending: h.pending, TerminalSessions: h.terminals, UserCA: h.userCA, SSHHostKey: h.hostKey, SSHConfig: sshconfig.Config{Enabled: true, Addr: h.sshAddr}, Listener: listener})
	go func() { _ = httpServer.Start() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	})
	return "http://" + listener.Addr().String(), jwt
}

func TestNativeSSHExecutionSurvivesRoutineBrowserRefresh(t *testing.T) {
	h := startSSHGWHarness(t)
	actor := h.seedAuthorizedUser(t)
	if _, err := h.store.DB().Exec(`UPDATE users SET auth_provider='local',role='admin',totp_enabled=1 WHERE id=?`, actor); err != nil {
		t.Fatal(err)
	}
	startRealExecutionAgent(t, h)
	hubURL, jwt := startExecutionREST(t, h)
	current, err := h.store.GetUserByID(actor)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	session := &model.Session{ID: "browser-refresh", UserID: actor, Kind: model.SessionKindWeb, CreatedAt: now, LastSeenAt: now}
	if err = h.store.CreateSession(session); err != nil {
		t.Fatal(err)
	}
	_, refresh, err := auth.GenerateSessionTokenPair(jwt, actor, string(current.Role), current.TokenGeneration, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "ssh", append(nativeExecCredentials(t, h), `printf ready; sleep 2; printf survived`)...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make([]byte, 5)
	if _, err = io.ReadFull(stdout, ready); err != nil || string(ready) != "ready" {
		t.Fatalf("command readiness: %q %v", ready, err)
	}
	body, err := json.Marshal(model.RefreshRequest{RefreshToken: refresh})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, hubURL+"/api/auth/refresh", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("refresh: status=%d body=%s err=%v", response.StatusCode, responseBody, readErr)
	}
	after, err := h.store.GetUserByID(actor)
	if err != nil || after.TokenGeneration != current.TokenGeneration {
		t.Fatal("routine browser refresh changed user-wide revocation generation")
	}
	tail, readErr := io.ReadAll(stdout)
	err = command.Wait()
	if readErr != nil || err != nil || string(tail) != "survived" || stderr.Len() != 0 {
		t.Fatalf("independent SSH cancelled by browser refresh: tail=%q stderr=%q wait=%v read=%v", tail, stderr.String(), err, readErr)
	}
}

func TestExecutionLiveCredentialAndGrantChangesCancel(t *testing.T) {
	for _, change := range []string{"password", "mfa", "grant"} {
		t.Run(change, func(t *testing.T) {
			h := startSSHGWHarness(t)
			actor := h.seedAuthorizedUser(t)
			actual, err := user.Current()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = h.store.DB().Exec(`UPDATE users SET ldap_username=? WHERE id=?`, actual.Username, actor); err != nil {
				t.Fatal(err)
			}
			startRealExecutionAgent(t, h)
			client := h.dialSSH(t)
			session, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := session.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = session.Start(`printf ready; sleep 2; printf survived`); err != nil {
				t.Fatal(err)
			}
			ready := make([]byte, 5)
			if _, err = io.ReadFull(stdout, ready); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "password":
				err = h.store.UpdateUserPassword(actor, "changed-password-hash")
			case "mfa":
				secret := "changed-mfa-secret"
				err = h.store.UpdateUserTOTP(actor, &secret, true)
			case "grant":
				_, err = h.store.DB().Exec(`UPDATE users SET terminal_access=0 WHERE id=?`, actor)
			}
			if err != nil {
				t.Fatal(err)
			}
			tail, readErr := io.ReadAll(stdout)
			err = session.Wait()
			if err == nil || readErr != nil || len(tail) != 0 {
				t.Fatalf("revoked execution survived: tail=%q wait=%v read=%v", tail, err, readErr)
			}
			waitFor(t, "credential/grant cancellation metadata", func() bool {
				var count int
				_ = h.store.DB().QueryRow(`SELECT COUNT(*) FROM executions WHERE actor_id=? AND state='cancelled'`, actor).Scan(&count)
				return count == 1
			})
		})
	}
}

func TestBuiltVEYExecutionThroughRealRESTGatewayAndAgent(t *testing.T) {
	h := startSSHGWHarness(t)
	actor := h.seedAuthorizedUser(t)
	if _, err := h.store.DB().Exec(`UPDATE users SET auth_provider='local',role='admin',totp_enabled=1 WHERE id=?`, actor); err != nil {
		t.Fatal(err)
	}
	startRealExecutionAgent(t, h)
	hubURL, _ := startExecutionREST(t, h)
	rawToken, tokenHash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if err = h.store.CreateAPIToken(&model.APIToken{ID: "vey-integration-api-token", UserID: actor, Name: "integration", TokenHash: tokenHash, TokenPrefix: prefix}); err != nil {
		t.Fatal(err)
	}
	args := nativeExecCredentials(t, h)
	var keyPath, certPath string
	for n, arg := range args {
		if arg == "-i" {
			keyPath = args[n+1]
		}
		if strings.HasPrefix(arg, "CertificateFile=") {
			certPath = strings.TrimPrefix(arg, "CertificateFile=")
		}
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	configRoot := t.TempDir()
	configDir := filepath.Join(configRoot, "vey")
	if err = os.Mkdir(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	credentials := map[string]map[string]interface{}{hubURL: {"ssh_private_key": string(keyBytes), "ssh_certificate": string(certBytes), "ssh_cert_expires_at": time.Now().Add(time.Hour), "ssh_host_fingerprint": ssh.FingerprintSHA256(h.hostKey.PublicKey())}}
	data, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(configDir, "credentials.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		command               string
		input, stdout, stderr []byte
		code                  int
	}{
		{`printf '%s' 'a b; "$(false)"'`, nil, []byte(`a b; "$(false)"`), nil, 0},
		{`sh -s`, []byte("printf 'vey-script'; printf 'vey-error' >&2; exit 42\n"), []byte("vey-script"), []byte("vey-error"), 42},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, cliBinaryPath, "--hub", hubURL, "ssh", sshGWServerName, "--", test.command)
		cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+configRoot, "VEYPORT_TOKEN="+rawToken, "DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent-vey-test-keyring")
		cmd.Stdin = bytes.NewReader(test.input)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err = cmd.Run()
		cancel()
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal(err)
			}
			code = exit.ExitCode()
		}
		lines := strings.SplitN(stderr.String(), "\n", 2)
		remoteStderr := stderr.Bytes()
		if strings.HasPrefix(lines[0], "warning: OS keyring unavailable;") && len(lines) == 2 {
			remoteStderr = []byte(lines[1])
		}
		if code != test.code || !bytes.Equal(stdout.Bytes(), test.stdout) || !bytes.Equal(remoteStderr, test.stderr) {
			t.Fatalf("vey stdout=%q stderr=%q exit=%d, want %q/%q/%d", stdout.Bytes(), stderr.Bytes(), code, test.stdout, test.stderr, test.code)
		}
	}
}
