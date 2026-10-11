package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auditruntime"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/server"
	"github.com/wyiu/veyport/hub/internal/sshgw"
	"github.com/wyiu/veyport/hub/internal/testaudit"
	"github.com/wyiu/veyport/proto/protectedinput"
	"golang.org/x/crypto/ssh"
)

var protectedFixtureBuild sync.Once
var protectedFixturePath string
var protectedFixtureBuildErr error

func startProtectedFixtureAgent(t *testing.T, h *sshGWHarness) {
	t.Helper()
	protectedFixtureBuild.Do(func() {
		protectedFixturePath = filepath.Join(filepath.Dir(agentBinaryPath), "protected-agent-test")
		cmd := exec.Command("go", "test", "-c", "-cover", "-coverpkg=./internal/client,./internal/execution", "-o", protectedFixturePath, "./internal/client")
		cmd.Dir = filepath.Join("..", "..", "..", "agent")
		if output, err := cmd.CombinedOutput(); err != nil {
			protectedFixtureBuildErr = fmt.Errorf("build protected agent fixture:%s:%w", output, err)
		}
	})
	if protectedFixtureBuildErr != nil {
		t.Fatal(protectedFixtureBuildErr)
	}
	cmd := exec.Command(protectedFixturePath, "-test.run=^TestProtectedExecutionEnrolledFixture$")
	cmd.Env = append(os.Environ(), "VEYPORT_TEST_PROTECTED_HUB="+h.grpcAddr, "VEYPORT_TEST_PROTECTED_TOKEN="+sshGWRegToken, "VEYPORT_TEST_PROTECTED_CAPIN="+h.caPin, "VEYPORT_TEST_PROTECTED_DIR="+t.TempDir(), "VEYPORT_EXECUTION_SPOOL_DIR=")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGINT)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	waitFor(t, "protected capability from real enrolled fixture", func() bool { return h.executions.SupportsProtected(sshGWServerID) })
}

// The storage doubles are compiled only into test binaries. These tests prove
// submission/admission/launch behavior, not actual encrypted mount readiness;
// the latter is exercised independently on the provisioned VM storage.
type protectedTestStore struct {
	mu   sync.Mutex
	used int64
	fail bool
}

func (s *protectedTestStore) Ready() error { return nil }
func (s *protectedTestStore) Create() (protectedinput.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return nil, io.ErrShortWrite
	}
	return &protectedTestFile{owner: s}, nil
}

type protectedTestFile struct {
	mu             sync.Mutex
	owner          *protectedTestStore
	buffer         bytes.Buffer
	sealed, closed bool
}

func (f *protectedTestFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owner.mu.Lock()
	defer f.owner.mu.Unlock()
	if f.closed || f.sealed {
		return 0, io.ErrClosedPipe
	}
	if f.buffer.Len()+len(p) > protectedinput.MaxScriptBytes || f.owner.used+int64(len(p)) > protectedinput.MaxAggregateBytes {
		return 0, protectedinput.ErrLimit
	}
	n, err := f.buffer.Write(p)
	f.owner.used += int64(n)
	return n, err
}
func (f *protectedTestFile) Seal() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sealed = true
	return nil
}
func (f *protectedTestFile) Open() (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || !f.sealed {
		return nil, io.ErrClosedPipe
	}
	return io.NopCloser(bytes.NewReader(f.buffer.Bytes())), nil
}
func (f *protectedTestFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		f.owner.mu.Lock()
		f.owner.used -= int64(f.buffer.Len())
		f.owner.mu.Unlock()
	}
	return nil
}

type cryptographicTestArchive struct {
	mu            sync.Mutex
	key           *ecdsa.PrivateKey
	verifier      *auditgate.Verifier
	mode          string
	records       map[string][]byte
	receipts      map[string]auditrecord.Receipt
	lastAdmission auditrecord.Receipt
	admissions    int
	reached       map[string]int
	underlying    auditgate.Preserver
	resolve       func(context.Context, model.PolicyVersion) (auditgate.Gate, error)
}

func testCryptographicArchive(t *testing.T, key *ecdsa.PrivateKey, fixture *testaudit.Fixture) *cryptographicTestArchive {
	t.Helper()
	verifier, err := auditgate.NewVerifier(auditgate.VerifierConfig{Issuer: fixture.Config.Issuer, Audience: fixture.Config.Audience, Keys: map[string]*ecdsa.PublicKey{fixture.Config.SigningKeyID: &key.PublicKey}, QualificationSHA256: fixture.Config.QualificationSHA256, GovernanceQualificationSHA256: fixture.Config.GovernanceQualificationSHA256, MaxTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return &cryptographicTestArchive{key: key, verifier: verifier, records: map[string][]byte{}, receipts: map[string]auditrecord.Receipt{}, reached: map[string]int{}}
}
func (a *cryptographicTestArchive) setMode(mode string) { a.mu.Lock(); a.mode = mode; a.mu.Unlock() }
func (a *cryptographicTestArchive) admissionCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.admissions
}
func (a *cryptographicTestArchive) modeCount(mode string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reached[mode]
}
func (a *cryptographicTestArchive) Resolve(ctx context.Context, policy model.PolicyVersion) (auditgate.Gate, error) {
	a.mu.Lock()
	mode, resolve := a.mode, a.resolve
	a.mu.Unlock()
	if mode == "not-ready" || resolve == nil {
		return auditgate.Gate{}, errors.New("archive readiness unavailable fixture")
	}
	gate, err := resolve(ctx, policy)
	if err != nil {
		return auditgate.Gate{}, err
	}
	a.mu.Lock()
	a.underlying = gate.Preserver
	a.mu.Unlock()
	return auditgate.Gate{Preserver: a, Verifier: gate.Verifier}, nil
}
func (a *cryptographicTestArchive) Preserve(ctx context.Context, raw []byte, attachments []auditgate.AttachmentInput) (auditrecord.Receipt, error) {
	expected, e, err := auditrecord.ExpectedFor(raw)
	if err != nil {
		return auditrecord.Receipt{}, err
	}
	a.mu.Lock()
	mode, underlying, previous := a.mode, a.underlying, a.lastAdmission
	if e.EventType == auditrecord.ExecutionAdmission {
		a.admissions++
	}
	a.mu.Unlock()
	if mode == "partition" || underlying == nil {
		if e.EventType == auditrecord.ExecutionAdmission && mode == "partition" {
			a.mu.Lock()
			a.reached[mode]++
			a.mu.Unlock()
		}
		return auditrecord.Receipt{}, errors.New("archive partition fixture")
	}
	if e.EventType == auditrecord.ExecutionAdmission && mode == "replay" {
		if previous.Token == "" {
			return auditrecord.Receipt{}, errors.New("fixture has no previous admission to replay")
		}
		a.mu.Lock()
		a.reached[mode]++
		a.mu.Unlock()
		return previous, nil
	}
	// Valid bytes, attachments, immutable versions and receipts come from the
	// actual scoped TLS service. Only explicit rejection modes alter a receipt.
	receipt, err := underlying.Preserve(ctx, raw, attachments)
	if err != nil {
		return auditrecord.Receipt{}, err
	}
	var claims auditrecord.Claims
	if e.EventType == auditrecord.ExecutionAdmission {
		claims, err = a.verifier.Verify(receipt.Token, expected, time.Now().UTC())
	} else {
		claims, err = a.verifier.VerifyHistorical(receipt.Token, expected, time.Now().UTC())
	}
	if err != nil {
		return auditrecord.Receipt{}, err
	}
	if e.EventType == auditrecord.ExecutionAdmission {
		switch mode {
		case "wrong-binding":
			claims.BindingSHA256 = auditrecord.Hash([]byte("wrong"))
		case "wrong-actor":
			claims.ActorSHA256 = auditrecord.Hash([]byte("wrong"))
		case "expired":
			claims.ExpiresAt = jwt.NewNumericDate(time.Now().UTC())
		}
		if mode == "wrong-binding" || mode == "wrong-actor" || mode == "expired" {
			token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			token.Header["kid"] = claims.KeyID
			receipt.Token, err = token.SignedString(a.key)
			if err != nil {
				return auditrecord.Receipt{}, err
			}
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records[e.EventID] = append([]byte(nil), raw...)
	a.receipts[e.EventID] = receipt
	if e.EventType == auditrecord.ExecutionAdmission {
		a.reached[mode]++
		a.lastAdmission = receipt
		if mode == "lost-reply" {
			return auditrecord.Receipt{}, errors.New("lost archived response fixture")
		}
	}
	return receipt, nil
}
func (a *cryptographicTestArchive) Lookup(_ context.Context, id, hash string) (auditrecord.Receipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mode == "partition" || auditrecord.Hash(a.records[id]) != hash {
		return auditrecord.Receipt{}, auditgate.ErrReceipt
	}
	return a.receipts[id], nil
}

type protectedNativeHarness struct {
	h                         *sshGWHarness
	archive                   *cryptographicTestArchive
	spool                     *protectedTestStore
	configRoot, hubURL, token string
}

func startProtectedNativeHarness(t *testing.T) *protectedNativeHarness {
	t.Helper()
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receipts := testaudit.NewWithSigningKey(t, testaudit.NewRealClock(), signingKey)
	archive := testCryptographicArchive(t, signingKey, receipts)
	spool := &protectedTestStore{}
	securityDir := filepath.Join(t.TempDir(), "security")
	installation, err := authorization.InitInstallation(securityDir)
	if err != nil {
		t.Fatal(err)
	}
	transition := authorization.TransitionConfig{InstallationID: installation, EnrollmentPath: filepath.Join(securityDir, "enhanced-enrollment.json")}
	h := startSSHGWHarnessWithOptions(t, func(c *sshgw.Config) {
		c.SecurityTransition = transition
		c.ProtectedExecution = &sshgw.ProtectedExecutionConfig{Spool: spool, ResolveArchive: archive.Resolve}
	})
	actor := h.seedAuthorizedUser(t)
	if _, err := h.store.DB().Exec(`UPDATE users SET auth_provider='local',role='admin',totp_enabled=1 WHERE id=?`, actor); err != nil {
		t.Fatal(err)
	}
	hubURL, _ := startExecutionREST(t, h)
	token, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if err = h.store.CreateAPIToken(&model.APIToken{ID: "protected-cli", UserID: actor, Name: "test", TokenHash: hash, TokenPrefix: prefix}); err != nil {
		t.Fatal(err)
	}
	args := nativeExecCredentials(t, h)
	var keyPath, certPath string
	for i, arg := range args {
		if arg == "-i" {
			keyPath = args[i+1]
		}
		if strings.HasPrefix(arg, "CertificateFile=") {
			certPath = strings.TrimPrefix(arg, "CertificateFile=")
		}
	}
	key, _ := os.ReadFile(keyPath)
	cert, _ := os.ReadFile(certPath)
	root := t.TempDir()
	dir := filepath.Join(root, "vey")
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	credentials, _ := json.Marshal(map[string]map[string]any{hubURL: {"ssh_private_key": string(key), "ssh_certificate": string(cert), "ssh_cert_expires_at": time.Now().Add(time.Hour), "ssh_host_fingerprint": ssh.FingerprintSHA256(h.hostKey.PublicKey())}})
	if err = os.WriteFile(filepath.Join(dir, "credentials.json"), credentials, 0600); err != nil {
		t.Fatal(err)
	}
	startProtectedFixtureAgent(t, h)
	activateNativeProtectedPolicy(t, h, receipts, archive, spool, transition)
	return &protectedNativeHarness{h: h, archive: archive, spool: spool, configRoot: root, hubURL: hubURL, token: token}
}

// Install the policy through the production approval/application service, with
// independently verified TLS evidence and the gateway's outside-DB continuity
// identity. The action proofs are test-issued to isolate native execution;
// actual password/MFA HTTP issuance is covered by server governance tests.
func activateNativeProtectedPolicy(t *testing.T, h *sshGWHarness, receipts *testaudit.Fixture, archive *cryptographicTestArchive, spool *protectedTestStore, transition authorization.TransitionConfig) {
	t.Helper()
	service := authorization.New(h.store)
	if err := service.ConfigureExecutionPolicy(transition); err != nil {
		t.Fatal(err)
	}
	storageKey, err := server.InitStorageKey(h.store)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"native-officer", "native-approver-a", "native-approver-b"}
	var nominations []model.SecurityNomination
	for i, id := range ids {
		secret, err := auth.Encrypt([]byte("JBSWY3DPEHPK3PXP"), auth.DeriveKey(storageKey))
		if err != nil {
			t.Fatal(err)
		}
		encoded := fmt.Sprintf("enc:%x", secret)
		role := model.RoleViewer
		protectedRole := model.RoleSecurityApprover
		if i == 0 {
			role, protectedRole = model.RoleAdmin, model.RoleSecurityOfficer
		}
		if err := h.store.CreateUser(&model.User{ID: id, Username: id, Email: id + "@synthetic.invalid", Role: role, AuthProvider: model.AuthProviderLocal, TOTPEnabled: true, TOTPSecret: &encoded}); err != nil {
			t.Fatal(err)
		}
		nominations = append(nominations, model.SecurityNomination{UserID: id, PersonID: "synthetic-person-" + id, Roles: []model.Role{protectedRole}, Verification: "Synthetic native integration identity, never deployment approval"})
	}
	credential, err := json.Marshal(receipts.Credential)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := json.Marshal(map[string]string{"kind": "destination", "value": string(credential)})
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := auth.Encrypt(secret, auth.DeriveKey(storageKey))
	if err != nil {
		t.Fatal(err)
	}
	const credentialRef = "secret:native-immutable-destination"
	if err := h.store.SaveSecuritySecret(credentialRef, encrypted, ids[0], time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	resolveSecret := func(ref string) (string, string, error) {
		return server.ResolveSecuritySecret(h.store, storageKey, ref)
	}
	runtime, err := auditruntime.Load(receipts.ConfigFile(t), auditruntime.Options{Store: h.store, Spool: spool, GatewayReady: h.gateway.Ready, SupportsProtected: h.executions.SupportsProtected, ResolveSecret: resolveSecret, Now: receipts.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	archive.mu.Lock()
	archive.resolve = runtime.ResolveArchive
	archive.mu.Unlock()
	transition.Evidence, transition.ResolveSecret = runtime.Evidence(), resolveSecret
	policy := model.AuditPolicy{Profile: "enhanced", Nodes: []string{sshGWServerID}, RuntimeSeconds: 3600, RetentionHours: 24, Destination: receipts.Config.Endpoint, CredentialRef: credentialRef, TrustKeyIDs: []string{receipts.Config.SigningKeyID}, QualificationSHA256: receipts.Config.QualificationSHA256}
	change, err := json.Marshal(model.SecurityChangePayload{Kind: "bootstrap", Policy: &policy, Nominations: nominations})
	if err != nil {
		t.Fatal(err)
	}
	proposal := authorization.Proposal{Reason: "Synthetic native execution qualification", ExpectedVersion: 1, Change: change}
	preview, err := authorization.Normalize(proposal)
	if err != nil {
		t.Fatal(err)
	}
	proof := func(user, action, digest string) string {
		p, err := h.store.IssueStepup(user, "native-session-"+user, action, digest, service.Now())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	request, err := service.Request(ids[0], "native-session-"+ids[0], proof(ids[0], authorization.ActionRequest, preview.Digest), proposal)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids[1:] {
		if _, err := service.Approve(request.ID, id, "native-session-"+id, proof(id, authorization.ActionApprove, request.Digest)); err != nil {
			t.Fatal(err)
		}
	}
	request, err = service.Apply(context.Background(), request.ID, ids[0], "native-session-"+ids[0], proof(ids[0], authorization.ActionApply, request.Digest), transition)
	if err != nil {
		t.Fatal(err)
	}
	state, err := h.store.GetPolicyState()
	if err != nil || request.State != "applied" || len(request.Approvals) != 2 || request.IntentRef == "" || request.CommitRef == "" || request.ResultRef == "" || state.Active.RequestID != request.ID || !authorization.EnrollmentMarkerMatches(transition, state) {
		t.Fatal("native policy lacks a completed quorum, verified evidence or exact outside-DB marker")
	}
	if err := service.CheckAnchor(context.Background(), transition); err != nil {
		t.Fatal("native policy lacks independent external continuity:", err)
	}
}

func (h *protectedNativeHarness) command(ctx context.Context, command string, input io.Reader) *exec.Cmd {
	cmd := exec.CommandContext(ctx, cliBinaryPath, "--hub", h.hubURL, "ssh", sshGWServerName, "--", command)
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+h.configRoot, "VEYPORT_TOKEN="+h.token, "DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent-vey-test-keyring")
	cmd.Stdin = input
	return cmd
}
func (h *protectedNativeHarness) run(t *testing.T, command string, input []byte) ([]byte, []byte, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := h.command(ctx, command, bytes.NewReader(input))
	var out, errout bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errout
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("protected native CLI stalled:%s", errout.String())
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	return out.Bytes(), errout.Bytes(), code
}

func TestProtectedNativeVEYExactReceiptAndRejectedReceiptsCannotCreateMarker(t *testing.T) {
	h := startProtectedNativeHarness(t)
	dir := t.TempDir()
	for _, mode := range []string{"valid", "wrong-binding", "wrong-actor", "expired", "replay", "partition", "lost-reply"} {
		t.Run(mode, func(t *testing.T) {
			h.archive.setMode(mode)
			before := h.archive.admissionCount()
			beforeMode := h.archive.modeCount(mode)
			marker := filepath.Join(dir, mode)
			script := []byte("printf x >> '" + marker + "'\nprintf verified\nexit 42\n")
			out, _, code := h.run(t, "/bin/sh -s", script)
			if h.archive.admissionCount() != before+1 || h.archive.modeCount(mode) != beforeMode+1 {
				t.Fatal("receipt case did not reach its specific independently verified archive mode")
			}
			if mode == "valid" {
				if code != 42 || string(out) != "verified" {
					t.Fatalf("valid receipt failed:%q/%d", out, code)
				}
				data, _ := os.ReadFile(marker)
				if string(data) != "x" {
					t.Fatal("valid exact receipt did not execute once")
				}
			} else {
				if code == 0 || len(out) != 0 {
					t.Fatalf("rejected receipt executed:%q/%d", out, code)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("rejected or ambiguous receipt created marker")
				}
			}
		})
	}
}

func TestProtectedNativeVEYReadinessOutagePreservesRedactedDenial(t *testing.T) {
	h := startProtectedNativeHarness(t)
	h.archive.setMode("not-ready")
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	command := "touch '" + marker + "'"
	_, _, code := h.run(t, command, nil)
	if code == 0 {
		t.Fatal("archive readiness outage admitted execution")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("readiness refusal affected the target")
	}
	var id, preparation string
	var dispatches int
	if err := h.h.store.DB().QueryRow(`SELECT id,preparation FROM executions WHERE enhanced=1 AND state='denied'`).Scan(&id, &preparation); err != nil {
		t.Fatal("authorized readiness denial was not recorded")
	}
	if preparation != "{}" {
		t.Fatal("readiness denial fabricated a remote preparation")
	}
	if err := h.h.store.DB().QueryRow(`SELECT count(*) FROM execution_dispatches`).Scan(&dispatches); err != nil || dispatches != 0 {
		t.Fatal("readiness denial claimed dispatch")
	}
	var raw []byte
	if err := h.h.store.DB().QueryRow(`SELECT envelope FROM execution_evidence_recovery WHERE execution_id=?`, id).Scan(&raw); err != nil {
		t.Fatal("readiness denial was not durably queued")
	}
	var denial auditrecord.Envelope
	if err := json.Unmarshal(raw, &denial); err != nil || denial.EventType != auditrecord.ExecutionDenial || denial.Execution != nil || denial.Details.Submission == nil || denial.Details.Submission.NodeID != sshGWServerID || denial.Details.Submission.CommandSHA256 != auditrecord.Hash([]byte(command)) || denial.Details.Submission.CommandBytes != int64(len(command)) || len(denial.Command) != 0 || len(denial.Attachments) != 0 || bytes.Contains(raw, []byte(marker)) {
		t.Fatal("readiness denial lost correlation or retained a raw command")
	}
	// Make the outage attempt deterministic. A wake must not bypass the
	// production one-minute retry delay; the old ten-second expectation raced
	// whether the first worker attempt preceded archive restoration.
	var attempts int
	var nextAttempt string
	waitFor(t, "outage denial retry backoff", func() bool {
		err := h.h.store.DB().QueryRow(`SELECT attempts,next_attempt_at FROM execution_evidence_recovery WHERE event_id=?`, id+".completion").Scan(&attempts, &nextAttempt)
		return err == nil && attempts > 0
	})
	next, err := time.Parse("2006-01-02 15:04:05", nextAttempt)
	if err != nil || !next.After(time.Now()) {
		t.Fatalf("failed denial preservation did not back off: attempts=%d next=%s", attempts, nextAttempt)
	}
	t.Logf("outage denial attempts=%d next_attempt_at=%s; making only restored event due", attempts, nextAttempt)
	h.archive.setMode("valid")
	if _, err := h.h.store.DB().Exec(`UPDATE execution_evidence_recovery SET next_attempt_at='2000-01-01' WHERE event_id=?`, id+".completion"); err != nil {
		t.Fatal(err)
	}
	if _, _, code := h.run(t, "true", nil); code != 0 {
		t.Fatal("restored archive did not admit an independent command")
	}
	waitFor(t, "external redacted readiness denial", func() bool {
		h.archive.mu.Lock()
		defer h.archive.mu.Unlock()
		return bytes.Equal(h.archive.records[id+".completion"], raw)
	})
}
func TestProtectedNativeVEYIncompleteOversizeUnsupportedInputNeverExecutesPrefix(t *testing.T) {
	h := startProtectedNativeHarness(t)
	marker := filepath.Join(t.TempDir(), "forbidden")
	prefix := []byte("touch '" + marker + "'\n")
	for _, command := range []string{"cat", "sh -s --", "bash -s x"} {
		_, _, code := h.run(t, command, prefix)
		if code == 0 {
			t.Fatal("unsupported enhanced stdin succeeded")
		}
	}
	script := bytes.Repeat([]byte{' '}, protectedinput.MaxScriptBytes+1)
	copy(script, prefix)
	_, _, code := h.run(t, "sh -s", script)
	if code == 0 {
		t.Fatal("oversize script accepted")
	}
	for _, kind := range []string{"interrupted", "nonending"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader, writer := io.Pipe()
			cmd := h.command(ctx, "sh -s", reader)
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(prefix); err != nil {
				t.Fatal(err)
			}
			time.Sleep(250 * time.Millisecond)
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("executed script prefix before EOF")
			}
			_ = cmd.Process.Signal(syscall.SIGTERM)
			time.Sleep(150 * time.Millisecond)
			_ = writer.Close()
			_ = reader.Close()
			_ = cmd.Wait()
		})
	}
	waitFor(t, "protected hub raw spool cleanup", func() bool { h.spool.mu.Lock(); defer h.spool.mu.Unlock(); return h.spool.used == 0 })
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("invalid finite script created marker")
	}
}
func TestProtectedNativeVEYAdmittedCommandSurvivesArchivePartition(t *testing.T) {
	h := startProtectedNativeHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := h.command(ctx, "sh -s", strings.NewReader("printf ready\nsleep 0.5\nprintf survived\nexit 42\n"))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make([]byte, 5)
	if _, err = io.ReadFull(stdout, ready); err != nil || string(ready) != "ready" {
		t.Fatal("command was not admitted")
	}
	h.archive.setMode("partition")
	tail, readErr := io.ReadAll(stdout)
	err = cmd.Wait()
	var exit *exec.ExitError
	if readErr != nil || !errors.As(err, &exit) || exit.ExitCode() != 42 || string(tail) != "survived" {
		t.Fatalf("audit partition changed admitted result:%q/%v/%v", tail, err, readErr)
	}
	waitFor(t, "unconfirmed completion preserves actual exit", func() bool {
		var n int
		_ = h.h.store.DB().QueryRow(`SELECT count(*) FROM executions WHERE enhanced=1 AND state='exited' AND exit_code=42 AND evidence_state='completion_unconfirmed'`).Scan(&n)
		return n == 1
	})
	_, _, code := h.run(t, "true", nil)
	if code == 0 {
		t.Fatal("partition admitted a new command")
	}
	h.archive.setMode("valid")
	if _, err = h.h.store.DB().Exec(`UPDATE execution_evidence_recovery SET next_attempt_at='2000-01-01'`); err != nil {
		t.Fatal(err)
	}
	_, _, code = h.run(t, "true", nil)
	if code != 0 {
		t.Fatal("restored archive failed new exact admission")
	}
	waitFor(t, "historical recovery confirms original exit", func() bool {
		var n int
		_ = h.h.store.DB().QueryRow(`SELECT count(*) FROM executions WHERE enhanced=1 AND state='exited' AND exit_code=42 AND evidence_state='confirmed'`).Scan(&n)
		return n == 1
	})
}
