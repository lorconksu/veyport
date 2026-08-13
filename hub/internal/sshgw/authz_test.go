package sshgw

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/server"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// T019 — SSH-layer authorization parity lock (SC-003, SC-009).
//
// The gateway must not have an authorization policy of its own: every decision
// has to be the one server.AuthorizeTerminalExecution — the web terminal's
// core — would make for the same (user, server) pair. This file drives REAL SSH
// connections through the gateway for the full SC-003 matrix and, for every
// cell, ALSO calls the core directly and asserts the two agree on both the
// verdict and the execution user. That makes the parity claim mechanical rather
// than eyeballed: a policy that drifts in either layer fails here.
//
// The load-bearing cell is the deleted account holding a still-valid
// certificate (SC-009). v1 publishes no CRL; the revocation window is bounded
// only because authorization is re-evaluated against live store state at shell
// time. If that property ever regresses, a departed operator keeps shell access
// for the remaining lifetime of their certificate.

const (
	authzServerBID   = "srv-b"
	authzServerBName = "db01"

	// Principals. LDAP users deliberately carry an ldap_username that differs
	// from their veyport username, so "the execution user is the LDAP name" is
	// actually observable rather than accidentally true.
	authzLDAPAdmin      = "lauren"
	authzLDAPAdminExec  = "lauren.unix"
	authzPermitted      = "carol"
	authzPermittedExec  = "carol.unix"
	authzNoAccess       = "dave"
	authzNoRootPath     = "erin"
	authzDeleted        = "frank"
	authzNonRootPath    = "/var/log"
	authzRootPath       = "/"
	fmtCreatePermission = "CreatePermission(%s, %s, %s) error: %v"
)

// authzDeletedMessage is the operator-facing refusal for an account that no
// longer exists when the shell is requested.
const authzDeletedMessage = "is not available for terminal access"

// ---------------------------------------------------------------------------
// matrix definition
// ---------------------------------------------------------------------------

// authzOutcome is the expected decision for one (user, server) pair.
type authzOutcome struct {
	allowed bool
	// runAs is the execution user the agent must be told to use. Empty is a
	// legitimate success for a LOCAL admin: it means the agent's default.
	runAs string
	// message is the operator-visible refusal text. For authorization refusals
	// this is the core's own sentinel text, which is the point: the SSH wording
	// is the web terminal's wording.
	message string
}

func allow(runAs string) authzOutcome { return authzOutcome{allowed: true, runAs: runAs} }
func deny(message string) authzOutcome {
	return authzOutcome{message: message}
}

// authzPrincipal is one row of the SC-003 matrix: a principal and its expected
// outcome on each of the two servers.
type authzPrincipal struct {
	name     string
	username string
	onA      authzOutcome
	onB      authzOutcome
	// deleteFirst removes the account AFTER its certificate is minted, which is
	// exactly the SC-009 situation: valid credential, revoked identity.
	deleteFirst bool
}

// authzCase is one cell: a principal resolved against one server.
type authzCase struct {
	name        string
	username    string
	serverID    string
	serverName  string
	deleteFirst bool
	want        authzOutcome
}

func authzPrincipals() []authzPrincipal {
	return []authzPrincipal{
		{
			name:     "local-admin",
			username: testUsername,
			onA:      allow(""),
			onB:      allow(""),
		},
		{
			name:     "ldap-admin",
			username: authzLDAPAdmin,
			onA:      allow(authzLDAPAdminExec),
			onB:      allow(authzLDAPAdminExec),
		},
		{
			// Terminal access plus a "/" assignment on server A only.
			name:     "permitted-ldap-user",
			username: authzPermitted,
			onA:      allow(authzPermittedExec),
			onB:      deny(server.ErrTerminalNoAssignment.Error()),
		},
		{
			// Root assignments on both servers, but terminal_access is off.
			name:     "ldap-user-without-terminal-access",
			username: authzNoAccess,
			onA:      deny(server.ErrTerminalNotAuthorized.Error()),
			onB:      deny(server.ErrTerminalNotAuthorized.Error()),
		},
		{
			// Terminal access, but only a sub-path assignment on both servers.
			name:     "ldap-user-without-root-assignment",
			username: authzNoRootPath,
			onA:      deny(server.ErrTerminalNoAssignment.Error()),
			onB:      deny(server.ErrTerminalNoAssignment.Error()),
		},
		{
			// SC-009: an admin whose account is deleted while their unexpired
			// certificate is still in hand.
			name:        "deleted-account-with-valid-certificate",
			username:    authzDeleted,
			onA:         deny(authzDeletedMessage),
			onB:         deny(authzDeletedMessage),
			deleteFirst: true,
		},
	}
}

// authzMatrix expands the principals across both servers.
func authzMatrix() []authzCase {
	principals := authzPrincipals()
	cases := make([]authzCase, 0, 2*len(principals))
	for _, p := range principals {
		cases = append(cases,
			authzCase{
				name: p.name + "/server-a", username: p.username,
				serverID: testServerID, serverName: testServerName,
				deleteFirst: p.deleteFirst, want: p.onA,
			},
			authzCase{
				name: p.name + "/server-b", username: p.username,
				serverID: authzServerBID, serverName: authzServerBName,
				deleteFirst: p.deleteFirst, want: p.onB,
			},
		)
	}
	return cases
}

// ---------------------------------------------------------------------------
// world
// ---------------------------------------------------------------------------

// matrixUser describes a principal to seed into the store.
type matrixUser struct {
	id             string
	username       string
	ldapUsername   string
	role           model.Role
	provider       model.AuthProvider
	terminalAccess bool
	rootOn         []string
	subPathOn      []string
}

func matrixUsers() []matrixUser {
	both := []string{testServerID, authzServerBID}
	return []matrixUser{
		{
			id: "user-ldap-admin", username: authzLDAPAdmin, ldapUsername: authzLDAPAdminExec,
			role: model.RoleAdmin, provider: model.AuthProviderLDAP,
		},
		{
			id: "user-permitted", username: authzPermitted, ldapUsername: authzPermittedExec,
			role: model.RoleViewer, provider: model.AuthProviderLDAP,
			terminalAccess: true, rootOn: []string{testServerID},
		},
		{
			id: "user-no-terminal-access", username: authzNoAccess, ldapUsername: "dave.unix",
			role: model.RoleViewer, provider: model.AuthProviderLDAP, rootOn: both,
		},
		{
			id: "user-no-root-assignment", username: authzNoRootPath, ldapUsername: "erin.unix",
			role: model.RoleViewer, provider: model.AuthProviderLDAP,
			terminalAccess: true, subPathOn: both,
		},
		{
			id: "user-deleted", username: authzDeleted,
			role: model.RoleAdmin, provider: model.AuthProviderLocal,
		},
	}
}

// authzWorld is the two-server, six-principal fixture the matrix runs against.
// A fresh world per cell keeps the audit log and the stub agents free of
// cross-talk, so "the agent received nothing" is an honest assertion.
type authzWorld struct {
	*fixture
	agentB *stubAgent
	users  map[string]string
}

func newAuthzWorld(t *testing.T) *authzWorld {
	t.Helper()
	f := newFixture(t, nil)
	w := &authzWorld{fixture: f, users: map[string]string{testUsername: testUserID}}

	if err := f.store.CreateServer(&model.Server{
		ID: authzServerBID, Name: authzServerBName, Status: "online", Labels: "{}",
	}); err != nil {
		t.Fatalf(fmtCreateServer, err)
	}
	w.agentB = newStubAgent(f.pending, authzServerBID)
	f.connMgr.Register(authzServerBID, w.agentB)
	f.connectAgent()

	for _, mu := range matrixUsers() {
		w.seedUser(t, mu)
	}
	f.start()
	return w
}

func (w *authzWorld) seedUser(t *testing.T, mu matrixUser) {
	t.Helper()
	if err := w.store.CreateUser(&model.User{
		ID: mu.id, Username: mu.username, Email: mu.username + "@example.test",
		PasswordHash: "x", Role: mu.role, AuthProvider: mu.provider,
		LDAPUsername: mu.ldapUsername, TerminalAccess: mu.terminalAccess,
	}); err != nil {
		t.Fatalf(fmtCreateUser, err)
	}
	w.grant(t, mu.id, mu.rootOn, authzRootPath)
	w.grant(t, mu.id, mu.subPathOn, authzNonRootPath)
	w.users[mu.username] = mu.id
}

func (w *authzWorld) grant(t *testing.T, userID string, serverIDs []string, path string) {
	t.Helper()
	for _, serverID := range serverIDs {
		if _, err := w.store.CreatePermission(userID, serverID, path); err != nil {
			t.Fatalf(fmtCreatePermission, userID, serverID, path, err)
		}
	}
}

// agentFor returns the stub agent for the addressed server, so a refusal can be
// checked against the agent that would have been asked to open the shell.
func (w *authzWorld) agentFor(serverID string) *stubAgent {
	if serverID == authzServerBID {
		return w.agentB
	}
	return w.agent
}

// ---------------------------------------------------------------------------
// the parity test
// ---------------------------------------------------------------------------

// TestGatewayAuthorizationMatchesWebTerminal is the SC-003 parity lock. For
// every cell it asks server.AuthorizeTerminalExecution directly, asserts the
// core's verdict is the one the matrix claims, and then makes the same request
// over a real SSH connection and asserts the gateway reached the same answer —
// including the execution user handed to the agent.
func TestGatewayAuthorizationMatchesWebTerminal(t *testing.T) {
	for _, c := range authzMatrix() {
		t.Run(c.name, func(t *testing.T) {
			newAuthzWorld(t).runCase(t, c)
		})
	}
}

func (w *authzWorld) runCase(t *testing.T, c authzCase) {
	t.Helper()

	// Mint the certificate while the account still exists: the SC-009 case is
	// specifically a VALID credential outliving the identity behind it.
	auth := certAuth(t, w.ca, c.username, testCertTTL)
	userID := w.users[c.username]
	if c.deleteFirst {
		if err := w.store.DeleteUser(userID); err != nil {
			t.Fatalf("DeleteUser(%s) error: %v", userID, err)
		}
	}

	// The core's verdict for this exact (user, server) pair — the web
	// terminal's decision, taken from the same live store state.
	coreExecUser, coreErr := server.AuthorizeTerminalExecution(w.store, userID, c.serverID)
	assertCoreVerdict(t, c, coreExecUser, coreErr)

	client, err := w.dial(c.username+"+"+c.serverName, auth, nil)
	if err != nil {
		t.Fatalf("ssh.Dial(%s+%s) error: %v", c.username, c.serverName, err)
	}
	defer func() { _ = client.Close() }()

	if c.want.allowed {
		w.assertShellOpens(t, c, client, coreExecUser)
		return
	}
	w.assertShellRefused(t, c, client)
}

// assertCoreVerdict pins the shared core's own answer. If the core ever changes
// its mind about a cell, this fires before the SSH assertions do, so the
// mismatch is attributed to the right layer.
func assertCoreVerdict(t *testing.T, c authzCase, execUser string, err error) {
	if !c.want.allowed {
		if err == nil {
			t.Fatalf("AuthorizeTerminalExecution(%s, %s) allowed with execution user %q, want a denial",
				c.username, c.serverID, execUser)
		}
		return
	}
	if err != nil {
		t.Fatalf("AuthorizeTerminalExecution(%s, %s) = %v, want it allowed", c.username, c.serverID, err)
	}
	if execUser != c.want.runAs {
		t.Fatalf("core execution user for (%s, %s) = %q, want %q",
			c.username, c.serverID, execUser, c.want.runAs)
	}
}

// assertShellOpens asserts the SSH path agrees with an ALLOW: the shell reaches
// the agent, and the execution user is byte-for-byte the core's.
func (w *authzWorld) assertShellOpens(t *testing.T, c authzCase, client *ssh.Client, coreExecUser string) {
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf(fmtNewSession, err)
	}
	defer func() { _ = sess.Close() }()
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf(fmtRequestPty, err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf(fmtShell, err)
	}

	open := w.agentFor(c.serverID).waitForMessage(t, "TerminalOpenRequest", func(m *pb.HubMessage) bool {
		return m.GetTerminalOpenRequest() != nil
	}).GetTerminalOpenRequest()
	if open.RunAsUser != c.want.runAs {
		t.Errorf("RunAsUser = %q, want %q", open.RunAsUser, c.want.runAs)
	}
	if open.RunAsUser != coreExecUser {
		t.Errorf("RunAsUser = %q but the web terminal core resolved %q: the two paths disagree",
			open.RunAsUser, coreExecUser)
	}

	w.terminals.End(c.serverID, open.SessionId, 0, "")
	_ = sess.Wait()
}

// refusedShellBounded is runRefusedShellOn with a deadline. A gateway that
// wrongly ALLOWS a denied cell leaves the shell open forever, so an unbounded
// Wait would hang the whole package until the go test timeout; here the same
// regression fails fast and says what it means.
func refusedShellBounded(t *testing.T, client *ssh.Client) (string, int) {
	t.Helper()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf(fmtNewSession, err)
	}
	defer func() { _ = sess.Close() }()
	stderr := &lockedBuffer{}
	sess.Stderr = stderr
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf(fmtRequestPty, err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf(fmtShell, err)
	}

	waited := make(chan error, 1)
	go func() { waited <- sess.Wait() }()
	select {
	case waitErr := <-waited:
		var exitErr *ssh.ExitError
		if errors.As(waitErr, &exitErr) {
			return stderr.String(), exitErr.ExitStatus()
		}
		return stderr.String(), 0
	case <-time.After(waitTimeout):
		t.Fatal("the session stayed open: the gateway allowed a shell the web terminal core denies")
		return "", 0
	}
}

// assertShellRefused asserts the SSH path agrees with a DENY: no shell opens,
// the operator is told why in the core's own words, and the refusal is audited.
func (w *authzWorld) assertShellRefused(t *testing.T, c authzCase, client *ssh.Client) {
	stderr, status := refusedShellBounded(t, client)
	if !strings.Contains(stderr, c.want.message) {
		t.Errorf("operator message = %q, want it to contain %q", stderr, c.want.message)
	}
	if status == 0 {
		t.Error("refused session exited 0, want a non-zero status")
	}
	if got := w.agentFor(c.serverID).messages(); len(got) != 0 {
		t.Errorf("the agent for %s received %d messages, want none: the shell must never open",
			c.serverID, len(got))
	}
	if got := len(w.auditEntries(model.AuditSSHSessionOpened)); got != 0 {
		t.Errorf("a refused session produced %d %s entries, want 0", got, model.AuditSSHSessionOpened)
	}
	w.assertRefusalAudit(t, c)
}

func (w *authzWorld) assertRefusalAudit(t *testing.T, c authzCase) {
	entry := w.waitForAudit(model.AuditSSHSessionRefused)
	if entry.Outcome != model.AuditOutcomeFailure {
		t.Errorf("audit outcome = %q, want %q", entry.Outcome, model.AuditOutcomeFailure)
	}
	if entry.Detail == nil || !strings.Contains(*entry.Detail, c.username) {
		t.Errorf("audit detail = %v, want it to name the SSH user %q", entry.Detail, c.username)
	}

	// A deleted account has no ID left to attribute the refusal to; every other
	// refusal must name the user it denied.
	if c.deleteFirst {
		if entry.UserID != nil {
			t.Errorf("audit user = %v, want none for a deleted account", entry.UserID)
		}
		return
	}
	want := w.users[c.username]
	if entry.UserID == nil || *entry.UserID != want {
		t.Errorf("audit user = %v, want %q", entry.UserID, want)
	}
}

// TestGatewayDeletedAccountRefusedWithinCertificateLifetime states SC-009 on
// its own, because it is the property that justifies shipping v1 without a
// certificate revocation list: the certificate is unexpired and cryptographically
// valid, authentication succeeds, and the session is still refused because the
// authorization decision is taken against live state at shell time.
func TestGatewayDeletedAccountRefusedWithinCertificateLifetime(t *testing.T) {
	w := newAuthzWorld(t)
	userID := w.users[authzDeleted]

	auth := certAuth(t, w.ca, authzDeleted, testCertTTL)
	connUser := authzDeleted + "+" + testServerName

	// Sanity: the same certificate authorizes a shell while the account lives.
	before, err := w.dial(connUser, auth, nil)
	if err != nil {
		t.Fatalf("ssh.Dial() error before deletion: %v", err)
	}
	w.assertShellOpens(t, authzCase{
		username: authzDeleted, serverID: testServerID, serverName: testServerName,
		want: allow(""),
	}, before, "")
	_ = before.Close()

	if err := w.store.DeleteUser(userID); err != nil {
		t.Fatalf("DeleteUser(%s) error: %v", userID, err)
	}

	// Same certificate, same principal, still unexpired: authentication still
	// succeeds — there is no CRL — but the shell must not open.
	after, err := w.dial(connUser, auth, nil)
	if err != nil {
		t.Fatalf("ssh.Dial() error after deletion: %v", err)
	}
	defer func() { _ = after.Close() }()

	stderr, status := refusedShellBounded(t, after)
	if !strings.Contains(stderr, authzDeletedMessage) {
		t.Errorf("operator message = %q, want it to explain the account is unavailable", stderr)
	}
	if status == 0 {
		t.Error("refused session exited 0, want a non-zero status")
	}
	if _, err := server.AuthorizeTerminalExecution(w.store, userID, testServerID); err == nil {
		t.Error("the web terminal core still authorizes the deleted account: the paths disagree")
	}
	w.waitForAudit(model.AuditSSHSessionRefused)
}
