package sshgw

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
)

// This fixture supplies a locally consistent completed synthetic request and
// marker. Real three-person MFA and external receipt application are covered by
// the production HTTP tests; these tests isolate the gateway's final routing.
func configuredGatewayPolicy(t *testing.T, cfg *Config) model.PolicyVersion {
	t.Helper()
	policy := model.AuditPolicy{Profile: "enhanced", Nodes: []string{testServerID}, RuntimeSeconds: 60, RetentionHours: 24, Destination: "https://synthetic-receipt.test.invalid", CredentialRef: "secret:synthetic-immutable", TrustKeyIDs: []string{"synthetic-key"}, QualificationSHA256: authorization.Digest([]byte("synthetic qualification"))}
	change, err := json.Marshal(model.SecurityChangePayload{Kind: "bootstrap", Policy: &policy, Nominations: []model.SecurityNomination{{UserID: testUserID, PersonID: "synthetic-officer", Roles: []model.Role{model.RoleSecurityOfficer}}, {UserID: "synthetic-a", PersonID: "synthetic-a", Roles: []model.Role{model.RoleSecurityApprover}}, {UserID: "synthetic-b", PersonID: "synthetic-b", Roles: []model.Role{model.RoleSecurityApprover}}}})
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := authorization.Normalize(authorization.Proposal{Reason: "Synthetic exact gateway continuity fixture", ExpectedVersion: 1, Change: change})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Store.DB().Exec(`INSERT INTO security_changes(id,revision,requester_id,requester_person,requester_generation,expected_version,digest,reason,payload,state,created_at,expires_at) VALUES('synthetic-gateway-bootstrap',1,?,'synthetic-officer',0,1,?, ?,?,'applied',?,?)`, testUserID, proposal.Digest, proposal.Proposal.Reason, proposal.Bytes, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	version := model.PolicyVersion{Version: 2, Policy: policy, SHA256: authorization.Digest(raw), RequestID: "synthetic-gateway-bootstrap"}
	if _, err := cfg.Store.DB().Exec("INSERT INTO audit_policy_versions(version,payload,digest,request_id) VALUES(2,?,?,?)", raw, version.SHA256, version.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Store.DB().Exec("UPDATE audit_policy_state SET active_version=2,state='enhanced' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg.SecurityTransition = authorization.TransitionConfig{InstallationID: "synthetic-gateway-installation", EnrollmentPath: filepath.Join(dir, "enrollment.json")}
	marker, err := json.Marshal(authorization.EnrollmentMarker{InstallationID: cfg.SecurityTransition.InstallationID, Version: version.Version, SHA256: version.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SecurityTransition.EnrollmentPath, marker, 0600); err != nil {
		t.Fatal(err)
	}
	return version
}

func TestInvalidContinuityConfigurationClosesSuppliedGatewayListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	t.Cleanup(func() { listener.Close() })
	f := newFixture(t, func(cfg *Config) {
		cfg.Listener = listener
		cfg.SecurityTransition = authorization.TransitionConfig{InstallationID: "incomplete-installation"}
	})
	if err := f.srv.Start(); !errors.Is(err, authorization.ErrRecovery) {
		t.Fatalf("partial continuity configuration started gateway: %v", err)
	}
	if f.srv.Ready() {
		t.Fatal("rejected configuration advertised a listening gateway")
	}
	select {
	case <-f.srv.ready:
	default:
		t.Fatal("failed startup did not signal attempt completion")
	}
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err == nil {
		connection.Close()
		t.Fatal("refused startup leaked its supplied listener")
	}
	if err := f.srv.Stop(context.Background()); err != nil {
		t.Fatalf("rejected gateway could not shut down: %v", err)
	}
}

func TestActualGatewayCannotRouteRecomputedPolicyToLegacyShellOrCommand(t *testing.T) {
	for _, corruption := range []string{"standard", "unrelated_scope"} {
		t.Run(corruption, func(t *testing.T) {
			var approved model.PolicyVersion
			f := newFixture(t, func(cfg *Config) { approved = configuredGatewayPolicy(t, cfg) })
			f.connectAgent()
			f.start()
			if policy, err := f.srv.securityService().PolicyForExecution(testUserID, testServerID); err != nil || !policy.Enhanced {
				t.Fatalf("independent gateway failed to initialize local continuity: %+v %v", policy, err)
			}
			corrupt := approved.Policy
			if corruption == "standard" {
				corrupt.Profile = "standard"
			} else {
				corrupt.Nodes = []string{"unrelated-node"}
			}
			raw, err := json.Marshal(corrupt)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.DB().Exec("UPDATE audit_policy_versions SET payload=?,digest=? WHERE version=2", raw, authorization.Digest(raw)); err != nil {
				t.Fatal(err)
			}
			client := f.mustDial(testUsername + "+" + testServerName)
			defer client.Close()
			for _, kind := range []string{reqShell, reqExec} {
				session, err := client.NewSession()
				if err != nil {
					t.Fatal(err)
				}
				if kind == reqExec {
					err = session.Start("synthetic-command-that-must-not-run")
				} else {
					err = session.Shell()
				}
				if err != nil {
					t.Fatalf("SSH submission acknowledgement failed: %v", err)
				}
				done := make(chan error, 1)
				go func() { done <- session.Wait() }()
				select {
				case err := <-done:
					var exit *ssh.ExitError
					if !errors.As(err, &exit) || exit.ExitStatus() == 0 {
						t.Fatalf("corrupted policy completed %s successfully: %v", kind, err)
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("corrupted policy did not promptly refuse %s", kind)
				}
				session.Close()
			}
			for _, message := range f.agent.messages() {
				if message.GetTerminalOpenRequest() != nil || message.GetExecutionPrepare() != nil {
					t.Fatal("corrupted policy reached legacy or protected agent dispatch")
				}
			}
			if err := f.srv.securityService().GuardInteractive(testUserID, testServerID); !errors.Is(err, authorization.ErrRecovery) {
				t.Fatalf("final local guard missed recomputed policy: %v", err)
			}
		})
	}
}
