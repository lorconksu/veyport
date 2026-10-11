package sshgw

import (
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/grpcserver"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestExecutionLiveRecheckRequiresCompletedPasswordWithUnchangedCredentials(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.srv.cfg.Executions = grpcserver.NewExecutionSessions(f.terminals, f.connMgr)
	f.srv.cfg.Executions.SetCapabilities(testServerID, f.agent, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "boot"})
	u, err := f.store.GetUserByID(testUserID)
	if err != nil {
		t.Fatal(err)
	}
	p := execParams{user: u, bridgeParams: bridgeParams{userID: testUserID, serverID: testServerID}}
	if err := f.srv.recheckExecution(p); err != nil {
		t.Fatalf("ordinary completed credentials denied: %v", err)
	}

	// Use a matching live credential snapshot for the unfinished account.
	// Revision, password, MFA and identity match, so credential-difference
	// detection cannot accidentally satisfy the authorization-denial assertion.
	if _, err := f.store.DB().Exec("UPDATE users SET must_change_password=1 WHERE id=?", testUserID); err != nil {
		t.Fatal(err)
	}
	p.user, err = f.store.GetUserByID(testUserID)
	if err != nil {
		t.Fatal(err)
	}
	live, err := f.store.GetUserByID(testUserID)
	if err != nil {
		t.Fatal(err)
	}
	if !p.user.MustChangePassword || !live.MustChangePassword || executionCredentialsChanged(p.user, live) {
		t.Fatal("fixture did not retain matching unfinished credentials")
	}
	if err := f.srv.recheckExecution(p); err == nil || !strings.Contains(err.Error(), "authorization changed") {
		t.Fatalf("unfinished credentials reached execution authority: %v", err)
	}

	if _, err := f.store.DB().Exec("UPDATE users SET must_change_password=0 WHERE id=?", testUserID); err != nil {
		t.Fatal(err)
	}
	p.user, err = f.store.GetUserByID(testUserID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.srv.recheckExecution(p); err != nil {
		t.Fatalf("password completion did not restore ordinary authorization: %v", err)
	}
}
