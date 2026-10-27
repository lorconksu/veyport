package sshgw

import (
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/userca"
	"golang.org/x/crypto/ssh"
)

func TestPasswordRecoveryPermanentlyRevokesOldSSHCertificatesAndConnections(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()
	oldAuth := certAuth(t, f.ca, testUsername, time.Hour)
	retained, err := f.dial(testUsername+"+"+testServerName, oldAuth, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	now := time.Now().UTC()
	entry := model.AuditEntry{UserID: ptrManagement(testUserID), Target: ptrManagement(testUserID), Action: model.AuditUserPasswordReset}
	reset, err := f.store.ResetLocalPassword(testUserID, 0, "temporary-hash", now.Add(time.Hour), now, 5, entry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ChangeLocalPassword(reset, "permanent-hash", now, 5, true, entry); err != nil {
		t.Fatal(err)
	}
	// The connection authenticated before the reset cannot open a later channel.
	stderr, status := refusedShellBounded(t, retained)
	if status == 0 || !strings.Contains(stderr, "credential revoked") {
		t.Fatalf("retained connection reused old credential: status %d", status)
	}
	// Reconnecting with the same unexpired certificate is equally refused.
	again, err := f.dial(testUsername+"+"+testServerName, oldAuth, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	stderr, status = refusedShellBounded(t, again)
	if status == 0 || !strings.Contains(stderr, "credential revoked") {
		t.Fatal("old certificate regained authority after recovery")
	}
	// Only a certificate signed for the current durable epoch can open a shell.
	live, err := f.store.GetUserByID(testUserID)
	if err != nil {
		t.Fatal(err)
	}
	signer := newClientKey(t)
	cert, err := f.ca.SignUserCert(signer.PublicKey(), testUsername, time.Hour, live.SSHCredentialGeneration)
	if err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := f.dial(testUsername+"+"+testServerName, ssh.PublicKeys(certSigner), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	session, _, _ := startPTYShell(t, fresh)
	defer session.Close()
	f.assertOpenRequestGeometry(t, 80, 24)
}
func ptrManagement(value string) *string { return &value }

func TestPresentedSSHCredentialEpochIsBoundToEachExecutionChannel(t *testing.T) {
	f := newFixture(t, nil)
	if _, err := f.store.DB().Exec("UPDATE users SET ssh_credential_generation=2 WHERE id=?", testUserID); err != nil {
		t.Fatal(err)
	}
	conn := &ssh.ServerConn{Permissions: &ssh.Permissions{Extensions: map[string]string{extUsername: testUsername, extTarget: testServerName, userca.CredentialGenerationExtension: "0"}}}
	if _, err := f.srv.authorizeExec(conn); err == nil || !strings.Contains(err.Error(), "credential revoked") {
		t.Fatalf("old exec channel authority accepted: %v", err)
	}
	live, err := f.store.GetUserByID(testUserID)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "0", "invalid", "-1"} {
		conn.Permissions.Extensions[userca.CredentialGenerationExtension] = raw
		if certificateAuthorityCurrent(conn, live) {
			t.Fatalf("accepted old/malformed epoch %q", raw)
		}
	}
	conn.Permissions.Extensions[userca.CredentialGenerationExtension] = "2"
	if !certificateAuthorityCurrent(conn, live) {
		t.Fatal("current signed epoch refused")
	}
}

func TestSSHCredentialEpochRecheckedAtRegistryAdmission(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	// The initial channel authorization observed epoch zero. Recovery commits
	// before its terminal registration, so registry admission must reread epoch.
	if _, err := f.store.DB().Exec("UPDATE users SET ssh_credential_generation=2 WHERE id=?", testUserID); err != nil {
		t.Fatal(err)
	}
	ch := newFakeChannel()
	defer ch.Close()
	f.srv.bridge(ch, bridgeParams{serverID: testServerID, serverName: testServerName, userID: testUserID, username: testUsername, credentialGeneration: 0, remoteIP: "127.0.0.1"})
	if !strings.Contains(ch.errBuf.String(), "credential revoked") || len(f.terminals.ListByUser(testUserID)) != 0 {
		t.Fatal("stale SSH channel entered registry after recovery")
	}
	old, err := f.store.GetUserByID(testUserID)
	if err != nil {
		t.Fatal(err)
	}
	live := *old
	live.SSHCredentialGeneration++
	if !executionCredentialsChanged(old, &live) {
		t.Fatal("execution recheck ignored durable SSH revocation epoch")
	}
}
