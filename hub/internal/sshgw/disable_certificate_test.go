package sshgw

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/userca"
	"golang.org/x/crypto/ssh"
)

func TestDisableEnableNeverRevivesOriginalSSHCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	f := newFixtureAt(t, nil, path)
	f.connectAgent()
	f.start()
	original := certAuth(t, f.ca, testUsername, time.Hour)
	retained, err := f.dial(testUsername+"+"+testServerName, original, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	// An independent Store models an administrator in another Hub process.
	writer, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.CreateUser(&model.User{ID: "other-admin", Username: "other-admin", Email: "other@test", PasswordHash: "h", Role: model.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	before, err := writer.GetUserByID(testUserID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.DisableUser(testUserID, "other-admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.EnableUser(testUserID, time.Now()); err != nil {
		t.Fatal(err)
	}
	live, err := writer.GetUserByID(testUserID)
	if err != nil || live.SSHCredentialGeneration != before.SSHCredentialGeneration+1 || !live.TOTPEnabled || live.DisabledAt != nil {
		t.Fatalf("invalid disable/enable transition: %v", err)
	}
	for _, client := range []*ssh.Client{retained, dialOriginalCertificate(t, f, original)} {
		defer client.Close()
		stderr, status := refusedShellBounded(t, client)
		if status == 0 || !strings.Contains(stderr, "credential revoked") {
			t.Fatalf("original certificate revived: status=%d stderr=%q", status, stderr)
		}
	}
	if countOpenRequests(f.agent.messages()) != 0 {
		t.Fatal("revoked certificate reached the agent")
	}
	// The same authority check protects SSH exec channels.
	conn := &ssh.ServerConn{Permissions: &ssh.Permissions{Extensions: map[string]string{extUsername: testUsername, extTarget: testServerName, userca.AccountIdentityExtension: testUserID, userca.CredentialGenerationExtension: "0"}}}
	if _, err := f.srv.authorizeExec(conn); err == nil {
		t.Fatal("original certificate retained exec authority")
	}
	key := newClientKey(t)
	cert, err := f.ca.SignUserCertForAccount(key.PublicKey(), testUsername, live.ID, time.Hour, live.SSHCredentialGeneration)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewCertSigner(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := f.dial(testUsername+"+"+testServerName, ssh.PublicKeys(signer), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	session, _, _ := startPTYShell(t, fresh)
	defer session.Close()
	f.assertOpenRequestGeometry(t, 80, 24)
}

func dialOriginalCertificate(t *testing.T, f *fixture, method ssh.AuthMethod) *ssh.Client {
	t.Helper()
	client, err := f.dial(testUsername+"+"+testServerName, method, nil)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
