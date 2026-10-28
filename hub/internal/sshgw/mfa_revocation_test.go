package sshgw

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"github.com/wyiu/veyport/hub/internal/userca"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"golang.org/x/crypto/ssh"
)

func TestMFARevocationClosesSSHAndRejectsCertificateAdmission(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(fmt.Sprintf("separate=%t", separate), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hub.db")
			f := newFixtureAt(t, nil, path)
			f.connectAgent()
			writer := f.store
			if separate {
				var err error
				writer, err = store.New(path)
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close()
			}
			ch := newFakeChannel()
			done, _ := f.startBridge(ch, nil)
			sessionID := f.openSessionID()
			waitForShell(t, f, sessionID)
			defer f.disconnect(ch)
			if err := disableGatewayMFA(t, writer); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("established SSH survived MFA removal")
			}
			f.agent.waitForMessage(t, "MFA revocation close", func(m *pb.HubMessage) bool {
				return m.GetTerminalClose() != nil && m.GetTerminalClose().SessionId == sessionID
			})
			if !ch.isClosed() {
				t.Fatal("SSH transport left open")
			}
			// A retained signed certificate cannot authorize another execution
			// channel, including after MFA is enrolled again at the new epoch.
			conn := &ssh.ServerConn{Permissions: &ssh.Permissions{Extensions: map[string]string{extUsername: testUsername, extTarget: testServerName, userca.AccountIdentityExtension: testUserID, userca.CredentialGenerationExtension: "0"}}}
			if _, err := f.srv.authorizeExec(conn); err == nil {
				t.Fatal("old certificate admitted after MFA revocation")
			}
			secret := "new-factor"
			if err := writer.UpdateUserTOTP(testUserID, &secret, true); err != nil {
				t.Fatal(err)
			}
			if _, err := f.srv.authorizeExec(conn); err == nil {
				t.Fatal("reenrollment revived old certificate")
			}
			denied := newFakeChannel()
			f.srv.bridge(denied, bridgeParams{serverID: testServerID, serverName: testServerName, userID: testUserID, username: testUsername, credentialGeneration: 0})
			if !denied.isClosed() || !strings.Contains(denied.errBuf.String(), "credential revoked") {
				t.Fatal("old shell admission accepted")
			}
		})
	}
}

func TestSSHAdmissionRequiresMFAAtCurrentEpoch(t *testing.T) {
	for _, change := range []string{"totp_enabled=0", "totp_secret=NULL"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t, nil)
			f.connectAgent()
			if _, err := f.store.DB().Exec("UPDATE users SET "+change+" WHERE id=?", testUserID); err != nil {
				t.Fatal(err)
			}
			conn := &ssh.ServerConn{Permissions: &ssh.Permissions{Extensions: map[string]string{extUsername: testUsername, extTarget: testServerName, userca.AccountIdentityExtension: testUserID, userca.CredentialGenerationExtension: "0"}}}
			if _, err := f.srv.authorizeExec(conn); err == nil {
				t.Fatal("current epoch without MFA admitted")
			}
			ch := newFakeChannel()
			f.srv.bridge(ch, bridgeParams{serverID: testServerID, serverName: testServerName, userID: testUserID, username: testUsername, credentialGeneration: 0})
			if !ch.isClosed() || !strings.Contains(ch.errBuf.String(), "credential revoked") {
				t.Fatal("missing MFA admitted to bridge")
			}
		})
	}
}

func TestMFAResetPermanentlyRevokesIssuedSSHCertificate(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(fmt.Sprintf("separate=%t", separate), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hub.db")
			f := newFixtureAt(t, nil, path)
			f.connectAgent()
			f.start()
			oldAuth := certAuth(t, f.ca, testUsername, time.Hour)
			retained, err := f.dial(testUsername+"+"+testServerName, oldAuth, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer retained.Close()
			writer := f.store
			if separate {
				writer, err = store.New(path)
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close()
			}
			if err := disableGatewayMFA(t, writer); err != nil {
				t.Fatal(err)
			}
			stderr, status := refusedShellBounded(t, retained)
			if status == 0 || !strings.Contains(stderr, "credential revoked") {
				t.Fatal("retained connection opened shell after MFA removal")
			}
			again, err := f.dial(testUsername+"+"+testServerName, oldAuth, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer again.Close()
			stderr, status = refusedShellBounded(t, again)
			if status == 0 || !strings.Contains(stderr, "credential revoked") {
				t.Fatal("issued certificate opened new shell after MFA removal")
			}
			live, err := writer.GetUserByID(testUserID)
			if err != nil {
				t.Fatal(err)
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
			stderr, status = refusedShellBounded(t, fresh)
			if status == 0 || !strings.Contains(stderr, "credential revoked") {
				t.Fatal("current epoch bypassed required MFA at shell admission")
			}
			secret := "reenrolled"
			if err := writer.UpdateUserTOTP(testUserID, &secret, true); err != nil {
				t.Fatal(err)
			}
			stderr, status = refusedShellBounded(t, retained)
			if status == 0 || !strings.Contains(stderr, "credential revoked") {
				t.Fatal("reenrollment revived old certificate")
			}
			session, _, _ := startPTYShell(t, fresh)
			defer session.Close()
			f.assertOpenRequestGeometry(t, 80, 24)
		})
	}
}

func disableGatewayMFA(t *testing.T, st *store.Store) error {
	t.Helper()
	admin := &model.User{ID: "recovery-admin", Username: "recovery-admin", Email: "admin@test", PasswordHash: "h", Role: model.RoleAdmin, TOTPEnabled: true, TOTPSecret: ptrManagement("enrolled")}
	if err := st.CreateUser(admin); err != nil {
		t.Fatal(err)
	}
	sessionID := admin.ID + "-session"
	if err := st.CreateSession(&model.Session{ID: sessionID, UserID: admin.ID, Kind: model.SessionKindWeb, CreatedAt: time.Now(), LastSeenAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return st.DisableUserTOTP(testUserID, time.Now(), model.AuditEntry{UserID: &admin.ID, Target: ptrManagement(testUserID), Action: model.AuditUserTOTPDisabled}, store.AccountManagementActor{UserID: admin.ID, SessionID: sessionID, Generation: admin.TokenGeneration, SecurityRevision: admin.SecurityRevision})
}
