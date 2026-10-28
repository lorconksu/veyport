package sshgw

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestIdleSSHClientClosesWhenRoleOrRootPermissionIsRevoked(t *testing.T) {
	for _, mutation := range []string{"role", "permission"} {
		t.Run(mutation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hub.db")
			f := newFixtureAt(t, nil, path)
			var permission *model.Permission
			if mutation == "permission" {
				if err := f.store.UpdateUserRole(testUserID, model.RoleViewer); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.DB().Exec("UPDATE users SET auth_provider='ldap',ldap_username=?,terminal_access=1 WHERE id=?", testUsername, testUserID); err != nil {
					t.Fatal(err)
				}
				var err error
				permission, err = f.store.CreatePermission(testUserID, testServerID, "/")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.CreatePermission(testUserID, testServerID, "/var/log"); err != nil {
					t.Fatal(err)
				}
			}
			f.connectAgent()
			f.start()
			client := dialOriginalCertificate(t, f, certAuth(t, f.ca, testUsername, time.Hour))
			defer client.Close()
			session, stdin, stdout := startPTYShell(t, client)
			defer session.Close()
			id := f.openSessionID()
			waitForShell(t, f, id)
			f.assertAgentOutputReachesClient(t, id, stdout)
			writer, err := store.New(path)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			if mutation == "role" {
				err = writer.UpdateUserRole(testUserID, model.RoleViewer)
			} else {
				err = writer.DeletePermission(permission.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			live, err := writer.GetUserByID(testUserID)
			if err != nil || live.TokenGeneration != 0 || live.SSHCredentialGeneration != 0 {
				t.Fatalf("fixture revoked credentials instead of authorization: %v", err)
			}
			finished := make(chan error, 1)
			go func() { finished <- session.Wait() }()
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("revoked shell reported successful completion")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("idle SSH client stayed attached after authorization removal")
			}
			if f.terminals.DeliverData(testServerID, id, []byte("LATE_PRIVATE_OUTPUT")) || strings.Contains(stdout.String(), "LATE_PRIVATE_OUTPUT") {
				t.Fatal("revoked SSH client received late output")
			}
			_, _ = stdin.Write([]byte("LATE_INPUT\n"))
			f.agent.waitForMessage(t, "authorization close", func(m *pb.HubMessage) bool {
				return m.GetTerminalClose() != nil && m.GetTerminalClose().SessionId == id
			})
			for _, msg := range f.agent.messages() {
				if input := msg.GetTerminalInput(); input != nil && strings.Contains(string(input.Data), "LATE_INPUT") {
					t.Fatal("revoked SSH input reached the agent")
				}
			}
		})
	}
}
