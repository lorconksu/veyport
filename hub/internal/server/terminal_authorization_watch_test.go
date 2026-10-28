package server

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestIdleBrowserTerminalClosesOnExternalRoleOrPermissionRemoval(t *testing.T) {
	for _, mutation := range []string{"role", "permission"} {
		t.Run(mutation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hub.db")
			s, token, node := testServerWithAgentAt(t, path)
			claims, err := auth.ValidateToken(s.jwtSecret, token)
			if err != nil {
				t.Fatal(err)
			}
			var permission *model.Permission
			if mutation == "permission" {
				if err := s.store.UpdateUserRole(claims.Subject, model.RoleViewer); err != nil {
					t.Fatal(err)
				}
				if _, err := s.store.DB().Exec("UPDATE users SET auth_provider='ldap',ldap_username='operator',terminal_access=1 WHERE id=?", claims.Subject); err != nil {
					t.Fatal(err)
				}
				permission, err = s.store.CreatePermission(claims.Subject, node, "/")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.store.CreatePermission(claims.Subject, node, "/var/log"); err != nil {
					t.Fatal(err)
				}
			}
			a := &daybreakTerminalAgent{mockGRPCStream: mockGRPCStream{pending: s.pending, serverID: node, terms: s.terminalSessions}, close: make(chan struct{})}
			s.connMgr.Register(node, a)
			id := createTerminalSessionForTest(t, s, token, node)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req := httptest.NewRequest("GET", testServersPrefix+node+testTerminalSessionsSuffix+"/"+id+"/stream", nil).WithContext(ctx)
			req.Header.Set("Authorization", testBearerPrefix+token)
			rec := &daybreakStreamRecorder{ResponseRecorder: httptest.NewRecorder(), ready: make(chan struct{})}
			done := make(chan struct{})
			go func() { defer close(done); s.routes().ServeHTTP(rec, req) }()
			select {
			case <-rec.ready:
			case <-time.After(2 * time.Second):
				t.Fatal("browser terminal stream never attached")
			}
			writer, err := store.New(path)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			if mutation == "role" {
				err = writer.UpdateUserRole(claims.Subject, model.RoleViewer)
			} else {
				err = writer.DeletePermission(permission.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				cancel()
				<-done
				t.Fatal("idle browser stream survived live authorization removal")
			}
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), "event: exit") {
				t.Fatalf("browser did not receive a terminal exit: %d %s", rec.Code, rec.Body.String())
			}
			if s.terminalSessions.DeliverData(node, id, []byte("LATE_PRIVATE_OUTPUT")) {
				t.Fatal("revoked browser terminal accepted late output")
			}
			input := lifecycleRequest(t, s, "POST", testServersPrefix+node+testTerminalSessionsSuffix+"/"+id+"/input", token, map[string]string{"data": "LATE_INPUT"})
			if input.Code < 400 {
				t.Fatalf("revoked browser terminal accepted input: %d", input.Code)
			}
			select {
			case <-a.close:
			case <-time.After(time.Second):
				t.Fatal("captured agent terminal was not closed")
			}
		})
	}
}
