package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

func TestUserRoleRejectsActorDemotedWhileReadingBody(t *testing.T) {
	f := newLifecycleFixture(t)
	body := &gatedCreateUserBody{
		reader:  bytes.NewReader([]byte(`{"role":"admin"}`)),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	req := httptest.NewRequest(http.MethodPut, testUsersPrefix+f.viewerID+"/role", body)
	req.Header.Set("Authorization", testBearerPrefix+f.adminToken)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.s.routes().ServeHTTP(rec, req)
	}()
	select {
	case <-body.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not reach body decoding")
	}
	if err := f.s.store.UpdateUserRole(f.adminID, model.RoleViewer); err != nil {
		t.Fatal(err)
	}
	close(body.release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("role request did not finish")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("demoted administrator changed a role: %d %s", rec.Code, rec.Body.String())
	}
	if user := storedUser(t, f.s, f.viewerID); user.Role != model.RoleViewer {
		t.Fatalf("demoted administrator changed target role to %q", user.Role)
	}
}

func TestUserLifecycleAuditFailureRollsBackMutation(t *testing.T) {
	for _, operation := range []string{"role", "delete", "disable", "enable", "unlock", "exemption"} {
		t.Run(operation, func(t *testing.T) {
			f := newLifecycleFixture(t)
			targetID := f.viewerID
			action := model.AuditUserRoleUpdated
			if operation == "enable" {
				if _, err := f.s.store.DisableUser(targetID, f.adminID, f.s.now()); err != nil {
					t.Fatal(err)
				}
				action = model.AuditUserEnabled
			} else if operation == "unlock" {
				lockAccount(t, f.s, targetID)
				action = model.AuditUserUnlocked
			} else if operation == "exemption" {
				targetID, _ = createLifecycleUser(t, f.s, f.adminToken, "exemptionadmin", model.RoleAdmin)
				action = model.AuditUserDormancyExemptSet
			} else if operation == "delete" {
				action = model.AuditUserDeleted
			} else if operation == "disable" {
				action = model.AuditUserDisabled
			}
			before := storedUser(t, f.s, targetID)
			trigger := fmt.Sprintf(`CREATE TRIGGER reject_lifecycle_audit BEFORE INSERT ON audit_logs WHEN NEW.action='%s' BEGIN SELECT RAISE(ABORT,'injected lifecycle audit failure'); END`, action)
			if _, err := f.s.store.DB().Exec(trigger); err != nil {
				t.Fatal(err)
			}
			var rec *httptest.ResponseRecorder
			switch operation {
			case "role":
				rec = lifecycleRequest(t, f.s, http.MethodPut, testUsersPrefix+targetID+"/role", f.adminToken, model.UpdateRoleRequest{Role: model.RoleAdmin})
			case "delete":
				rec = lifecycleRequest(t, f.s, http.MethodDelete, testUsersPrefix+targetID, f.adminToken, nil)
			case "disable":
				rec = putStatus(t, f.s, f.adminToken, targetID, true)
			case "enable":
				rec = putStatus(t, f.s, f.adminToken, targetID, false)
			case "unlock":
				rec = postUnlock(t, f.s, f.adminToken, targetID)
			case "exemption":
				rec = putExemption(t, f.s, f.adminToken, targetID, true)
			}
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("audit failure reported success: %d %s", rec.Code, rec.Body.String())
			}
			after, err := f.s.store.GetUserByID(targetID)
			if err != nil {
				t.Fatalf("audit failure removed target: %v", err)
			}
			switch operation {
			case "role":
				if after.Role != before.Role || after.TokenGeneration != before.TokenGeneration {
					t.Fatal("audit failure committed role mutation")
				}
			case "delete":
				// Reload above proves the deletion rolled back.
			case "disable":
				if after.DisabledAt != nil || after.TokenGeneration != before.TokenGeneration {
					t.Fatal("audit failure committed disable mutation")
				}
			case "enable":
				if after.DisabledAt == nil {
					t.Fatal("audit failure committed enable mutation")
				}
			case "unlock":
				if after.LockedUntil == nil {
					t.Fatal("audit failure committed unlock mutation")
				}
			case "exemption":
				if after.DormancyExempt {
					t.Fatal("audit failure committed exemption mutation")
				}
			}
		})
	}
}
