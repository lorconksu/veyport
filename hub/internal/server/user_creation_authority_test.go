package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

type gatedCreateUserBody struct {
	reader  *bytes.Reader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *gatedCreateUserBody) Read(p []byte) (int, error) {
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return b.reader.Read(p)
}

func (*gatedCreateUserBody) Close() error { return nil }

func TestCreateUserRejectsActorRevokedWhileReadingBody(t *testing.T) {
	f := newLifecycleFixture(t)
	body := &gatedCreateUserBody{
		reader:  bytes.NewReader([]byte(`{"username":"postrevocationadmin","email":"postrevocationadmin@test.com","role":"admin"}`)),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	req := httptest.NewRequest(http.MethodPost, testUsersPath, body)
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
	if _, err := f.s.store.IncrementTokenGeneration(f.adminID); err != nil {
		t.Fatal(err)
	}
	close(body.release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("create-user request did not finish")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("revoked administrator created a user: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := f.s.store.GetUserByUsername("postrevocationadmin"); err == nil {
		t.Fatal("revoked administrator left a persistent account")
	}
}

func TestCreateUserAuditFailureRollsBackAccount(t *testing.T) {
	f := newLifecycleFixture(t)
	if _, err := f.s.store.DB().Exec(`CREATE TRIGGER reject_created_audit BEFORE INSERT ON audit_logs WHEN NEW.action='user.created' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	rec := lifecycleRequest(t, f.s, http.MethodPost, testUsersPath, f.adminToken,
		model.CreateUserRequest{Username: "unauditedadmin", Email: "unauditedadmin@test.com", Role: model.RoleAdmin})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure reported success: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := f.s.store.GetUserByUsername("unauditedadmin"); err == nil {
		t.Fatal("audit failure left a persistent account")
	}
}

func TestCreateUserAllowsLiveAdminAPIToken(t *testing.T) {
	f := newLifecycleFixture(t)
	raw := createAdminAPIToken(t, f.s)
	rec := lifecycleRequest(t, f.s, http.MethodPost, testUsersPath, raw,
		model.CreateUserRequest{Username: "apitokenadmin", Email: "apitokenadmin@test.com", Role: model.RoleAdmin})
	if rec.Code != http.StatusCreated {
		t.Fatalf("live administrator API token was rejected: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCreateUserRejectsRevokedAdminAPITokenAfterAdmission(t *testing.T) {
	f := newLifecycleFixture(t)
	raw := createAdminAPIToken(t, f.s)
	body := &gatedCreateUserBody{
		reader:  bytes.NewReader([]byte(`{"username":"revokedapiadmin","email":"revokedapiadmin@test.com","role":"admin"}`)),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	req := httptest.NewRequest(http.MethodPost, testUsersPath, body)
	req.Header.Set("Authorization", testBearerPrefix+raw)
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
	if err := f.s.store.RevokeAllAPITokensByUserID(f.adminID); err != nil {
		t.Fatal(err)
	}
	close(body.release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("create-user request did not finish")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("revoked administrator API token created a user: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := f.s.store.GetUserByUsername("revokedapiadmin"); err == nil {
		t.Fatal("revoked administrator API token left a persistent account")
	}
}
