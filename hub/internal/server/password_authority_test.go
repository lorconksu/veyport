package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestPasswordChangeRetainsPreBodyAndPreHashAuthority(t *testing.T) {
	for _, phase := range []string{"body", "hash"} {
		for _, mutation := range []string{"healthy", "session ended", "generation revoked", "MFA removed", "MFA replaced", "session owner", "session expired", "session idle", "account dormant"} {
			t.Run(phase+"/"+mutation, func(t *testing.T) {
				s := testServer(t)
				token := registerAndGetAdminToken(t, s)
				claims, err := auth.ValidateToken(s.jwtSecret, token)
				if err != nil {
					t.Fatal(err)
				}
				before, err := s.store.GetUserByID(claims.Subject)
				if err != nil {
					t.Fatal(err)
				}
				mutate := func() { mutatePasswordAuthority(t, s, before, claims.SessionID, mutation) }
				body := `{"current_password":"` + testPassword + `","new_password":"OriginalAuthority!Password123"}`
				req := httptest.NewRequest("PUT", "/api/auth/password", strings.NewReader(body))
				req.Header.Set("Authorization", testBearerPrefix+token)
				rec := httptest.NewRecorder()
				if phase == "body" {
					req.Body = io.NopCloser(&managementDelayedBody{reader: strings.NewReader(body), before: mutate})
					s.routes().ServeHTTP(rec, req)
				} else {
					// Hold the password hasher in flight after real bcrypt work. No
					// timing assumptions about CPU speed or request progress.
					hashed, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
					s.passwordHashFn = func(password string) (string, error) {
						hash, err := auth.HashPassword(password)
						close(hashed)
						<-resume
						return hash, err
					}
					go func() { defer close(done); s.routes().ServeHTTP(rec, req) }()
					select {
					case <-hashed:
					case <-time.After(30 * time.Second):
						close(resume)
						t.Fatal("request never reached password hashing")
					}
					mutate()
					close(resume)
					select {
					case <-done:
					case <-time.After(30 * time.Second):
						t.Fatal("password change did not finish")
					}
				}
				live, err := s.store.GetUserByID(before.ID)
				if err != nil {
					t.Fatal(err)
				}
				if mutation == "healthy" {
					if rec.Code != http.StatusOK || !auth.ComparePassword(live.PasswordHash, "OriginalAuthority!Password123") {
						t.Fatalf("live original authority refused: %d %s", rec.Code, rec.Body.String())
					}
					return
				}
				if rec.Code != http.StatusConflict || live.PasswordHash != before.PasswordHash {
					t.Fatalf("revoked %s authority committed: %d %s", mutation, rec.Code, rec.Body.String())
				}
				for _, query := range []string{
					"SELECT COUNT(*) FROM password_history WHERE user_id=?",
					"SELECT COUNT(*) FROM audit_logs WHERE user_id=? AND action='user.password_changed' AND outcome='success'",
				} {
					var count int
					if err := s.store.DB().QueryRow(query, before.ID).Scan(&count); err != nil || count != 0 {
						t.Fatalf("refusal changed history or success audit: %d %v", count, err)
					}
				}
			})
		}
	}
}

func mutatePasswordAuthority(t *testing.T, s *Server, u *model.User, sid, mutation string) {
	t.Helper()
	var err error
	switch mutation {
	case "healthy":
		return
	case "session ended":
		_, err = s.store.EndSession(sid, model.SessionEndLogout, nil, s.now())
	case "generation revoked":
		_, err = s.store.IncrementTokenGeneration(u.ID)
	case "MFA removed":
		err = s.store.UpdateUserTOTP(u.ID, nil, false)
	case "MFA replaced":
		secret := "replacement-factor"
		err = s.store.UpdateUserTOTP(u.ID, &secret, true)
	case "session owner":
		other := &model.User{ID: "other", Username: "other", Email: "other@test", PasswordHash: "h", Role: model.RoleViewer}
		if err = s.store.CreateUser(other); err == nil {
			_, err = s.store.DB().Exec("UPDATE sessions SET user_id=? WHERE id=?", other.ID, sid)
		}
	case "session expired":
		_, err = s.store.DB().Exec("UPDATE sessions SET expires_at=? WHERE id=?", s.now().Add(-time.Second).Format("2006-01-02 15:04:05"), sid)
	case "session idle":
		_, err = s.store.DB().Exec("UPDATE sessions SET last_seen_at=? WHERE id=?", s.now().Add(-24*time.Hour).Format("2006-01-02 15:04:05"), sid)
	case "account dormant":
		_, err = s.store.DB().Exec("UPDATE users SET created_at=?,last_activity_at=NULL,reactivated_at=NULL,dormancy_exempt=0 WHERE id=?", s.now().Add(-60*24*time.Hour).Format("2006-01-02 15:04:05"), u.ID)
	default:
		t.Fatalf("unknown mutation %s", mutation)
	}
	if err != nil {
		t.Fatal(err)
	}
}
