package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

type managementDelayedBody struct {
	reader *strings.Reader
	before func()
}

func (body *managementDelayedBody) Read(buffer []byte) (int, error) {
	if body.before != nil {
		before := body.before
		body.before = nil
		before()
	}
	return body.reader.Read(buffer)
}

// SEC-001: a request admitted before recovery must never select the new SSH
// epoch after its caller's credential has been revoked while sending the body.
func TestSSHCertificateIssuanceRechecksOriginalAuthorityAfterDelayedBody(t *testing.T) {
	for _, change := range []string{"recovery completed", "session ended", "MFA removed"} {
		t.Run(change, func(t *testing.T) {
			s, _ := testSSHServer(t)
			oldAccess := registerAndGetAdminToken(t, s)
			user, err := s.store.GetUserByUsername(testSSHAdminUsername)
			if err != nil {
				t.Fatal(err)
			}
			claims, err := auth.ValidateToken(s.jwtSecret, oldAccess)
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(sshCertificateRequest{PublicKey: testSSHClientPublicKey(t)})
			if err != nil {
				t.Fatal(err)
			}
			delayed := &managementDelayedBody{reader: strings.NewReader(string(data)), before: func() {
				now := time.Now().UTC()
				audit := model.AuditEntry{UserID: &user.ID, Target: &user.ID, Action: model.AuditUserPasswordReset}
				switch change {
				case "recovery completed":
					reset, err := s.store.ResetLocalPassword(store.PasswordResetTarget{UserID: user.ID, ExpectedGeneration: user.TokenGeneration}, store.TemporaryPasswordCredential{Hash: "temporary-hash", ExpiresAt: now.Add(time.Hour)}, now, 5, audit)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := s.store.ChangeLocalPassword(reset, "permanent-hash", now, 5, true, audit); err != nil {
						t.Fatal(err)
					}
				case "session ended":
					if _, err := s.store.EndSession(claims.SessionID, model.SessionEndLogout, &user.ID, now); err != nil {
						t.Fatal(err)
					}
				case "MFA removed":
					if err := s.store.UpdateUserTOTP(user.ID, nil, false); err != nil {
						t.Fatal(err)
					}
				}
			}}
			req := httptest.NewRequest("POST", testSSHCertPath, delayed)
			req.Header.Set("Authorization", testBearerPrefix+oldAccess)
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("revoked request issued SSH authority after %s: status %d", change, rec.Code)
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["certificate"] != nil {
				t.Fatal("refusal exposed a usable certificate")
			}
		})
	}
}
