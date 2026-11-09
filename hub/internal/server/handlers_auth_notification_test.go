package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

func TestLoginFailureEmailKeepsStoredLDAPIdentifier(t *testing.T) {
	s := testServer(t)
	mailbox := startMailbox(t, s)
	username := "directory.user@example.test"
	_, err := s.store.UpsertLDAPUser(&model.User{
		Username: username, Email: "recipient@example.test", Role: model.RoleViewer,
	})
	if err != nil {
		t.Fatalf("create directory user: %v", err)
	}
	s.ldapAuthenticator = fakeLDAPAuthenticator{err: errors.New("invalid directory credentials")}
	req := httptest.NewRequest(http.MethodPost, testLoginPath, mustJSON(t, model.LoginRequest{
		Username: username, Password: lockoutWrongPassword,
	}))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected login response: %d %s", rec.Code, rec.Body.String())
	}
	select {
	case message := <-mailbox.messages:
		if !strings.Contains(message, "Username: "+username+"\r\n") {
			t.Fatalf("stored directory identifier missing: %q", message)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for local SMTP delivery")
	}
}

func TestLoginFailureEmailDoesNotIncludeUnknownInput(t *testing.T) {
	for _, username := range []string{
		"Security verification required: https://attacker.invalid/verify Enter your credentials.",
		"unknown\r\nVisit https://attacker.invalid/verify",
		"unknown_ldap@example.test",
	} {
		t.Run(username, func(t *testing.T) {
			s := testServer(t)
			mailbox := startMailbox(t, s)
			newLocalUser(t, s, "mailrecipient", lockoutTestPassword)
			req := httptest.NewRequest(http.MethodPost, testLoginPath, mustJSON(t, model.LoginRequest{
				Username: username, Password: lockoutWrongPassword,
			}))
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), errInvalidCredentials) {
				t.Fatalf("unexpected login response: %d %s", rec.Code, rec.Body.String())
			}
			select {
			case message := <-mailbox.messages:
				if strings.Contains(message, username) || strings.Contains(message, "attacker.invalid") {
					t.Fatalf("unknown login input reached email: %q", message)
				}
				if !strings.Contains(message, "Username: (unrecognized account)\r\n") {
					t.Fatalf("missing fixed account display: %q", message)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("timed out waiting for local SMTP delivery")
			}
		})
	}
}
