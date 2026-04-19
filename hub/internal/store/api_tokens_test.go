package store_test

import (
	"testing"
	"time"

	"github.com/wyiu/aerodocs/hub/internal/model"
)

func TestCreateAndGetActiveAPIToken(t *testing.T) {
	s := testStore(t)
	user := &model.User{
		ID:           "u1",
		Username:     "scanner",
		Email:        "scanner@test.com",
		PasswordHash: "hash",
		Role:         model.RoleViewer,
	}
	if err := s.CreateUser(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	token := &model.APIToken{
		ID:          "tok-1",
		UserID:      user.ID,
		Name:        "nightly",
		TokenHash:   "hash-1",
		TokenPrefix: "adt_123456789abc",
	}
	if err := s.CreateAPIToken(token); err != nil {
		t.Fatalf("create api token: %v", err)
	}

	got, err := s.GetActiveAPITokenByHash(token.TokenHash)
	if err != nil {
		t.Fatalf("get api token: %v", err)
	}
	if got.ID != token.ID {
		t.Fatalf("expected token id %q, got %q", token.ID, got.ID)
	}
	if got.Name != token.Name {
		t.Fatalf("expected token name %q, got %q", token.Name, got.Name)
	}
}

func TestGetActiveAPITokenByHash_Expired(t *testing.T) {
	s := testStore(t)
	user := &model.User{
		ID:           "u1",
		Username:     "scanner",
		Email:        "scanner@test.com",
		PasswordHash: "hash",
		Role:         model.RoleViewer,
	}
	if err := s.CreateUser(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	expiresAt := time.Now().UTC().Add(-time.Hour)
	token := &model.APIToken{
		ID:          "tok-1",
		UserID:      user.ID,
		Name:        "nightly",
		TokenHash:   "hash-1",
		TokenPrefix: "adt_123456789abc",
		ExpiresAt:   &expiresAt,
	}
	if err := s.CreateAPIToken(token); err != nil {
		t.Fatalf("create api token: %v", err)
	}

	if _, err := s.GetActiveAPITokenByHash(token.TokenHash); err == nil {
		t.Fatal("expected expired token lookup to fail")
	}
}

func TestRevokeAPIToken(t *testing.T) {
	s := testStore(t)
	user := &model.User{
		ID:           "u1",
		Username:     "scanner",
		Email:        "scanner@test.com",
		PasswordHash: "hash",
		Role:         model.RoleViewer,
	}
	if err := s.CreateUser(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	token := &model.APIToken{
		ID:          "tok-1",
		UserID:      user.ID,
		Name:        "nightly",
		TokenHash:   "hash-1",
		TokenPrefix: "adt_123456789abc",
	}
	if err := s.CreateAPIToken(token); err != nil {
		t.Fatalf("create api token: %v", err)
	}

	if err := s.RevokeAPIToken(token.ID); err != nil {
		t.Fatalf("revoke api token: %v", err)
	}

	if _, err := s.GetActiveAPITokenByHash(token.TokenHash); err == nil {
		t.Fatal("expected revoked token lookup to fail")
	}

	tokens, err := s.ListAPITokensByUserID(user.ID)
	if err != nil {
		t.Fatalf("list api tokens: %v", err)
	}
	if len(tokens) != 1 || tokens[0].RevokedAt == nil {
		t.Fatal("expected revoked token to remain listed with revoked_at set")
	}
}

func TestListAPITokensByUserID_Empty(t *testing.T) {
	s := testStore(t)
	user := &model.User{
		ID:           "u1",
		Username:     "scanner",
		Email:        "scanner@test.com",
		PasswordHash: "hash",
		Role:         model.RoleViewer,
	}
	if err := s.CreateUser(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	tokens, err := s.ListAPITokensByUserID(user.ID)
	if err != nil {
		t.Fatalf("list api tokens: %v", err)
	}
	if len(tokens) != 0 {
		t.Fatalf("expected no tokens, got %d", len(tokens))
	}
}

func TestUpdateAPITokenLastUsed(t *testing.T) {
	s := testStore(t)
	user := &model.User{
		ID:           "u1",
		Username:     "scanner",
		Email:        "scanner@test.com",
		PasswordHash: "hash",
		Role:         model.RoleViewer,
	}
	if err := s.CreateUser(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	expiresAt := time.Now().UTC().Add(time.Hour)
	token := &model.APIToken{
		ID:          "tok-1",
		UserID:      user.ID,
		Name:        "nightly",
		TokenHash:   "hash-1",
		TokenPrefix: "adt_123456789abc",
		ExpiresAt:   &expiresAt,
	}
	if err := s.CreateAPIToken(token); err != nil {
		t.Fatalf("create api token: %v", err)
	}

	usedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	if err := s.UpdateAPITokenLastUsed(token.ID, usedAt); err != nil {
		t.Fatalf("update last used: %v", err)
	}

	got, err := s.GetActiveAPITokenByHash(token.TokenHash)
	if err != nil {
		t.Fatalf("get api token: %v", err)
	}
	if got.LastUsedAt == nil {
		t.Fatal("expected last_used_at to be set")
	}
	if got.LastUsedAt.UTC().Format(time.RFC3339) != usedAt.Format(time.RFC3339) {
		t.Fatalf("expected last_used_at %s, got %s", usedAt.Format(time.RFC3339), got.LastUsedAt.UTC().Format(time.RFC3339))
	}
	if got.ExpiresAt == nil {
		t.Fatal("expected expires_at to be preserved")
	}
}

func TestRevokeAPIToken_NotFound(t *testing.T) {
	s := testStore(t)

	err := s.RevokeAPIToken("missing")
	if err == nil || err.Error() != "api token not found" {
		t.Fatalf("expected not found error, got %v", err)
	}
}

func TestCreateAPIToken_ClosedStore(t *testing.T) {
	s := testStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	err := s.CreateAPIToken(&model.APIToken{
		ID:          "tok-closed",
		UserID:      "u1",
		Name:        "nightly",
		TokenHash:   "hash-closed",
		TokenPrefix: "adt_closed",
	})
	if err == nil || err.Error() == "" {
		t.Fatal("expected closed-store create to fail")
	}
}

func TestListAPITokensByUserID_ClosedStore(t *testing.T) {
	s := testStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	if _, err := s.ListAPITokensByUserID("u1"); err == nil {
		t.Fatal("expected closed-store list to fail")
	}
}

func TestUpdateAPITokenLastUsed_ClosedStore(t *testing.T) {
	s := testStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	if err := s.UpdateAPITokenLastUsed("tok-1", time.Now().UTC()); err == nil {
		t.Fatal("expected closed-store update to fail")
	}
}

func TestRevokeAPIToken_ClosedStore(t *testing.T) {
	s := testStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	if err := s.RevokeAPIToken("tok-1"); err == nil {
		t.Fatal("expected closed-store revoke to fail")
	}
}
