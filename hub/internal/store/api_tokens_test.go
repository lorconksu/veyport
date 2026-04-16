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
