package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/aerodocs/hub/internal/auth"
	"github.com/wyiu/aerodocs/hub/internal/model"
	"github.com/wyiu/aerodocs/hub/internal/store"
)

const (
	adminUsage         = "usage: aerodocs admin <command>\ncommands: reset-totp, create-api-token, list-api-tokens, revoke-api-token"
	defaultAdminDBPath = "aerodocs.db"
)

func runAdmin(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(adminUsage)
	}

	switch args[0] {
	case "reset-totp":
		return runResetTOTP(args[1:])
	case "create-api-token":
		return runCreateAPIToken(args[1:])
	case "list-api-tokens":
		return runListAPITokens(args[1:])
	case "revoke-api-token":
		return runRevokeAPIToken(args[1:])
	default:
		return fmt.Errorf("unknown admin command: %s", args[0])
	}
}

func runResetTOTP(args []string) error {
	fs := newAdminFlagSet("reset-totp")
	username := fs.String("username", "", "username to reset TOTP for")
	dbPath := fs.String("db", defaultAdminDBPath, "SQLite database path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resolvedUsername, err := requireValue(*username, "username")
	if err != nil {
		return err
	}

	st, user, err := openStoreAndLookupUser(*dbPath, resolvedUsername)
	if err != nil {
		return err
	}
	defer st.Close()

	tempPassword := auth.GenerateTemporaryPassword()
	hash, err := auth.HashPassword(tempPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if err := st.UpdateUserTOTP(user.ID, nil, false); err != nil {
		return fmt.Errorf("reset TOTP: %w", err)
	}
	if err := st.UpdateUserPassword(user.ID, hash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	fmt.Printf("TOTP reset for user %q\n", resolvedUsername)
	fmt.Printf("Temporary password: %s\n", tempPassword)
	fmt.Println("User must set up TOTP again on next login.")
	return nil
}

func runCreateAPIToken(args []string) error {
	fs := newAdminFlagSet("create-api-token")
	username := fs.String("username", "", "username that owns the token")
	name := fs.String("name", "", "human-readable token name")
	dbPath := fs.String("db", defaultAdminDBPath, "SQLite database path")
	expiresIn := fs.Duration("expires-in", 30*24*time.Hour, "token lifetime (0 for no expiry)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resolvedUsername, err := requireValue(*username, "username")
	if err != nil {
		return err
	}
	resolvedName, err := requireValue(*name, "name")
	if err != nil {
		return err
	}

	st, user, err := openStoreAndLookupUser(*dbPath, resolvedUsername)
	if err != nil {
		return err
	}
	defer st.Close()

	raw, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		return err
	}

	token := &model.APIToken{
		ID:          uuid.NewString(),
		UserID:      user.ID,
		Name:        resolvedName,
		TokenHash:   hash,
		TokenPrefix: prefix,
	}
	if *expiresIn > 0 {
		expiresAt := time.Now().UTC().Add(*expiresIn)
		token.ExpiresAt = &expiresAt
	}

	if err := st.CreateAPIToken(token); err != nil {
		return err
	}

	tokenID := token.ID
	tokenName := token.Name
	apiTokenResourceType := "api_token"
	_ = st.LogAudit(model.AuditEntry{
		ID:           uuid.NewString(),
		UserID:       &user.ID,
		Action:       model.AuditAPITokenCreated,
		Target:       &tokenID,
		Detail:       &tokenName,
		Outcome:      model.AuditOutcomeSuccess,
		ActorType:    model.AuditActorTypeSystem,
		ResourceType: &apiTokenResourceType,
	})

	fmt.Printf("API token created for %q\n", user.Username)
	fmt.Printf("Token ID: %s\n", token.ID)
	fmt.Printf("Name: %s\n", token.Name)
	fmt.Printf("Prefix: %s\n", token.TokenPrefix)
	fmt.Printf("Expires At: %s\n", formatOptionalTime(token.ExpiresAt))
	fmt.Printf("Token: %s\n", raw)
	fmt.Println("Store the token securely. It will not be shown again.")
	return nil
}

func runListAPITokens(args []string) error {
	fs := newAdminFlagSet("list-api-tokens")
	username := fs.String("username", "", "username that owns the tokens")
	dbPath := fs.String("db", defaultAdminDBPath, "SQLite database path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resolvedUsername, err := requireValue(*username, "username")
	if err != nil {
		return err
	}

	st, user, err := openStoreAndLookupUser(*dbPath, resolvedUsername)
	if err != nil {
		return err
	}
	defer st.Close()

	tokens, err := st.ListAPITokensByUserID(user.ID)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		fmt.Printf("No API tokens found for %q\n", user.Username)
		return nil
	}

	fmt.Println("ID\tNAME\tPREFIX\tEXPIRES_AT\tLAST_USED_AT\tSTATUS")
	now := time.Now().UTC()
	for _, token := range tokens {
		fmt.Printf(
			"%s\t%s\t%s\t%s\t%s\t%s\n",
			token.ID,
			token.Name,
			token.TokenPrefix,
			formatOptionalTime(token.ExpiresAt),
			formatOptionalTime(token.LastUsedAt),
			apiTokenStatus(token, now),
		)
	}
	return nil
}

func runRevokeAPIToken(args []string) error {
	fs := newAdminFlagSet("revoke-api-token")
	tokenID := fs.String("id", "", "token ID to revoke")
	dbPath := fs.String("db", defaultAdminDBPath, "SQLite database path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resolvedTokenID, err := requireValue(*tokenID, "id")
	if err != nil {
		return err
	}

	st, err := openAdminStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.RevokeAPIToken(resolvedTokenID); err != nil {
		return err
	}

	revokedID := resolvedTokenID
	apiTokenResourceType := "api_token"
	_ = st.LogAudit(model.AuditEntry{
		ID:           uuid.NewString(),
		Action:       model.AuditAPITokenRevoked,
		Target:       &revokedID,
		Outcome:      model.AuditOutcomeSuccess,
		ActorType:    model.AuditActorTypeSystem,
		ResourceType: &apiTokenResourceType,
	})

	fmt.Printf("API token %s revoked\n", resolvedTokenID)
	return nil
}

func newAdminFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func requireValue(value, name string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("--%s is required", name)
	}
	return trimmed, nil
}

func openAdminStore(dbPath string) (*store.Store, error) {
	st, err := store.New(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	return st, nil
}

func openStoreAndLookupUser(dbPath, username string) (*store.Store, *model.User, error) {
	st, err := openAdminStore(dbPath)
	if err != nil {
		return nil, nil, err
	}

	user, err := st.GetUserByUsername(username)
	if err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("user %q not found", username)
	}
	return st, user, nil
}

func formatOptionalTime(value *time.Time) string {
	if value == nil {
		return "never"
	}
	return value.Format(time.RFC3339)
}

func apiTokenStatus(token model.APIToken, now time.Time) string {
	if token.RevokedAt != nil {
		return "revoked"
	}
	if token.ExpiresAt != nil && token.ExpiresAt.Before(now) {
		return "expired"
	}
	return "active"
}
