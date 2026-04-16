package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/aerodocs/hub/internal/auth"
	"github.com/wyiu/aerodocs/hub/internal/model"
	"github.com/wyiu/aerodocs/hub/internal/store"
)

func runAdmin(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: aerodocs admin <command>\ncommands: reset-totp, create-api-token, list-api-tokens, revoke-api-token")
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
	fs := flag.NewFlagSet("reset-totp", flag.ExitOnError)
	username := fs.String("username", "", "username to reset TOTP for")
	dbPath := fs.String("db", "aerodocs.db", "SQLite database path")
	fs.Parse(args)

	if *username == "" {
		return fmt.Errorf("--username is required")
	}

	st, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	user, err := st.GetUserByUsername(*username)
	if err != nil {
		return fmt.Errorf("user %q not found", *username)
	}

	// Generate new temporary password
	tempPassword := auth.GenerateTemporaryPassword()
	hash, err := auth.HashPassword(tempPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// Reset TOTP and password
	if err := st.UpdateUserTOTP(user.ID, nil, false); err != nil {
		return fmt.Errorf("reset TOTP: %w", err)
	}
	if err := st.UpdateUserPassword(user.ID, hash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	fmt.Printf("TOTP reset for user %q\n", *username)
	fmt.Printf("Temporary password: %s\n", tempPassword)
	fmt.Println("User must set up TOTP again on next login.")

	return nil
}

func runCreateAPIToken(args []string) error {
	fs := flag.NewFlagSet("create-api-token", flag.ExitOnError)
	username := fs.String("username", "", "username that owns the token")
	name := fs.String("name", "", "human-readable token name")
	dbPath := fs.String("db", "aerodocs.db", "SQLite database path")
	expiresIn := fs.Duration("expires-in", 30*24*time.Hour, "token lifetime (0 for no expiry)")
	fs.Parse(args)

	if *username == "" {
		return fmt.Errorf("--username is required")
	}
	if strings.TrimSpace(*name) == "" {
		return fmt.Errorf("--name is required")
	}

	st, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	user, err := st.GetUserByUsername(*username)
	if err != nil {
		return fmt.Errorf("user %q not found", *username)
	}

	raw, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		return err
	}

	token := &model.APIToken{
		ID:          uuid.NewString(),
		UserID:      user.ID,
		Name:        strings.TrimSpace(*name),
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

	fmt.Printf("API token created for %q\n", user.Username)
	fmt.Printf("Token ID: %s\n", token.ID)
	fmt.Printf("Name: %s\n", token.Name)
	fmt.Printf("Prefix: %s\n", token.TokenPrefix)
	if token.ExpiresAt != nil {
		fmt.Printf("Expires At: %s\n", token.ExpiresAt.Format(time.RFC3339))
	} else {
		fmt.Println("Expires At: never")
	}
	fmt.Printf("Token: %s\n", raw)
	fmt.Println("Store the token securely. It will not be shown again.")
	return nil
}

func runListAPITokens(args []string) error {
	fs := flag.NewFlagSet("list-api-tokens", flag.ExitOnError)
	username := fs.String("username", "", "username that owns the tokens")
	dbPath := fs.String("db", "aerodocs.db", "SQLite database path")
	fs.Parse(args)

	if *username == "" {
		return fmt.Errorf("--username is required")
	}

	st, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	user, err := st.GetUserByUsername(*username)
	if err != nil {
		return fmt.Errorf("user %q not found", *username)
	}

	tokens, err := st.ListAPITokensByUserID(user.ID)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		fmt.Printf("No API tokens found for %q\n", user.Username)
		return nil
	}

	fmt.Println("ID\tNAME\tPREFIX\tEXPIRES_AT\tLAST_USED_AT\tSTATUS")
	for _, token := range tokens {
		expiresAt := "never"
		if token.ExpiresAt != nil {
			expiresAt = token.ExpiresAt.Format(time.RFC3339)
		}
		lastUsedAt := "never"
		if token.LastUsedAt != nil {
			lastUsedAt = token.LastUsedAt.Format(time.RFC3339)
		}
		status := "active"
		if token.RevokedAt != nil {
			status = "revoked"
		} else if token.ExpiresAt != nil && token.ExpiresAt.Before(time.Now().UTC()) {
			status = "expired"
		}
		fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\n", token.ID, token.Name, token.TokenPrefix, expiresAt, lastUsedAt, status)
	}
	return nil
}

func runRevokeAPIToken(args []string) error {
	fs := flag.NewFlagSet("revoke-api-token", flag.ExitOnError)
	tokenID := fs.String("id", "", "token ID to revoke")
	dbPath := fs.String("db", "aerodocs.db", "SQLite database path")
	fs.Parse(args)

	if *tokenID == "" {
		return fmt.Errorf("--id is required")
	}

	st, err := store.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	if err := st.RevokeAPIToken(*tokenID); err != nil {
		return err
	}

	fmt.Printf("API token %s revoked\n", *tokenID)
	return nil
}
