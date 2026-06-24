package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

// RotateResult holds the outcome of a JWT secret rotation.
// It must NOT carry the new secret — no field for key material.
type RotateResult struct {
	RevokedAPITokens int
}

// RotateJWTSecret replaces the jwt_signing_key with a fresh 32-byte
// crypto/rand hex value, revokes all active API tokens, and records the
// rotation timestamp — all in a single SQLite transaction.  After commit it
// writes one audit entry (action AuditJWTSecretRotated).
//
// Returns an error if the instance has never been initialised (jwt_signing_key
// absent or empty); in that case no state is written.
func RotateJWTSecret(st *store.Store) (RotateResult, error) {
	// Guard: must be initialised.
	existing, err := st.GetConfig("jwt_signing_key")
	if err != nil || existing == "" {
		return RotateResult{}, fmt.Errorf("instance not initialized: jwt_signing_key not found in database")
	}

	// Generate new key.
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return RotateResult{}, fmt.Errorf("generate new jwt signing key: %w", err)
	}
	newKey := hex.EncodeToString(keyBytes)

	rotatedAt := time.Now().UTC().Format(time.RFC3339)

	// Run everything in a single transaction.
	tx, err := st.DB().Begin()
	if err != nil {
		return RotateResult{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Update jwt_signing_key.
	if _, err := tx.Exec(
		"INSERT INTO _config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		"jwt_signing_key", newKey,
	); err != nil {
		return RotateResult{}, fmt.Errorf("update jwt_signing_key: %w", err)
	}

	// Set jwt_secret_rotated_at.
	if _, err := tx.Exec(
		"INSERT INTO _config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		"jwt_secret_rotated_at", rotatedAt,
	); err != nil {
		return RotateResult{}, fmt.Errorf("update jwt_secret_rotated_at: %w", err)
	}

	// Revoke all active API tokens (cross-user), counting affected rows.
	result, err := tx.Exec(
		`UPDATE api_tokens
		 SET revoked_at = datetime('now'), updated_at = datetime('now')
		 WHERE revoked_at IS NULL`,
	)
	if err != nil {
		return RotateResult{}, fmt.Errorf("revoke all api tokens: %w", err)
	}
	revokedCount, err := result.RowsAffected()
	if err != nil {
		return RotateResult{}, fmt.Errorf("count revoked api tokens: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return RotateResult{}, fmt.Errorf("commit rotation transaction: %w", err)
	}

	// Post-commit: write audit entry (mirrors InitStorageKey / reset-totp pattern).
	detail, _ := json.Marshal(map[string]interface{}{
		"revoked_api_tokens": int(revokedCount),
	})
	detailStr := string(detail)
	_ = st.LogAudit(model.AuditEntry{
		ID:        uuid.NewString(),
		Action:    model.AuditJWTSecretRotated,
		Outcome:   model.AuditOutcomeSuccess,
		ActorType: model.AuditActorTypeSystem,
		Detail:    &detailStr,
	})

	return RotateResult{RevokedAPITokens: int(revokedCount)}, nil
}
