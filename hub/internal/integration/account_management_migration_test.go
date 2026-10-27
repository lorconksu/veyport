package integration

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	_ "modernc.org/sqlite"
)

// Exercise reopening a real baseline database, not just executing the ALTER in
// isolation. Legacy SSH credentials keep epoch zero until an actual recovery.
func TestAccountManagementMigrationPreservesLegacyUsersAndRevokesSSHCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.db")
	st, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	u := &model.User{ID: "legacy", Username: "legacy", Email: "legacy@test.invalid", PasswordHash: "legacy-hash", Role: model.RoleViewer, TokenGeneration: 7}
	if err := st.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	st.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// Reconstruct the released schema immediately preceding migration 031.
	if _, err := db.Exec("ALTER TABLE users DROP COLUMN ssh_credential_generation"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM _migrations WHERE filename='031_ssh_credential_generation.sql'"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	st, err = store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	live, err := st.GetUserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if live.PasswordHash != u.PasswordHash || live.TokenGeneration != 7 || live.SSHCredentialGeneration != 0 {
		t.Fatal("migration changed legacy authority")
	}
	now := time.Now().UTC()
	entry := model.AuditEntry{UserID: &u.ID, Target: &u.ID, Action: model.AuditUserPasswordReset}
	reset, err := st.ResetLocalPassword(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: 7}, store.TemporaryPasswordCredential{Hash: "temporary-hash", ExpiresAt: now.Add(time.Hour)}, now, 5, entry)
	if err != nil {
		t.Fatal(err)
	}
	if reset.SSHCredentialGeneration != 1 {
		t.Fatal("password reset did not revoke legacy SSH epoch")
	}
	if _, err := st.ChangeLocalPassword(reset, "permanent-hash", now, 5, true, entry); err != nil {
		t.Fatal(err)
	}
	live, err = st.GetUserByID(u.ID)
	if err != nil || live.SSHCredentialGeneration != 2 || live.MustChangePassword {
		t.Fatal("completion restored legacy SSH authority")
	}
}
