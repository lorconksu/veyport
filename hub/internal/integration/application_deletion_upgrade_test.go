package integration

import (
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"path/filepath"
	"testing"
	"time"
)

func TestApplicationDeletionMigrationUpgradesPrototype029WithoutChangingAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prototype.db")
	st, e := store.New(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = st.CreateUser(&model.User{ID: "upgrade-user", Username: "upgrade-user", Email: "upgrade@example.test", Role: model.RoleViewer, TOTPEnabled: true}); e != nil {
		t.Fatal(e)
	}
	before, e := st.GetUserByID("upgrade-user")
	if e != nil {
		t.Fatal(e)
	}
	app := &model.Application{ID: "upgrade-app", Name: "Upgrade", Slug: "upgrade", PublicHostname: "upgrade.apps.example.test", BackendURL: "http://127.0.0.1:8081", Route: "hub", Enabled: true, AllowedCIDRs: []string{"127.0.0.0/8"}}
	if e = st.CreateApplication(app, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	// Reconstruct the exact previous prototype schema, retaining user/app rows.
	if _, e = st.DB().Exec(`ALTER TABLE applications DROP COLUMN deleting`); e != nil {
		t.Fatal(e)
	}
	if _, e = st.DB().Exec(`DELETE FROM _migrations WHERE filename='030_application_deletion_admission.sql'`); e != nil {
		t.Fatal(e)
	}
	if e = st.Close(); e != nil {
		t.Fatal(e)
	}
	st, e = store.New(path)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	after, e := st.GetUserByID(before.ID)
	if e != nil {
		t.Fatal(e)
	}
	if after.Role != before.Role || after.TokenGeneration != before.TokenGeneration || after.SecurityRevision != before.SecurityRevision {
		t.Fatal("migration changed preexisting authority")
	}
	var deleting int
	if e = st.DB().QueryRow(`SELECT deleting FROM applications WHERE id=?`, app.ID).Scan(&deleting); e != nil || deleting != 0 {
		t.Fatal("deletion column not initialized", e)
	}
	current, e := st.GetApplication(app.ID)
	if e != nil || !current.Enabled || current.ConfigVersion != 1 {
		t.Fatal("migration changed app admission", e)
	}
	if e = st.BeginApplicationDeletion(app.ID, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	current, e = st.GetApplication(app.ID)
	if e != nil || current.Enabled || current.ConfigVersion != 2 {
		t.Fatal("upgraded app cannot close admission", e)
	}
}
