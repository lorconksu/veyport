package migrate_test

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/migrate"
)

func TestOriginalAccessMigrationAddsBoundedOneUseMetadata(t *testing.T) {
	db := testDB(t)
	if err := migrate.Run(db); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"original_access", "original_read_evidence", "original_read_confirmations"} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("missing %s: %v", table, err)
		}
	}
	var columns int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('original_access') WHERE name IN ('handle_sha256','consumed_at','security_revision','session_id')").Scan(&columns); err != nil || columns != 4 {
		t.Fatalf("one-use authority columns=%d err=%v", columns, err)
	}
	var raw int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('original_access') WHERE name IN ('handle','command','script','original_bytes')").Scan(&raw); err != nil || raw != 0 {
		t.Fatal("original content or raw handle column exists")
	}
}
