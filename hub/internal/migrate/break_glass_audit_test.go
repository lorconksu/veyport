package migrate_test

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/migrate"
)

func TestBreakGlassAuditUpgradeFromEarly032(t *testing.T) {
	db := testDB(t)
	execSQL(t, db, "PRAGMA foreign_keys=ON")
	if err := migrate.Run(db); err != nil {
		t.Fatal(err)
	}
	// Recreate exactly the early 032 grant shape, which lacked an audit FK.
	execSQL(t, db, `DROP TABLE local_break_glass_recoveries;
	 CREATE TABLE local_break_glass_recoveries(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,audit_id TEXT NOT NULL,password_hash TEXT NOT NULL,token_generation INTEGER NOT NULL,password_pending INTEGER NOT NULL,expires_at TEXT NOT NULL);
	 DELETE FROM _migrations WHERE filename='033_bind_break_glass_audit.sql';
	 INSERT INTO users(id,username,email,password_hash,role) VALUES('valid','valid','valid@test','h','viewer'),('orphan','orphan','orphan@test','h','viewer'),('invalid','invalid','invalid@test','h','viewer');
	 INSERT INTO audit_logs(id,user_id,target,action,outcome,actor_type) VALUES('reset','valid','valid','user.totp_reset','success','system'),('wrong','invalid','invalid','user.totp_reset','failure','system');
	 INSERT INTO local_break_glass_recoveries VALUES('valid','reset','h',1,1,'2099-01-01'),('orphan','missing','h',1,1,'2099-01-01'),('invalid','wrong','h',1,1,'2099-01-01');`)
	if err := migrate.Run(db); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM local_break_glass_recoveries WHERE user_id='valid'").Scan(&count); err != nil || count != 1 {
		t.Fatal("upgrade lost valid recovery authority")
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM local_break_glass_recoveries").Scan(&count); err != nil || count != 1 {
		t.Fatal("upgrade retained invalid provenance")
	}
	if err := migrate.Run(db); err != nil {
		t.Fatal(err)
	}
	execSQL(t, db, "DELETE FROM audit_logs WHERE id='reset'")
	if err := db.QueryRow("SELECT COUNT(*) FROM local_break_glass_recoveries").Scan(&count); err != nil || count != 0 {
		t.Fatal("upgraded grant did not cascade on audit deletion")
	}
}
