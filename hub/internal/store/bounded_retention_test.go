package store

import (
	"fmt"
	"strings"
	"testing"
)

func TestRetentionIndexedBoundedAndContinuesPastLiveGrants(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, q := range []string{
		`WITH RECURSIVE n(x) AS(VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<2999)
 INSERT INTO audit_logs(id,action,created_at) SELECT printf('%06d',x),'user.totp_reset','2000-01-01 00:00:00' FROM n`,
		`WITH RECURSIVE n(x) AS(VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<1099)
 INSERT INTO users(id,username,email,password_hash,role) SELECT printf('%06d',x),printf('user%d',x),printf('user%d@test',x),'h','viewer' FROM n`,
		`INSERT INTO local_break_glass_recoveries SELECT id,id,'h',0,1,'2099-01-01 00:00:00' FROM users`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		query, index string
		args         []any
	}{
		{"EXPLAIN QUERY PLAN " + auditRetentionCandidates, "idx_audit_logs_retention", []any{int64(-1 << 63), "", int64(2000000000), auditRetentionBatch}},
		{"EXPLAIN QUERY PLAN DELETE FROM audit_logs WHERE id=? AND NOT EXISTS(SELECT 1 FROM local_break_glass_recoveries r WHERE r.audit_id=audit_logs.id AND unixepoch(r.expires_at)>unixepoch())", "idx_local_break_glass_recoveries_audit_id", []any{"000000"}},
	} {
		rows, err := s.db.Query(test.query, test.args...)
		if err != nil {
			t.Fatal(err)
		}
		var plan strings.Builder
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan.WriteString(detail + "\n")
		}
		rows.Close()
		t.Log(plan.String())
		if !strings.Contains(plan.String(), test.index) || strings.Contains(plan.String(), "SCAN audit_logs") || strings.Contains(plan.String(), "SCAN r") || strings.Contains(plan.String(), "TEMP B-TREE") {
			t.Fatal("unbounded retention plan")
		}
	}
	total := 0
	for call := 0; call < 4; call++ {
		n, err := s.DeleteAuditLogsBefore(fmt.Sprintf("2026-10-27T00:00:%02dZ", call))
		if err != nil {
			t.Fatal(err)
		}
		if n > auditRetentionBatch*auditRetentionBatches {
			t.Fatal("retention exceeded request budget")
		}
		if call == 0 && n != 0 {
			t.Fatal("first window did not retain live grants")
		}
		total += n
	}
	if total != 1900 {
		t.Fatalf("continuation starved rows beyond pinned grants: %d", total)
	}
	var pinned int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_logs").Scan(&pinned); err != nil || pinned != 1100 {
		t.Fatalf("lost live provenance: %d %v", pinned, err)
	}
}
func TestRetentionExactSubsecondAndOffsetInstants(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i, stamp := range []string{"2026-10-26T18:00:00.999999998Z", "2026-10-26T20:00:00.999999999+02:00", "2026-10-26 18:00:01"} {
		if _, err := s.db.Exec("INSERT INTO audit_logs(id,action,created_at) VALUES(?,'user.login',?)", fmt.Sprint(i), stamp); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.DeleteAuditLogsBefore("2026-10-26T18:00:00.999999999Z"); err != nil || n != 1 {
		t.Fatalf("subsecond cutoff: %d %v", n, err)
	}
}

func TestRetentionPeriodicallyRevisitsFormerlyPinnedRows(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, query := range []string{
		`WITH RECURSIVE n(x) AS(VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<9000)
 INSERT INTO audit_logs(id,action,created_at) SELECT printf('%06d',x),'user.totp_reset','2000-01-01 00:00:00' FROM n`,
		`INSERT INTO users(id,username,email,password_hash,role) VALUES('protected','protected','protected@test','h','viewer')`,
		`INSERT INTO local_break_glass_recoveries(user_id,audit_id,password_hash,token_generation,password_pending,expires_at)
 VALUES('protected','000000','h',0,1,'2099-01-01 00:00:00')`,
	} {
		if _, err := s.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DeleteAuditLogsBefore("2026-10-27T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE local_break_glass_recoveries SET expires_at='2000-01-01 00:00:00' WHERE audit_id='000000'"); err != nil {
		t.Fatal(err)
	}
	for call := 1; call < auditRetentionRewindCalls; call++ {
		if _, err := s.DeleteAuditLogsBefore("2026-10-27T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE id='000000'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("formerly pinned audit row was starved behind a persistent retention backlog")
	}
}

func TestRetentionRevisitDoesNotStarveMainSweep(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, query := range []string{
		`WITH RECURSIVE n(x) AS(VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<8191)
 INSERT INTO audit_logs(id,action,created_at) SELECT printf('%06d',x),'user.totp_reset','2000-01-01 00:00:00' FROM n`,
		`INSERT INTO audit_logs(id,action,created_at) VALUES('999999','user.login','2000-01-01 00:00:00')`,
		`WITH RECURSIVE n(x) AS(VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<8191)
 INSERT INTO users(id,username,email,password_hash,role) SELECT printf('%06d',x),printf('pinned%d',x),printf('pinned%d@test',x),'h','viewer' FROM n`,
		`INSERT INTO local_break_glass_recoveries(user_id,audit_id,password_hash,token_generation,password_pending,expires_at)
 SELECT id,id,'h',0,1,'malformed-but-retained' FROM users`,
	} {
		if _, err := s.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	for call := 0; call < 24; call++ {
		n, err := s.DeleteAuditLogsBefore("2026-10-27T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		if n > auditRetentionBatch*auditRetentionBatches {
			t.Fatal("retention exceeded request budget")
		}
	}
	var eligible int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE id='999999'").Scan(&eligible); err != nil {
		t.Fatal(err)
	}
	if eligible != 0 {
		t.Fatal("periodic revisit starved the main retention cursor")
	}
	var pinned int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE id!='999999'").Scan(&pinned); err != nil || pinned != 8192 {
		t.Fatalf("retention removed pinned provenance: %d %v", pinned, err)
	}
}
