package store

import (
	"github.com/wyiu/veyport/hub/internal/model"
	"strings"
	"testing"
)

func TestAuditRetentionFailedBatchReportsOnlyCommittedDeletes(t *testing.T) {
	s := auditGuardStore(t)
	auditGuardExec(t, s, "INSERT INTO audit_logs(id,action,created_at) VALUES('a','user.login','2000-01-01 00:00:00'),('b','user.login','2000-01-01 00:00:00')")
	auditGuardExec(t, s, `CREATE TRIGGER reject_retention BEFORE DELETE ON audit_logs WHEN OLD.id='b' BEGIN SELECT RAISE(ABORT,'retention fault'); END`)
	n, err := s.DeleteAuditLogsBefore("2026-01-01T00:00:00Z")
	if err == nil || n != 0 {
		t.Fatalf("rolled back batch reported committed deletes: count=%d err=%v", n, err)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_logs").Scan(&count); err != nil || count != 2 {
		t.Fatalf("failed batch lost records: %d %v", count, err)
	}
	auditGuardExec(t, s, "DROP TRIGGER reject_retention")
	if n, err := s.DeleteAuditLogsBefore("2026-01-01T00:00:00Z"); err != nil || n != 2 {
		t.Fatalf("retry skipped rolled back candidates: %d %v", n, err)
	}
}

func TestAuditAppendStorageFailuresRollBackAndRecover(t *testing.T) {
	for _, failure := range []string{"read", "insert", "commit"} {
		t.Run(failure, func(t *testing.T) {
			s := auditGuardStore(t)
			restore := ""
			switch failure {
			case "read":
				auditGuardExec(t, s, "ALTER TABLE audit_logs RENAME TO saved_logs")
				restore = "ALTER TABLE saved_logs RENAME TO audit_logs"
			case "insert":
				auditGuardExec(t, s, `CREATE TRIGGER reject_append BEFORE INSERT ON audit_logs BEGIN SELECT RAISE(ABORT,'append fault'); END`)
				restore = "DROP TRIGGER reject_append"
			case "commit":
				auditGuardExec(t, s, `CREATE TRIGGER reject_append AFTER INSERT ON audit_logs BEGIN UPDATE audit_logs SET user_id='missing' WHERE id=NEW.id; END`)
				auditGuardExec(t, s, "PRAGMA defer_foreign_keys=ON")
				restore = "DROP TRIGGER reject_append"
			}
			if err := s.LogAudit(model.AuditEntry{ID: "write", Action: model.AuditUserLogin}); err == nil {
				t.Fatal("storage failure accepted")
			}
			auditGuardExec(t, s, restore)
			rows, total, err := s.ListAuditLogs(model.AuditFilter{})
			if err != nil || total != 0 || len(rows) != 0 {
				t.Fatalf("failed append persisted: %d %v", total, err)
			}
			h, err := s.GetAuditHealth()
			if err != nil || !h.Degraded || h.FailureCount != 1 {
				t.Fatalf("append failure not visible: %+v %v", h, err)
			}
			if err := s.LogAudit(model.AuditEntry{Action: model.AuditUserLogin}); err != nil {
				t.Fatal(err)
			}
			h, err = s.GetAuditHealth()
			if err != nil || h.Degraded || h.LastRecoveredAt == nil {
				t.Fatalf("committed append did not recover health: %+v %v", h, err)
			}
		})
	}
}

func TestAuditWorkflowRoundTripAndStorageFailures(t *testing.T) {
	s := auditGuardStore(t)
	auditGuardExec(t, s, "INSERT INTO users(id,username,email,password_hash,role) VALUES('reviewer','reviewer','reviewer@test','h','admin')")
	f, err := s.CreateAuditSavedFilter("reviewer", "saved", `{"action":"user.login"}`)
	if err != nil {
		t.Fatal(err)
	}
	filters, err := s.ListAuditSavedFilters()
	if err != nil || len(filters) != 1 || filters[0].ID != f.ID {
		t.Fatalf("filter roundtrip: %+v %v", filters, err)
	}
	from, to := "2026-01-01", "2026-02-01"
	r, err := s.CreateAuditReview("reviewer", "{}", "reviewed", &from, &to)
	if err != nil {
		t.Fatal(err)
	}
	reviews, err := s.ListAuditReviews(0)
	if err != nil || len(reviews) != 1 || reviews[0].ID != r.ID || reviews[0].From == nil || *reviews[0].To != to {
		t.Fatalf("review roundtrip: %+v %v", reviews, err)
	}
	if err := s.LogAudit(model.AuditEntry{ID: "entry", Action: model.AuditUserLogin}); err != nil {
		t.Fatal(err)
	}
	entry := "entry"
	flag, err := s.CreateAuditFlag("reviewer", &entry, "{}", "inspect")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAuditFlag("reviewer", nil, "{}", "whole selection"); err != nil {
		t.Fatal(err)
	}
	flags, err := s.ListAuditFlags(0)
	if err != nil || len(flags) != 2 {
		t.Fatalf("flag roundtrip: %+v %v", flags, err)
	}
	found := false
	for _, got := range flags {
		if got.ID == flag.ID && got.EntryID != nil && *got.EntryID == entry {
			found = true
		}
	}
	if !found {
		t.Fatal("flag lost entry binding")
	}
	if err := s.DeleteAuditSavedFilter(f.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAuditSavedFilter(f.ID); err == nil {
		t.Fatal("missing delete accepted")
	}
	for _, table := range []string{"audit_saved_filters", "audit_reviews", "audit_flags"} {
		t.Run(table, func(t *testing.T) {
			auditGuardExec(t, s, "ALTER TABLE "+table+" RENAME TO saved_workflow")
			switch table {
			case "audit_saved_filters":
				if _, err := s.ListAuditSavedFilters(); err == nil {
					t.Fatal("read accepted")
				}
				if _, err := s.CreateAuditSavedFilter("reviewer", "f", "{}"); err == nil {
					t.Fatal("write accepted")
				}
				if err := s.DeleteAuditSavedFilter("missing"); err == nil {
					t.Fatal("delete accepted")
				}
			case "audit_reviews":
				if _, err := s.ListAuditReviews(1); err == nil {
					t.Fatal("read accepted")
				}
				if _, err := s.CreateAuditReview("reviewer", "{}", "n", nil, nil); err == nil {
					t.Fatal("write accepted")
				}
			case "audit_flags":
				if _, err := s.ListAuditFlags(1); err == nil {
					t.Fatal("read accepted")
				}
				if _, err := s.CreateAuditFlag("reviewer", nil, "{}", "n"); err == nil {
					t.Fatal("write accepted")
				}
			}
			auditGuardExec(t, s, "ALTER TABLE saved_workflow RENAME TO "+table)
		})
	}
}

func TestAuditSettingsValidationRejectsEachInvalidField(t *testing.T) {
	for _, field := range []string{"retention", "reminder", "history", "ttl", "login", "registration", "privileged"} {
		t.Run(field, func(t *testing.T) {
			s := auditGuardStore(t)
			v := s.GetAuditSettings()
			switch field {
			case "retention":
				v.RetentionDays = 3651
			case "reminder":
				v.ReviewReminderDays = 366
			case "history":
				v.PasswordHistoryCount = 25
			case "ttl":
				v.TemporaryPasswordTTLHours = 721
			case "login":
				v.Thresholds.LoginFailuresPerHour = 10001
			case "registration":
				v.Thresholds.RegistrationFailuresPerHour = 10001
			case "privileged":
				v.Thresholds.PrivilegedActionsPerHour = 10001
			}
			if err := s.UpdateAuditSettings(v); err == nil || !strings.Contains(err.Error(), "must be between") {
				t.Fatalf("invalid %s accepted: %v", field, err)
			}
			if auditGuardCount(t, s) != 0 {
				t.Fatal("validation emitted success")
			}
		})
	}
}

func TestAuditListTimeFiltersCompareInstantsAcrossFormatsAndOffsets(t *testing.T) {
	s := auditGuardStore(t)
	auditGuardExec(t, s, "INSERT INTO audit_logs(id,action,created_at) VALUES('older','user.login','2026-11-03 21:59:59'),('inside','user.login','2026-11-03 22:00:00'),('offset','user.login','2026-11-04T00:00:00+02:00'),('newer','user.login','2026-11-03 22:00:01')")
	from, to := "2026-11-03T22:00:00Z", "2026-11-04T00:00:00+02:00"
	entries, n, err := s.ListAuditLogs(model.AuditFilter{From: &from, To: &to})
	if err != nil || n != 2 || len(entries) != 2 {
		t.Fatalf("equivalent audit instants excluded: count=%d entries=%+v err=%v", n, entries, err)
	}
	for _, entry := range entries {
		if entry.ID != "inside" && entry.ID != "offset" {
			t.Fatalf("outside audit instant included: %+v", entry)
		}
	}
}

func TestAuditTimeFilterUsesIndexedCandidateRange(t *testing.T) {
	s := auditGuardStore(t)
	rows, err := s.db.Query("EXPLAIN QUERY PLAN SELECT COUNT(*) FROM audit_logs WHERE (created_at_epoch >= ? OR created_at_epoch IS NULL) AND veyport_audit_time_compare(created_at, ?) >= 0", int64(1793663999), "2026-11-03T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "idx_audit_logs_retention") || strings.Contains(plan.String(), "SCAN audit_logs") {
		t.Fatalf("unindexed time filter: %s", plan.String())
	}
}

func TestAuditRetentionConcurrentSweepYieldsAndPreservesCandidate(t *testing.T) {
	s := auditGuardStore(t)
	auditGuardExec(t, s, "INSERT INTO audit_logs(id,action,created_at) VALUES('old','user.login','2000-01-01 00:00:00')")
	s.auditRetentionMu.Lock()
	n, err := s.DeleteAuditLogsBefore("2026-01-01T00:00:00Z")
	s.auditRetentionMu.Unlock()
	if err != nil || n != 0 {
		t.Fatalf("overlapping sweep did not yield: %d %v", n, err)
	}
	if n, err := s.DeleteAuditLogsBefore("2026-01-01T00:00:00Z"); err != nil || n != 1 {
		t.Fatalf("overlapping sweep advanced or lost candidate: %d %v", n, err)
	}
}

func TestAuditRetentionLaterBatchFailureKeepsCommittedCountAndResumes(t *testing.T) {
	s := auditGuardStore(t)
	auditGuardExec(t, s, `WITH RECURSIVE n(x) AS(VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<257) INSERT INTO audit_logs(id,action,created_at) SELECT printf('%04d',x),'user.login','2000-01-01 00:00:00' FROM n`)
	auditGuardExec(t, s, `CREATE TRIGGER reject_later_retention BEFORE DELETE ON audit_logs WHEN OLD.id='0257' BEGIN SELECT RAISE(ABORT,'later retention fault'); END`)
	if n, err := s.DeleteAuditLogsBefore("2026-01-01T00:00:00Z"); err == nil || n != auditRetentionBatch {
		t.Fatalf("partial retention count includes rollback or loses committed batch: %d %v", n, err)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_logs").Scan(&count); err != nil || count != 2 {
		t.Fatalf("later batch did not roll back: %d %v", count, err)
	}
	auditGuardExec(t, s, "DROP TRIGGER reject_later_retention")
	if n, err := s.DeleteAuditLogsBefore("2026-01-01T00:00:00Z"); err != nil || n != 2 {
		t.Fatalf("retry skipped failed batch: %d %v", n, err)
	}
}

func TestAuditTimeFilterRetainsExactFractionalBoundariesAndPagination(t *testing.T) {
	for _, precision := range []struct{ name, older, inside, newer, from, to string }{
		{"microseconds", "2026-11-03 22:00:00.000001", "2026-11-03 22:00:00.000002", "2026-11-03 22:00:00.000003", "2026-11-03T22:00:00.000002Z", "2026-11-04T00:00:00.000002+02:00"},
		{"nanoseconds", "2026-11-03 22:00:00.000000001", "2026-11-03 22:00:00.000000002", "2026-11-03 22:00:00.000000003", "2026-11-03T22:00:00.000000002Z", "2026-11-04T00:00:00.000000002+02:00"},
		{"second-rollover", "2026-11-03 22:00:00.999999998", "2026-11-03 22:00:00.999999999", "2026-11-03 22:00:01", "2026-11-03T22:00:00.999999999Z", "2026-11-04T00:00:00.999999999+02:00"},
		{"non-sqlite-offset", "2026-11-03 07:00:00.000001", "2026-11-03 07:00:00.000002", "2026-11-03 07:00:00.000003", "2026-11-03T22:00:00.000002+15:00", "2026-11-03T22:00:00.000002+15:00"},
	} {
		t.Run(precision.name, func(t *testing.T) {
			s := auditGuardStore(t)
			for _, row := range []struct{ id, stamp string }{{"older", precision.older}, {"inside", precision.inside}, {"newer", precision.newer}, {"offset-equivalent", precision.to}} {
				auditGuardExec(t, s, "INSERT INTO audit_logs(id,action,created_at) VALUES(?,'user.login',?)", row.id, row.stamp)
			}
			for _, filter := range []model.AuditFilter{{From: &precision.from}, {To: &precision.to}, {From: &precision.from, To: &precision.to, Limit: 1, Offset: 1}} {
				entries, total, err := s.ListAuditLogs(filter)
				if err != nil {
					t.Fatal(err)
				}
				if filter.From != nil && filter.To != nil {
					if total != 2 || len(entries) != 1 {
						t.Fatalf("fractional pagination/count: total=%d entries=%+v", total, entries)
					}
					if entries[0].ID != "inside" {
						t.Fatalf("offset applied before exact filtering: %+v", entries)
					}
					continue
				}
				if total != 3 || len(entries) != 3 {
					t.Fatalf("fractional boundary included adjacent instant: total=%d entries=%+v", total, entries)
				}
				for _, entry := range entries {
					if entry.ID == "offset-equivalent" {
						expected, err := auditInstant(precision.to)
						if err != nil || !entry.CreatedAt.Equal(expected) {
							t.Fatalf("offset timestamp lost during scan: got %s want %s err=%v", entry.CreatedAt, expected, err)
						}
					}
					if filter.From != nil && entry.ID == "older" || filter.To != nil && entry.ID == "newer" {
						t.Fatalf("fractional timestamp crossed filter: %+v", entry)
					}
				}
			}
		})
	}
}

func TestAuditExactTimeFilterRejectsMalformedTimestamps(t *testing.T) {
	s := auditGuardStore(t)
	auditGuardExec(t, s, "INSERT INTO audit_logs(id,action,created_at) VALUES('valid','user.login','2026-11-03 22:00:00'),('invalid','user.login','not-a-time')")
	valid, invalid := "2026-11-03T00:00:00Z", "not-a-time"
	for _, filter := range []model.AuditFilter{{From: &valid}, {From: &invalid}, {To: &invalid}} {
		entries, total, err := s.ListAuditLogs(filter)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if filter.From == &valid {
			want = 1
		}
		if total != want || len(entries) != want {
			t.Fatalf("malformed timestamp accepted: total=%d entries=%+v", total, entries)
		}
	}
	// NULL and malformed stored values must produce SQL NULL, never a fabricated
	// equality that could satisfy an inclusive filter.
	for _, input := range []any{nil, "not-a-time", int64(1)} {
		var compared any
		if err := s.db.QueryRow("SELECT veyport_audit_time_compare(?,?)", input, valid).Scan(&compared); err != nil || compared != nil {
			t.Fatalf("invalid stored timestamp compared as an instant: %v %v", compared, err)
		}
	}
	var compared any
	if err := s.db.QueryRow("SELECT veyport_audit_time_compare(?,?)", valid, invalid).Scan(&compared); err != nil || compared != nil {
		t.Fatalf("invalid bound compared as an instant: %v %v", compared, err)
	}
}
