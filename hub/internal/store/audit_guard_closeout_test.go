package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

func auditGuardStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func auditGuardExec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}
func auditGuardCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action=?", model.AuditAuditRetentionUpdated).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAuditedSettingsDirectAuthorityAndPolicyFailures(t *testing.T) {
	for _, failure := range []string{"validation", "enrolled", "policy-state-read", "policy-history-read", "user-read", "dormant", "missing-api-token"} {
		t.Run(failure, func(t *testing.T) {
			s := auditGuardStore(t)
			auditGuardExec(t, s, "INSERT INTO users(id,username,email,password_hash,role) VALUES('actor','actor','actor@test','h','admin')")
			actor := AccountManagementActor{UserID: "actor"}
			before := s.GetAuditSettings()
			after := before
			after.RetentionDays++
			restore := ""
			switch failure {
			case "validation":
				after.RetentionDays = 0
			case "enrolled":
				auditGuardExec(t, s, "INSERT INTO audit_policy_versions(version,payload,digest) SELECT 2,payload,? FROM audit_policy_versions WHERE version=1", SecurityDigest([]byte(initialStandardPolicy)))
			case "policy-state-read":
				auditGuardExec(t, s, "ALTER TABLE audit_policy_state RENAME TO saved_policy_state")
				restore = "ALTER TABLE saved_policy_state RENAME TO audit_policy_state"
			case "policy-history-read":
				auditGuardExec(t, s, "ALTER TABLE audit_policy_versions RENAME TO saved_policy_versions")
				restore = "ALTER TABLE saved_policy_versions RENAME TO audit_policy_versions"
			case "user-read":
				auditGuardExec(t, s, "ALTER TABLE users RENAME COLUMN security_revision TO unavailable_revision")
				restore = "ALTER TABLE users RENAME COLUMN unavailable_revision TO security_revision"
			case "dormant":
				auditGuardExec(t, s, "UPDATE users SET created_at='2000-01-01 00:00:00' WHERE id='actor'")
			case "missing-api-token":
				actor.APITokenHash = "missing-token"
			}
			if err := s.UpdateAuditSettingsAudited(after, time.Now().UTC(), model.AuditEntry{}, actor); err == nil {
				t.Fatal("rejected authority or policy accepted")
			}
			if restore != "" {
				auditGuardExec(t, s, restore)
			}
			if s.GetAuditSettings() != before || auditGuardCount(t, s) != 0 {
				t.Fatal("rejection changed settings or recorded success")
			}
			h, err := s.GetAuditHealth()
			if err != nil || h.Degraded || h.FailureCount != 0 {
				t.Fatalf("guard rejection changed audit health: %+v %v", h, err)
			}
		})
	}
}

func activationGuardFixture(t *testing.T) (*Store, model.SecurityChange, model.SecurityChangePayload, time.Time) {
	t.Helper()
	s := auditGuardStore(t)
	now := time.Now().UTC()
	settings := s.GetAuditSettings()
	settings.RetentionDays++
	p := model.SecurityChangePayload{Kind: "audit-settings", AuditSettings: &settings}
	raw, err := json.Marshal(struct {
		Change model.SecurityChangePayload `json:"change"`
	}{p})
	if err != nil {
		t.Fatal(err)
	}
	c := model.SecurityChange{ID: "change", Revision: 1, ExpectedVersion: 1, Digest: SecurityDigest(raw), ApprovedBytes: raw, RequesterID: "requester", RequesterPersonID: "user:requester", ApplierID: "applier", ApplierPersonID: "user:applier"}
	for _, id := range []string{"requester", "applier", "approver1", "approver2"} {
		auditGuardExec(t, s, "INSERT INTO users(id,username,email,password_hash,role,totp_enabled,totp_secret) VALUES(?,?,?,'h','admin',1,'secret')", id, id, id+"@test")
		role := "security-officer"
		if id == "approver1" || id == "approver2" {
			role = "security-approver"
		}
		auditGuardExec(t, s, "INSERT INTO user_roles(user_id,role) VALUES(?,?)", id, role)
	}
	var rev int
	if err := s.db.QueryRow("SELECT security_revision FROM users WHERE id='requester'").Scan(&rev); err != nil {
		t.Fatal(err)
	}
	c.RequesterGeneration = rev
	c.ApplierRevision = rev
	auditGuardExec(t, s, `INSERT INTO security_changes(id,revision,requester_id,requester_person,requester_generation,expected_version,digest,reason,payload,state,created_at,expires_at,commit_ref) VALUES(?,?,?,?,?,?,?,'test',?,'applying',?,?,'external-commit')`, c.ID, c.Revision, c.RequesterID, c.RequesterPersonID, rev, c.ExpectedVersion, c.Digest, raw, now.Unix(), now.Add(time.Hour).Unix())
	for _, id := range []string{"approver1", "approver2"} {
		auditGuardExec(t, s, "INSERT INTO security_approvals(request_id,revision,digest,user_id,person_id,proof_sha256,token_generation,approved_at) VALUES(?,1,?,?,?,'proof',?,?)", c.ID, c.Digest, id, "user:"+id, rev, now.Unix())
	}
	auditGuardExec(t, s, "INSERT INTO audit_policy_versions(version,payload,digest,request_id) VALUES(2,?,?,?)", initialStandardPolicy, SecurityDigest([]byte(initialStandardPolicy)), c.ID)
	auditGuardExec(t, s, "UPDATE audit_policy_state SET state='applying',pending_version=2,pending_change=? WHERE id=1", c.ID)
	return s, c, p, now
}

func TestGovernedAuditSettingsActivationGuardsPreserveSettingsAndAudit(t *testing.T) {
	for _, failure := range []string{"missing-applying", "wrong-id", "wrong-version", "history-read", "unexpected-active", "missing-commit", "applier", "requester", "late-principal", "final-principal", "nil-payload", "policy-write"} {
		t.Run(failure, func(t *testing.T) {
			s, c, p, now := activationGuardFixture(t)
			before := s.GetAuditSettings()
			clockCalls := 0
			clock := func() time.Time {
				clockCalls++
				if failure == "late-principal" && clockCalls >= 6 || failure == "final-principal" && clockCalls >= 7 {
					return now.AddDate(2, 0, 0)
				}
				return now
			}
			switch failure {
			case "missing-applying":
				auditGuardExec(t, s, "UPDATE audit_policy_state SET state='recovery_required'")
			case "wrong-id":
				c.ID = "other"
			case "wrong-version":
				c.ExpectedVersion = 5
			case "history-read":
				auditGuardExec(t, s, "UPDATE audit_policy_versions SET digest='corrupt' WHERE version=2")
			case "unexpected-active":
				c.ExpectedVersion = 0
				auditGuardExec(t, s, "UPDATE audit_policy_state SET active_version=2,pending_version=1")
			case "missing-commit":
				auditGuardExec(t, s, "UPDATE security_changes SET commit_ref=''")
			case "applier":
				c.ApplierRevision++
			case "requester":
				c.RequesterGeneration++
			case "nil-payload":
				p.AuditSettings = nil
			case "policy-write":
				auditGuardExec(t, s, `CREATE TRIGGER reject_activation BEFORE UPDATE OF active_version ON audit_policy_state BEGIN SELECT RAISE(ABORT,'activation write fault'); END`)
			}
			err := s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
				_, err := s.activateSecurityChangeConn(ctx, conn, c, p, clock)
				return err
			})
			if err == nil {
				t.Fatal("invalid activation accepted")
			}
			if s.GetAuditSettings() != before || auditGuardCount(t, s) != 0 {
				t.Fatal("failed activation left settings or success audit")
			}
		})
	}
}

func TestGovernedAuditSettingsActivationReplayDoesNotDuplicate(t *testing.T) {
	s, c, p, now := activationGuardFixture(t)
	for attempt := 0; attempt < 2; attempt++ {
		appended := false
		err := s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
			var err error
			appended, err = s.activateSecurityChangeConn(ctx, conn, c, p, func() time.Time { return now })
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if appended != (attempt == 0) {
			t.Fatalf("attempt %d appended=%t", attempt, appended)
		}
	}
	if s.GetAuditSettings() != *p.AuditSettings || auditGuardCount(t, s) != 1 {
		t.Fatal("replay duplicated or lost committed settings audit")
	}
}

func TestAuditedSettingsAppendFailureRollsBackAndReportsPersistenceFailure(t *testing.T) {
	s := auditGuardStore(t)
	auditGuardExec(t, s, "INSERT INTO users(id,username,email,password_hash,role) VALUES('actor','actor','actor@test','h','admin')")
	before := s.GetAuditSettings()
	after := before
	after.RetentionDays++
	auditGuardExec(t, s, `CREATE TRIGGER reject_settings_append BEFORE INSERT ON audit_logs BEGIN SELECT RAISE(ABORT,'audited settings append fault'); END`)
	err := s.UpdateAuditSettingsAudited(after, time.Now().UTC(), model.AuditEntry{}, AccountManagementActor{UserID: "actor"})
	var persistence *auditSettingsPersistenceError
	if !errors.As(err, &persistence) || errors.Unwrap(err) == nil {
		t.Fatalf("append error lost persistence cause: %v", err)
	}
	if s.GetAuditSettings() != before || auditGuardCount(t, s) != 0 {
		t.Fatal("failed append left settings or success audit")
	}
	h, healthErr := s.GetAuditHealth()
	if healthErr != nil || !h.Degraded || h.FailureCount != 1 {
		t.Fatalf("append failure not visible: %+v %v", h, healthErr)
	}
}
