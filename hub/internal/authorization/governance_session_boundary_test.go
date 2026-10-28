package authorization

import (
	"context"
	"database/sql/driver"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"modernc.org/sqlite"
)

func delayGovernancePrincipalRead(t *testing.T, st *store.Store, delay time.Duration) <-chan struct{} {
	t.Helper()
	name := "governance_principal_delay_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	var once sync.Once
	called := make(chan struct{})
	if err := sqlite.RegisterScalarFunction(name, 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		once.Do(func() {
			close(called)
			time.Sleep(delay)
		})
		return args[0], nil
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := st.DB().Query("PRAGMA table_info(users)")
	if err != nil {
		t.Fatal(err)
	}
	var columns []string
	for rows.Next() {
		var cid int
		var column, kind string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &column, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		expression := `"` + column + `"`
		if column == "security_revision" {
			expression = name + `("security_revision") AS "security_revision"`
		}
		columns = append(columns, expression)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"ALTER TABLE users RENAME TO delayed_governance_users",
		"CREATE VIEW users AS SELECT " + strings.Join(columns, ",") + " FROM delayed_governance_users",
	} {
		if _, err := st.DB().Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	// Scalar functions are installed on newly opened SQLite connections.
	// Drop idle fixture connections so the governance transaction receives one.
	st.DB().SetMaxIdleConns(0)
	return called
}

func TestGovernanceRequiresLiveActorSessionAtMutation(t *testing.T) {
	for _, action := range []string{ActionRequest, ActionApprove, ActionApply} {
		for _, mutation := range []string{"ended", "absolute", "idle", "missing", "owner", "malformed", "generation"} {
			t.Run(action+"/"+mutation, func(t *testing.T) {
				s, f := fixtureGovernance(t)
				user := "requester"
				if action == ActionApprove {
					user = "approver-one"
				}
				if action == ActionApply {
					approveFixture(t, s, f, "approver-one")
					approveFixture(t, s, f, "approver-two")
				}
				sid := "session-" + user
				proof, err := s.Store.IssueStepup(user, sid, action, f.change.Digest, f.now)
				if err != nil {
					t.Fatal(err)
				}
				query := ""
				switch mutation {
				case "ended":
					_, err = s.Store.EndSession(sid, model.SessionEndLogout, nil, f.now)
				case "absolute":
					query = "UPDATE sessions SET expires_at='2000-01-01 00:00:00' WHERE id=?"
				case "idle":
					query = "UPDATE sessions SET last_seen_at='2000-01-01 00:00:00' WHERE id=?"
				case "missing":
					query = "DELETE FROM sessions WHERE id=?"
				case "owner":
					query = "UPDATE sessions SET user_id='other-admin' WHERE id=?"
				case "malformed":
					query = "UPDATE sessions SET expires_at='malformed' WHERE id=?"
				case "generation":
					_, err = s.Store.IncrementTokenGeneration(user)
				}
				if query != "" {
					_, err = s.Store.DB().Exec(query, sid)
				}
				if err != nil {
					t.Fatal(err)
				}
				switch action {
				case ActionRequest:
					c := f.change
					c.ID = "refused-request"
					err = s.Store.CreateSecurityChange(c, nil, sid, proof, f.now)
				case ActionApprove:
					_, err = s.Approve(f.change.ID, user, sid, proof)
				case ActionApply:
					err = s.Store.ClaimSecurityApplier(f.change, user, f.change.RequesterPersonID, 0, sid, proof, f.now)
				}
				if err == nil {
					t.Fatal("revoked governance authority committed")
				}
				var consumed bool
				if err := s.Store.DB().QueryRow("SELECT consumed_at IS NOT NULL FROM stepup_proofs WHERE hash=?", store.SecurityDigest([]byte(proof))).Scan(&consumed); err != nil || consumed {
					t.Fatalf("refusal consumed proof: %t %v", consumed, err)
				}
				var count int
				if err := s.Store.DB().QueryRow("SELECT COUNT(*) FROM security_changes WHERE id='refused-request' OR (id=? AND applier_id!='')", f.change.ID).Scan(&count); err != nil || count != 0 {
					t.Fatalf("refusal mutated request: %d %v", count, err)
				}
			})
		}
	}
}

func TestGovernancePrincipalReadsUseOneAdvancingTransactionClock(t *testing.T) {
	for _, action := range []string{ActionRequest, ActionApprove, ActionApply} {
		t.Run(action, func(t *testing.T) {
			s, f := fixtureGovernance(t, filepath.Join(t.TempDir(), "principal-clock.db"))
			user, person := "requester", "person-one"
			if action == ActionApprove {
				user, person = "approver-one", "person-two"
			}
			if action == ActionApply {
				approveFixture(t, s, f, "approver-one")
				approveFixture(t, s, f, "approver-two")
			}
			sid := "session-" + user
			if _, err := s.Store.DB().Exec("UPDATE sessions SET expires_at=? WHERE id=?", f.now.Add(time.Second).Format("2006-01-02 15:04:05"), sid); err != nil {
				t.Fatal(err)
			}
			proof, err := s.Store.IssueStepup(user, sid, action, f.change.Digest, f.now)
			if err != nil {
				t.Fatal(err)
			}
			delayed := delayGovernancePrincipalRead(t, s.Store, 1200*time.Millisecond)
			switch action {
			case ActionRequest:
				change := f.change
				change.ID = "principal-delay-request"
				err = s.Store.CreateSecurityChange(change, nil, sid, proof, f.now)
			case ActionApprove:
				err = s.Store.AddSecurityApproval(f.change, model.SecurityApproval{UserID: user, PersonID: person, TokenGeneration: 0}, sid, proof, f.now)
			case ActionApply:
				err = s.Store.ClaimSecurityApplier(f.change, user, person, 0, sid, proof, f.now)
			}
			if err == nil {
				t.Fatal("governance mutation accepted session authority that expired during principal reads")
			}
			select {
			case <-delayed:
			default:
				t.Fatalf("principal-read delay fixture was not exercised; operation error: %v", err)
			}
			var consumed bool
			if err := s.Store.DB().QueryRow("SELECT consumed_at IS NOT NULL FROM stepup_proofs WHERE hash=?", store.SecurityDigest([]byte(proof))).Scan(&consumed); err != nil || consumed {
				t.Fatalf("expired authority consumed proof: consumed=%t err=%v", consumed, err)
			}
		})
	}
}

func delayGovernanceMutation(t *testing.T, st *store.Store, trigger string) <-chan struct{} {
	t.Helper()
	name := "governance_mutation_delay_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	var once sync.Once
	called := make(chan struct{})
	if err := sqlite.RegisterScalarFunction(name, 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		once.Do(func() {
			close(called)
			time.Sleep(1200 * time.Millisecond)
		})
		return args[0], nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(strings.ReplaceAll(trigger, "$DELAY", name)); err != nil {
		t.Fatal(err)
	}
	st.DB().SetMaxIdleConns(0)
	return called
}

func TestGovernanceSessionExpiryAfterProofConsumptionRollsBackMutation(t *testing.T) {
	for _, action := range []string{ActionRequest, ActionApprove, ActionApply} {
		t.Run(action, func(t *testing.T) {
			s, f := fixtureGovernance(t, filepath.Join(t.TempDir(), "final-session-clock.db"))
			user, person := "requester", "person-one"
			if action == ActionApprove {
				user, person = "approver-one", "person-two"
			}
			if action == ActionApply {
				approveFixture(t, s, f, "approver-one")
				approveFixture(t, s, f, "approver-two")
			}
			sid := "session-" + user
			if _, err := s.Store.DB().Exec("UPDATE sessions SET expires_at=? WHERE id=?", f.now.Add(time.Second).Format("2006-01-02 15:04:05"), sid); err != nil {
				t.Fatal(err)
			}
			proof, err := s.Store.IssueStepup(user, sid, action, f.change.Digest, f.now)
			if err != nil {
				t.Fatal(err)
			}
			var trigger string
			switch action {
			case ActionRequest:
				trigger = `CREATE TRIGGER final_request_delay AFTER INSERT ON security_changes WHEN NEW.id='final-delay-request' BEGIN SELECT $DELAY(NEW.id); END`
			case ActionApprove:
				trigger = `CREATE TRIGGER final_approval_delay AFTER INSERT ON security_approvals WHEN NEW.user_id='approver-one' BEGIN SELECT $DELAY(NEW.user_id); END`
			case ActionApply:
				trigger = `CREATE TRIGGER final_claim_delay AFTER UPDATE OF applier_id ON security_changes WHEN NEW.applier_id='requester' BEGIN SELECT $DELAY(NEW.id); END`
			}
			delayed := delayGovernanceMutation(t, s.Store, trigger)
			switch action {
			case ActionRequest:
				change := f.change
				change.ID = "final-delay-request"
				err = s.Store.CreateSecurityChange(change, nil, sid, proof, f.now)
			case ActionApprove:
				err = s.Store.AddSecurityApproval(f.change, model.SecurityApproval{UserID: user, PersonID: person, TokenGeneration: 0}, sid, proof, f.now)
			case ActionApply:
				err = s.Store.ClaimSecurityApplier(f.change, user, person, 0, sid, proof, f.now)
			}
			if err == nil {
				t.Fatal("governance mutation committed after its session expired")
			}
			select {
			case <-delayed:
			default:
				t.Fatalf("final-mutation delay fixture was not exercised: %v", err)
			}
			var consumed bool
			if err := s.Store.DB().QueryRow("SELECT consumed_at IS NOT NULL FROM stepup_proofs WHERE hash=?", store.SecurityDigest([]byte(proof))).Scan(&consumed); err != nil || consumed {
				t.Fatalf("expired final authority consumed proof: consumed=%t err=%v", consumed, err)
			}
			mutationQuery := "SELECT COUNT(*) FROM security_changes WHERE id='final-delay-request'"
			args := []any{}
			if action == ActionApprove {
				mutationQuery = "SELECT COUNT(*) FROM security_approvals WHERE request_id=? AND user_id='approver-one'"
				args = append(args, f.change.ID)
			} else if action == ActionApply {
				mutationQuery = "SELECT COUNT(*) FROM security_changes WHERE id=? AND applier_id!=''"
				args = append(args, f.change.ID)
			}
			var mutations int
			if err := s.Store.DB().QueryRow(mutationQuery, args...).Scan(&mutations); err != nil || mutations != 0 {
				t.Fatalf("expired final authority left mutation: count=%d err=%v", mutations, err)
			}
		})
	}
}

func TestGovernanceChangeExpiryAfterFinalSessionReadRollsBackMutation(t *testing.T) {
	for _, action := range []string{ActionRequest, ActionApprove, ActionApply} {
		t.Run(action, func(t *testing.T) {
			s, f := fixtureGovernance(t, filepath.Join(t.TempDir(), "final-change-clock.db"))
			user, person := "requester", "person-one"
			if action == ActionApprove {
				user, person = "approver-one", "person-two"
			}
			if action == ActionApply {
				approveFixture(t, s, f, "approver-one")
				approveFixture(t, s, f, "approver-two")
			}
			expires := f.now.Add(time.Second)
			if action != ActionRequest {
				if _, err := s.Store.DB().Exec("UPDATE security_changes SET expires_at=? WHERE id=?", expires.Unix(), f.change.ID); err != nil {
					t.Fatal(err)
				}
			}
			sid := "session-" + user
			proof, err := s.Store.IssueStepup(user, sid, action, f.change.Digest, f.now)
			if err != nil {
				t.Fatal(err)
			}
			var trigger string
			switch action {
			case ActionRequest:
				trigger = `CREATE TRIGGER final_request_expiry_delay AFTER INSERT ON security_changes WHEN NEW.id='final-expiry-request' BEGIN SELECT $DELAY(NEW.id); END`
			case ActionApprove:
				trigger = `CREATE TRIGGER final_approval_expiry_delay AFTER INSERT ON security_approvals WHEN NEW.user_id='approver-one' BEGIN SELECT $DELAY(NEW.user_id); END`
			case ActionApply:
				trigger = `CREATE TRIGGER final_claim_expiry_delay AFTER UPDATE OF applier_id ON security_changes WHEN NEW.applier_id='requester' BEGIN SELECT $DELAY(NEW.id); END`
			}
			delayed := delayGovernanceMutation(t, s.Store, trigger)
			switch action {
			case ActionRequest:
				change := f.change
				change.ID, change.ExpiresAt = "final-expiry-request", expires
				err = s.Store.CreateSecurityChange(change, nil, sid, proof, f.now)
			case ActionApprove:
				err = s.Store.AddSecurityApproval(f.change, model.SecurityApproval{UserID: user, PersonID: person, TokenGeneration: 0}, sid, proof, f.now)
			case ActionApply:
				err = s.Store.ClaimSecurityApplier(f.change, user, person, 0, sid, proof, f.now)
			}
			if err == nil {
				t.Fatal("governance mutation committed after the change expired")
			}
			select {
			case <-delayed:
			default:
				t.Fatalf("final change-expiry delay fixture was not exercised: %v", err)
			}
			var consumed bool
			if err := s.Store.DB().QueryRow("SELECT consumed_at IS NOT NULL FROM stepup_proofs WHERE hash=?", store.SecurityDigest([]byte(proof))).Scan(&consumed); err != nil || consumed {
				t.Fatalf("expired change consumed proof: consumed=%t err=%v", consumed, err)
			}
		})
	}
}

func TestGovernancePolicyReadFailureFailsClosed(t *testing.T) {
	s, f := fixtureGovernance(t, filepath.Join(t.TempDir(), "policy-read-failure.db"))
	proof, err := s.Store.IssueStepup("approver-one", "session-approver-one", ActionApprove, f.change.Digest, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"ALTER TABLE _config RENAME TO unavailable_governance_config",
		"CREATE VIEW _config AS SELECT key,value FROM missing_governance_config",
	} {
		if _, err := s.Store.DB().Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Store.AddSecurityApproval(f.change, model.SecurityApproval{UserID: "approver-one", PersonID: "person-two", TokenGeneration: 0}, "session-approver-one", proof, f.now); err == nil {
		t.Fatal("unavailable governance policy silently authorized an approval")
	}
	var consumed bool
	if err := s.Store.DB().QueryRow("SELECT consumed_at IS NOT NULL FROM stepup_proofs WHERE hash=?", store.SecurityDigest([]byte(proof))).Scan(&consumed); err != nil || consumed {
		t.Fatalf("policy read failure consumed proof: consumed=%t err=%v", consumed, err)
	}
	var approvals int
	if err := s.Store.DB().QueryRow("SELECT COUNT(*) FROM security_approvals WHERE request_id=? AND user_id='approver-one'", f.change.ID).Scan(&approvals); err != nil || approvals != 0 {
		t.Fatalf("policy read failure committed approval: approvals=%d err=%v", approvals, err)
	}
}

func TestCapabilityEvaluationPolicyReadFailureFailsClosed(t *testing.T) {
	s, _ := fixtureGovernance(t, filepath.Join(t.TempDir(), "capability-policy-failure.db"))
	for _, query := range []string{
		"ALTER TABLE _config RENAME TO unavailable_capability_config",
		"CREATE VIEW _config AS SELECT key,value FROM missing_capability_config",
	} {
		if _, err := s.Store.DB().Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if effective, err := s.Effective("requester"); err == nil || len(effective.Capabilities) != 0 {
		t.Fatalf("unavailable policy store granted capabilities: effective=%#v err=%v", effective, err)
	}
}

func TestGovernanceDormancyIsCheckedAfterAuthorityReads(t *testing.T) {
	for _, action := range []string{ActionRequest, ActionApprove, ActionApply} {
		t.Run(action, func(t *testing.T) {
			s, f := fixtureGovernance(t, filepath.Join(t.TempDir(), "dormancy-clock.db"))
			user, person := "requester", "person-one"
			if action == ActionApprove {
				user, person = "approver-one", "person-two"
			}
			if action == ActionApply {
				approveFixture(t, s, f, "approver-one")
				approveFixture(t, s, f, "approver-two")
			}
			if err := s.Store.SetConfig("account.dormant_days", "1"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Store.DB().Exec("UPDATE users SET dormancy_exempt=0,created_at=?,last_activity_at=NULL,reactivated_at=NULL WHERE id=?", f.now.Add(-24*time.Hour).Format("2006-01-02 15:04:05"), user); err != nil {
				t.Fatal(err)
			}
			sid := "session-" + user
			proof, err := s.Store.IssueStepup(user, sid, action, f.change.Digest, f.now)
			if err != nil {
				t.Fatal(err)
			}
			delayed := delayGovernancePrincipalRead(t, s.Store, 1200*time.Millisecond)
			switch action {
			case ActionRequest:
				change := f.change
				change.ID = "dormant-delay-request"
				err = s.Store.CreateSecurityChange(change, nil, sid, proof, f.now)
			case ActionApprove:
				err = s.Store.AddSecurityApproval(f.change, model.SecurityApproval{UserID: user, PersonID: person, TokenGeneration: 0}, sid, proof, f.now)
			case ActionApply:
				err = s.Store.ClaimSecurityApplier(f.change, user, person, 0, sid, proof, f.now)
			}
			if err == nil {
				t.Fatal("principal that became dormant during authority reads committed governance mutation")
			}
			select {
			case <-delayed:
			default:
				t.Fatalf("dormancy delay fixture was not exercised: %v", err)
			}
			var consumed bool
			if err := s.Store.DB().QueryRow("SELECT consumed_at IS NOT NULL FROM stepup_proofs WHERE hash=?", store.SecurityDigest([]byte(proof))).Scan(&consumed); err != nil || consumed {
				t.Fatalf("dormant authority consumed proof: consumed=%t err=%v", consumed, err)
			}
		})
	}
}

func TestBeginApplyExpiryAdvancesThroughAuthorityReads(t *testing.T) {
	s, f := fixtureGovernance(t, filepath.Join(t.TempDir(), "begin-apply-clock.db"))
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	proof, err := s.Store.IssueStepup("requester", "session-requester", ActionApply, f.change.Digest, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.ClaimSecurityApplier(f.change, "requester", "person-one", 0, "session-requester", proof, f.now); err != nil {
		t.Fatal(err)
	}
	f.change.ApplierID, f.change.ApplierPersonID, f.change.ApplierRevision = "requester", "person-one", 0
	if _, err := s.Store.DB().Exec("UPDATE security_changes SET expires_at=? WHERE id=?", f.now.Unix()+1, f.change.ID); err != nil {
		t.Fatal(err)
	}
	delayed := delayGovernancePrincipalRead(t, s.Store, 1200*time.Millisecond)
	if err := s.Store.BeginSecurityApply(f.change, model.AuditPolicy{Profile: "enhanced"}, "intent", f.now); err == nil {
		t.Fatal("change that expired during begin-apply authority reads entered applying")
	}
	select {
	case <-delayed:
	default:
		t.Fatal("begin-apply authority delay fixture was not exercised")
	}
	var state, pending string
	if err := s.Store.DB().QueryRow("SELECT state,pending_change FROM audit_policy_state WHERE id=1").Scan(&state, &pending); err != nil {
		t.Fatal(err)
	}
	if state == "applying" || pending != "" {
		t.Fatalf("expired begin-apply left partial state: state=%q pending=%q", state, pending)
	}
}

func TestBeginApplyExpiryAfterFinalWriteRollsBackTransition(t *testing.T) {
	s, f := fixtureGovernance(t, filepath.Join(t.TempDir(), "begin-apply-final-write.db"))
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	proof, err := s.Store.IssueStepup("requester", "session-requester", ActionApply, f.change.Digest, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.ClaimSecurityApplier(f.change, "requester", "person-one", 0, "session-requester", proof, f.now); err != nil {
		t.Fatal(err)
	}
	f.change.ApplierID, f.change.ApplierPersonID, f.change.ApplierRevision = "requester", "person-one", 0
	if _, err := s.Store.DB().Exec("UPDATE security_changes SET expires_at=? WHERE id=?", f.now.Unix()+1, f.change.ID); err != nil {
		t.Fatal(err)
	}
	delayed := delayGovernanceMutation(t, s.Store, `CREATE TRIGGER begin_apply_final_write_delay AFTER UPDATE OF state ON security_changes WHEN NEW.state='applying' BEGIN SELECT $DELAY(NEW.id); END`)
	if err := s.Store.BeginSecurityApply(f.change, model.AuditPolicy{Profile: "enhanced"}, "intent", f.now); err == nil {
		t.Fatal("change that expired during the final begin-apply write entered applying")
	}
	select {
	case <-delayed:
	default:
		t.Fatal("begin-apply final-write delay fixture was not exercised")
	}
	var state, pending string
	var pendingVersion any
	if err := s.Store.DB().QueryRow("SELECT state,pending_change,pending_version FROM audit_policy_state WHERE id=1").Scan(&state, &pending, &pendingVersion); err != nil {
		t.Fatal(err)
	}
	if state == "applying" || pending != "" || pendingVersion != nil {
		t.Fatalf("expired begin-apply left partial transition: state=%q pending=%q version=%v", state, pending, pendingVersion)
	}
	var versions int
	if err := s.Store.DB().QueryRow("SELECT COUNT(*) FROM audit_policy_versions WHERE request_id=?", f.change.ID).Scan(&versions); err != nil || versions != 0 {
		t.Fatalf("expired begin-apply left pending version: count=%d err=%v", versions, err)
	}
}

func TestGovernanceWriterWaitUsesFreshAuthorityClock(t *testing.T) {
	for _, action := range []string{ActionRequest, ActionApprove, ActionApply, "begin apply", "consume"} {
		for _, expiry := range []string{"proof", "session", "change", "revoked"} {
			if action == "begin apply" && expiry != "change" || action == "consume" && expiry == "change" {
				continue
			}
			t.Run(action+"/"+expiry, func(t *testing.T) {
				t.Parallel()
				path := filepath.Join(t.TempDir(), "hub.db")
				s, f := fixtureGovernance(t, path)
				user := "requester"
				if action == ActionApprove {
					user = "approver-one"
				}
				if action == ActionApply || action == "begin apply" {
					approveFixture(t, s, f, "approver-one")
					approveFixture(t, s, f, "approver-two")
				}
				sid := "session-" + user
				if action == "begin apply" {
					claim, err := s.Store.IssueStepup(user, sid, ActionApply, f.change.Digest, f.now)
					if err != nil {
						t.Fatal(err)
					}
					if err := s.Store.ClaimSecurityApplier(f.change, user, "person-one", 0, sid, claim, f.now); err != nil {
						t.Fatal(err)
					}
					f.change.ApplierID, f.change.ApplierPersonID, f.change.ApplierRevision = user, "person-one", 0
				}
				proof, err := s.Store.IssueStepup(user, sid, action, f.change.Digest, f.now)
				if err != nil {
					t.Fatal(err)
				}
				switch expiry {
				case "proof":
					_, err = s.Store.DB().Exec("UPDATE stepup_proofs SET expires_at=? WHERE hash=?", f.now.Unix()+1, store.SecurityDigest([]byte(proof)))
				case "session":
					_, err = s.Store.DB().Exec("UPDATE sessions SET expires_at=? WHERE id=?", f.now.Add(time.Second).Format("2006-01-02 15:04:05"), sid)
				case "change":
					_, err = s.Store.DB().Exec("UPDATE security_changes SET expires_at=? WHERE id=?", f.now.Unix()+1, f.change.ID)
					f.change.ExpiresAt = f.now.Add(time.Second)
				}
				if err != nil {
					t.Fatal(err)
				}
				locker, err := store.New(path)
				if err != nil {
					t.Fatal(err)
				}
				defer locker.Close()
				conn, err := locker.DB().Conn(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
					t.Fatal(err)
				}
				defer conn.ExecContext(context.Background(), "ROLLBACK")
				if expiry == "revoked" {
					if _, err := conn.ExecContext(context.Background(), "UPDATE sessions SET ended_at=? WHERE id=?", f.now.Format("2006-01-02 15:04:05"), sid); err != nil {
						t.Fatal(err)
					}
				}
				done := make(chan error, 1)
				go func() {
					switch action {
					case ActionRequest:
						c := f.change
						c.ID = "late-request"
						done <- s.Store.CreateSecurityChange(c, nil, sid, proof, f.now)
					case ActionApprove:
						done <- s.Store.AddSecurityApproval(f.change, model.SecurityApproval{UserID: user, PersonID: "person-two", TokenGeneration: 0}, sid, proof, f.now)
					case ActionApply:
						done <- s.Store.ClaimSecurityApplier(f.change, user, "person-one", 0, sid, proof, f.now)
					case "consume":
						done <- s.Store.ConsumeStepup(proof, user, sid, action, f.change.Digest, f.now)
					case "begin apply":
						done <- s.Store.BeginSecurityApply(f.change, model.AuditPolicy{Profile: "enhanced"}, "intent", f.now)
					}
				}()
				// Real writer contention, with a full second beyond the transaction's
				// initially live fake-clock deadline. The action cannot finish early.
				select {
				case err := <-done:
					t.Fatalf("writer did not wait: %v", err)
				case <-time.After(1200 * time.Millisecond):
				}
				if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("expired authority committed after writer wait")
					}
				case <-time.After(6 * time.Second):
					t.Fatal("write did not terminate")
				}
				var consumed bool
				if err := s.Store.DB().QueryRow("SELECT consumed_at IS NOT NULL FROM stepup_proofs WHERE hash=?", store.SecurityDigest([]byte(proof))).Scan(&consumed); err != nil || consumed {
					t.Fatalf("expired proof consumed: %v", err)
				}
			})
		}
	}
}
