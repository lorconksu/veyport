package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func governedAuditSettingsFixture(t *testing.T, standard bool) (*Service, authorizationFixture, model.AuditSettings, model.AuditSettings) {
	t.Helper()
	s, f := activatedFixture(t)
	if standard {
		policy := model.AuditPolicy{Profile: "standard", RuntimeSeconds: 3600, RetentionHours: 24}
		c, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "policy", Policy: &policy})
		if err != nil {
			t.Fatal(err)
		}
		f.change = c
		approveFixture(t, s, f, "approver-one")
		approveFixture(t, s, f, "approver-two")
		if err := applyFixture(t, s, f); err != nil {
			t.Fatal(err)
		}
	}
	before := s.Store.GetAuditSettings()
	after := before
	after.RetentionDays++
	after.ReviewReminderDays++
	after.PasswordHistoryCount++
	after.TemporaryPasswordTTLHours++
	after.Thresholds.LoginFailuresPerHour++
	after.Thresholds.RegistrationFailuresPerHour++
	after.Thresholds.PrivilegedActionsPerHour++
	c, err := protectedChange(t, s, model.SecurityChangePayload{Kind: "audit-settings", AuditSettings: &after})
	if err != nil {
		t.Fatal(err)
	}
	f.change = c
	return s, f, before, after
}

func auditSettingsEntries(t *testing.T, s *Service, id string) []model.AuditEntry {
	t.Helper()
	action := model.AuditAuditRetentionUpdated
	entries, _, err := s.Store.ListAuditLogs(model.AuditFilter{Action: &action, CorrelationID: &id})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func assertGovernedSettingsAudit(t *testing.T, s *Service, f authorizationFixture, before, after model.AuditSettings) {
	t.Helper()
	entries := auditSettingsEntries(t, s, f.change.ID)
	if len(entries) != 1 {
		t.Fatalf("settings activation requires one local audit record, got %d", len(entries))
	}
	e := entries[0]
	if e.UserID == nil || *e.UserID != "requester" || e.ActorType != model.AuditActorTypeUser || e.Outcome != model.AuditOutcomeSuccess || e.Detail == nil {
		t.Fatalf("settings audit lost applying actor or outcome: %+v", e)
	}
	var detail struct {
		Before model.AuditSettings `json:"before"`
		After  model.AuditSettings `json:"after"`
	}
	if err := json.Unmarshal([]byte(*e.Detail), &detail); err != nil || detail.Before != before || detail.After != after {
		t.Fatalf("settings audit lost full old/new settings: %+v %v", detail, err)
	}
}

func TestGovernedAuditSettingsPreserveIndependentApprovalEvidence(t *testing.T) {
	s, f, before, after := governedAuditSettingsFixture(t, false)
	initialEvents := len(f.evidence.records)
	for _, approver := range []string{"approver-one", "approver-two"} {
		if err := applyFixture(t, s, f); err == nil {
			t.Fatal("settings applied without two independent approvals")
		}
		if s.Store.GetAuditSettings() != before || len(auditSettingsEntries(t, s, f.change.ID)) != 0 || len(f.evidence.records) != initialEvents {
			t.Fatal("insufficient quorum changed settings or produced completion evidence")
		}
		approveFixture(t, s, f, approver)
	}
	if err := applyFixture(t, s, f); err != nil {
		t.Fatal(err)
	}
	assertGovernedSettingsAudit(t, s, f, before, after)
	for _, kind := range []string{auditrecord.PolicyIntent, auditrecord.PolicyCommit, auditrecord.PolicyAnchor, auditrecord.PolicyResult} {
		var envelope auditrecord.Envelope
		if err := json.Unmarshal(f.evidence.records[f.change.ID+"-"+kind], &envelope); err != nil {
			t.Fatal(err)
		}
		details := envelope.Details
		if envelope.Actor.UserID != "requester" || envelope.Actor.PersonID != "person-one" || details == nil || details.Requester == nil || details.Requester.UserID != "requester" || details.Reason != f.change.Reason || details.RequestSHA256 != f.change.Digest || len(details.Approvals) != 2 {
			t.Fatalf("external %s lost actor, reason, or independent approved request: %+v", kind, envelope)
		}
		people := map[string]bool{details.Requester.PersonID: true}
		for _, approval := range details.Approvals {
			if people[approval.PersonID] || approval.StepupProofSHA256 == "" {
				t.Fatalf("external %s lost distinct verified people or approval MFA evidence", kind)
			}
			people[approval.PersonID] = true
		}
		if kind != auditrecord.PolicyAnchor && !bytes.Equal(details.ApprovedChange, f.change.ApprovedBytes) {
			t.Fatalf("external %s changed exact approved settings bytes", kind)
		}
		var reference string
		if err := s.Store.DB().QueryRow("SELECT reference FROM security_evidence WHERE request_id=? AND event_type=?", f.change.ID, kind).Scan(&reference); err != nil || reference == "" {
			t.Fatalf("successful apply lost durable %s acknowledgment: %q %v", kind, reference, err)
		}
	}
}

func TestGovernedAuditSettingsObserversCanReenterPolicy(t *testing.T) {
	s, f, before, after := governedAuditSettingsFixture(t, false)
	approveFixture(t, s, f, "approver-one")
	approveFixture(t, s, f, "approver-two")
	if _, err := s.Store.DB().Exec("CREATE TRIGGER settings_observer_fault BEFORE INSERT ON audit_logs WHEN NEW.action='audit.retention_updated' BEGIN SELECT RAISE(ABORT,'settings audit failure'); END"); err != nil {
		t.Fatal(err)
	}
	callbacks := 0
	observe := func(model.AuditHealth) {
		_ = s.Store.WithInteractivePolicy(func() error {
			callbacks++
			return nil
		})
	}
	s.Store.SetAuditObservers(observe, observe)
	bounded := func(fn func() error) error {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- fn() }()
		select {
		case err := <-done:
			return err
		case <-time.After(2 * time.Second):
			t.Fatal("settings audit observer ran while the policy mutex was held")
			return nil
		}
	}
	proof, err := s.Store.IssueStepup("requester", "session-requester", ActionApply, f.change.Digest, s.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := bounded(func() error {
		_, err := s.Apply(context.Background(), f.change.ID, "requester", "session-requester", proof, f.config)
		return err
	}); err == nil || callbacks != 1 || s.Store.GetAuditSettings() != before {
		t.Fatalf("failed governed audit lost failure notification or changed settings: %v callbacks=%d", err, callbacks)
	}
	if _, err := s.Store.DB().Exec("DROP TRIGGER settings_observer_fault"); err != nil {
		t.Fatal(err)
	}
	if err := bounded(func() error {
		_, err := s.ReconcileChange(context.Background(), f.change.ID, f.config)
		return err
	}); err != nil || callbacks != 2 {
		t.Fatalf("reconciled governed audit lost recovery notification: %v callbacks=%d", err, callbacks)
	}
	assertGovernedSettingsAudit(t, s, f, before, after)
}

func TestGovernedAuditSettingsRequireAtomicLocalEvidence(t *testing.T) {
	for _, standard := range []bool{false, true} {
		profile := "enhanced"
		if standard {
			profile = "standard_after_enrollment"
		}
		t.Run(profile, func(t *testing.T) {
			for _, fault := range []struct {
				name, trigger, external string
				activated               bool
			}{
				{name: "intent_archive", external: auditrecord.PolicyIntent},
				{name: "intent_ack", trigger: "BEFORE UPDATE OF reference ON security_evidence WHEN NEW.event_type='policy.intent' AND NEW.reference!=''"},
				{name: "commit_archive", external: auditrecord.PolicyCommit},
				{name: "commit_ack", trigger: "BEFORE UPDATE OF reference ON security_evidence WHEN NEW.event_type='policy.commit' AND NEW.reference!=''"},
				{name: "anchor_archive", external: auditrecord.PolicyAnchor},
				{name: "anchor_ack", trigger: "BEFORE UPDATE OF reference ON security_evidence WHEN NEW.event_type='policy.anchor' AND NEW.reference!=''"},
				{name: "partial_config", trigger: "BEFORE INSERT ON _config WHEN NEW.key='auth.password_history_count'"},
				{name: "local_audit", trigger: "BEFORE INSERT ON audit_logs WHEN NEW.action='audit.retention_updated'"},
				{name: "active_version", trigger: "BEFORE UPDATE OF active_version ON audit_policy_state WHEN NEW.active_version!=OLD.active_version"},
				{name: "result_archive", external: auditrecord.PolicyResult, activated: true},
				{name: "result_ack", trigger: "BEFORE UPDATE OF reference ON security_evidence WHEN NEW.event_type='policy.result' AND NEW.reference!=''", activated: true},
				{name: "finish", trigger: "BEFORE UPDATE ON security_changes WHEN NEW.state='applied'", activated: true},
			} {
				t.Run(fault.name, func(t *testing.T) {
					s, f, before, after := governedAuditSettingsFixture(t, standard)
					initialState, err := s.Store.GetPolicyState()
					if err != nil {
						t.Fatal(err)
					}
					approveFixture(t, s, f, "approver-one")
					approveFixture(t, s, f, "approver-two")
					if fault.trigger != "" {
						if _, err := s.Store.DB().Exec("CREATE TRIGGER settings_fault " + fault.trigger + " BEGIN SELECT RAISE(ABORT,'settings durability fault'); END"); err != nil {
							t.Fatal(err)
						}
					}
					f.evidence.fail = fault.external
					if err := applyFixture(t, s, f); err == nil {
						t.Fatal("failed settings evidence write reported success")
					}
					want := before
					if fault.activated {
						want = after
						assertGovernedSettingsAudit(t, s, f, before, after)
					} else if entries := auditSettingsEntries(t, s, f.change.ID); len(entries) != 0 {
						t.Fatalf("failed activation left a success audit: %+v", entries)
					}
					if got := s.Store.GetAuditSettings(); got != want {
						t.Fatalf("failed activation left settings without required evidence: %+v, want %+v", got, want)
					}
					if fault.name == "local_audit" {
						health, err := s.Store.GetAuditHealth()
						if err != nil || !health.Degraded || health.FailureCount != 1 {
							t.Fatalf("failed governed audit append did not report degraded health: %+v %v", health, err)
						}
					}
					change, err := s.Store.GetSecurityChange(f.change.ID)
					if err != nil || change.State == "applied" || change.ResultRef != "" {
						t.Fatalf("incomplete evidence completed settings change: %+v %v", change, err)
					}
					state, err := s.Store.GetPolicyState()
					if err != nil {
						t.Fatal(err)
					}
					wantVersion := initialState.Active.Version
					if fault.activated {
						wantVersion++
					}
					if state.Active.Version != wantVersion {
						t.Fatalf("activation and settings did not share transaction: %+v", state)
					}
					if state.Pending != nil && !standard {
						if _, err := s.PolicyForExecution("requester", "node"); !errors.Is(err, ErrTransition) {
							t.Fatalf("incomplete governed settings reopened covered execution: %v", err)
						}
					}
					if err := s.Store.UpdateAuditSettings(after); !errors.Is(err, store.ErrProtectedChange) {
						t.Fatalf("enrolled governance allowed Standard settings bypass: %v", err)
					}
					frozen := map[string][]byte{}
					for id, raw := range f.evidence.records {
						frozen[id] = append([]byte(nil), raw...)
					}
					f.evidence.fail = ""
					if fault.trigger != "" {
						if _, err := s.Store.DB().Exec("DROP TRIGGER settings_fault"); err != nil {
							t.Fatal(err)
						}
					}
					if state.Pending != nil {
						_, err = s.ReconcileChange(context.Background(), f.change.ID, f.config)
					} else {
						err = applyFixture(t, s, f)
					}
					if err != nil {
						t.Fatalf("restored evidence could not reconcile exact approved settings: %v", err)
					}
					if got := s.Store.GetAuditSettings(); got != after {
						t.Fatalf("recovery lost approved settings: %+v", got)
					}
					assertGovernedSettingsAudit(t, s, f, before, after)
					for id, raw := range frozen {
						if !bytes.Equal(raw, f.evidence.records[id]) {
							t.Fatalf("recovery changed preserved evidence %s", id)
						}
					}
					if err := s.ValidateAnchor(context.Background(), f.config); err != nil {
						t.Fatal(err)
					}
					entries := auditSettingsEntries(t, s, f.change.ID)
					if _, err := s.ReconcileChange(context.Background(), f.change.ID, f.config); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(entries, auditSettingsEntries(t, s, f.change.ID)) {
						t.Fatal("completed reconciliation duplicated or changed settings audit")
					}
				})
			}
		})
	}
}
