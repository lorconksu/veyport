package authorization

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

// ConfigureExecutionPolicy installs one immutable local continuity binding for
// all services sharing this store, including final SSH and web terminal guards.
// Full startup/reconciliation additionally authenticates the external anchor.
func (s *Service) ConfigureExecutionPolicy(cfg TransitionConfig) (err error) {
	defer func() { s.policyConfigurationErr = err }()
	if cfg.InstallationID == "" && cfg.EnrollmentPath == "" {
		return nil // Never-configured Standard remains standalone.
	}
	if !auditrecord.ValidID(cfg.InstallationID) || cfg.EnrollmentPath == "" {
		return ErrRecovery
	}
	local := TransitionConfig{InstallationID: cfg.InstallationID, EnrollmentPath: filepath.Clean(cfg.EnrollmentPath)}
	key := local.InstallationID + "\x00" + local.EnrollmentPath
	return s.Store.InstallExecutionPolicyValidator(key, func(reader *store.Store, state model.PolicyState) error {
		validator := &Service{Store: reader}
		return validator.validateLocalExecutionPolicy(state, local)
	})
}

// validateApprovedPolicy also checks unchanged-policy role/person/settings
// revisions against their predecessor, so an advanced candidate marker cannot
// conceal a rewritten previous scope. No external service is consulted here.
func (s *Service) validateApprovedPolicy(policy model.PolicyVersion, applying bool) error {
	for policy.Version > 1 {
		change, err := s.Store.GetSecurityChange(policy.RequestID)
		if err != nil || change.ExpectedVersion+1 != policy.Version || Digest(change.ApprovedBytes) != change.Digest || (change.State != "applied" && !(applying && change.State == "applying")) {
			return ErrRecovery
		}
		var approved struct {
			Reason          string                      `json:"reason"`
			ExpectedVersion uint64                      `json:"expected_version"`
			Change          model.SecurityChangePayload `json:"change"`
		}
		if auditrecord.Decode(change.ApprovedBytes, &approved, 64*1024) != nil || approved.ExpectedVersion != change.ExpectedVersion || approved.Reason != change.Reason {
			return ErrRecovery
		}
		payload := approved.Change
		if validatePayload(payload) != nil {
			return ErrRecovery
		}
		if payload.Policy != nil {
			raw, err := json.Marshal(payload.Policy)
			if err != nil || Digest(raw) != policy.SHA256 {
				return ErrRecovery
			}
			return nil
		}
		previous, err := s.Store.GetPolicyVersion(change.ExpectedVersion)
		if err != nil || previous.SHA256 != policy.SHA256 {
			return ErrRecovery
		}
		policy, applying = previous, false
	}
	if policy.Version != 1 || policy.RequestID != "" {
		return ErrRecovery
	}
	// ValidateExecutionPolicy's unconfigured fallback checks the exact migration
	// record. Use the same known initial fields and hash for configured bootstrap.
	raw, err := json.Marshal(model.AuditPolicy{Profile: "standard", Actors: []string{}, Nodes: []string{}, RuntimeSeconds: 3600, RetentionHours: 24, TrustKeyIDs: []string{}})
	if err != nil || policy.SHA256 != Digest(raw) {
		return ErrRecovery
	}
	return nil
}

func (s *Service) validateLocalExecutionPolicy(state model.PolicyState, cfg TransitionConfig) error {
	marker, markerErr := readMarker(cfg.EnrollmentPath)
	if state.Pending == nil {
		if state.PendingChange != "" || state.Previous != nil {
			return ErrRecovery
		}
		switch state.State {
		case "standard":
			if state.Active.Policy.Profile != "standard" {
				return ErrRecovery
			}
		case "enhanced":
			if state.Active.Policy.Profile != "enhanced" {
				return ErrRecovery
			}
		case "setup_pending":
			if state.Active.Version != 1 || state.Active.RequestID != "" || state.Active.Policy.Profile != "standard" {
				return ErrRecovery
			}
		case "recovery_required":
			// The caller returns an explicit recovery denial after this check.
		default:
			return ErrRecovery
		}
		if err := s.validateApprovedPolicy(state.Active, false); err != nil {
			return err
		}
		if state.Active.Version == 1 && errors.Is(markerErr, os.ErrNotExist) {
			enrolled, err := s.Store.GovernanceEnrolled()
			if err == nil && !enrolled {
				return nil
			}
			return ErrRecovery
		}
		if markerErr != nil || marker.InstallationID != cfg.InstallationID || marker.Version != state.Active.Version || marker.SHA256 != state.Active.SHA256 {
			return ErrRecovery
		}
		return nil
	}
	if (state.State != "applying" && state.State != "recovery_required") || state.Previous == nil || state.PendingChange == "" || state.Pending.RequestID != state.PendingChange || state.Pending.Version != state.Previous.Version+1 || (state.Active.Version != state.Previous.Version && state.Active.Version != state.Pending.Version) {
		return ErrRecovery
	}
	if err := s.validateApprovedPolicy(*state.Previous, false); err != nil {
		return err
	}
	if err := s.validateApprovedPolicy(*state.Pending, true); err != nil {
		return err
	}
	change, err := s.Store.GetSecurityChange(state.PendingChange)
	if err != nil || change.State != "applying" || change.ExpectedVersion != state.Previous.Version || change.ExpectedVersion+1 != state.Pending.Version {
		return ErrRecovery
	}
	activated := state.Active.Version == state.Pending.Version
	if markerErr != nil {
		payload, err := DecodeChange(change.Payload)
		if !activated && errors.Is(markerErr, os.ErrNotExist) && err == nil && payload.Kind == "bootstrap" && state.Previous.Version == 1 {
			return nil
		}
		return ErrRecovery
	}
	if marker.InstallationID != cfg.InstallationID {
		return ErrRecovery
	}
	if marker.Version == state.Pending.Version && marker.SHA256 == state.Pending.SHA256 {
		return nil
	}
	if !activated && marker.Version == state.Previous.Version && marker.SHA256 == state.Previous.SHA256 {
		return nil
	}
	return ErrRecovery
}
