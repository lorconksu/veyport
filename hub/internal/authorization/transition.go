package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

// Evidence is independent of local policy state. Implementations verify signed
// receipts, archive qualification and exact bytes before reporting confirmation.
type Evidence interface {
	Preserve(context.Context, []byte) (string, error)
	Anchor(context.Context, string) (PolicyAnchor, error)
	Ready(context.Context, model.AuditPolicy) error
	Qualify(context.Context, model.AuditPolicy) error
}
type PolicyAnchor struct {
	InstallationID string
	Version        uint64
	SHA256         string
	RequestID      string
	RequestSHA256  string
}
type TransitionConfig struct {
	Evidence       Evidence
	EnrollmentPath string
	InstallationID string
	ResolveSecret  func(string) (string, string, error)
	PrepareChange  func(model.SecurityChangePayload) (model.SecurityChangePayload, error)
}
type EnrollmentMarker struct {
	InstallationID string `json:"installation_id"`
	Version        uint64 `json:"version"`
	SHA256         string `json:"sha256"`
}

// The enrollment directory must already exist with private permissions. Deployment
// tooling owns directory creation and parent fsync before the hub can enroll.
func openEnrollmentRoot(path string) (*os.Root, error) {
	if path == "" {
		return nil, os.ErrNotExist
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrRecovery
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	f, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	info, err = f.Stat()
	f.Close()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		root.Close()
		return nil, ErrRecovery
	}
	return root, nil
}
func readMarker(path string) (EnrollmentMarker, error) {
	var m EnrollmentMarker
	root, err := openEnrollmentRoot(path)
	if err != nil {
		return m, err
	}
	defer root.Close()
	f, err := root.OpenFile(filepath.Base(path), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return m, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return m, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return m, ErrRecovery
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return m, err
	}
	if len(raw) > 4096 || json.Unmarshal(raw, &m) != nil || !auditrecord.ValidID(m.InstallationID) || m.Version == 0 || !auditrecord.ValidHash(m.SHA256) {
		return m, ErrRecovery
	}
	return m, nil
}
func writeMarker(path string, m EnrollmentMarker) error {
	if path == "" {
		return ErrNotReady
	}
	root, err := openEnrollmentRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	old, err := readMarker(path)
	if err == nil && (old.InstallationID != m.InstallationID || old.Version > m.Version || old.Version == m.Version && old.SHA256 != m.SHA256) {
		return ErrRecovery
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := ".enhanced-enrollment-" + uuid.NewString()
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = root.Rename(tmp, filepath.Base(path)); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *Service) CheckAnchor(ctx context.Context, cfg TransitionConfig) error {
	err := s.ValidateAnchor(ctx, cfg)
	if err != nil {
		_ = s.Store.RequirePolicyRecovery()
	}
	return err
}

// ValidateAnchor checks continuity without mutating policy state. It is safe for
// bounded read-only readiness; enforcement startup uses CheckAnchor to freeze
// access when the same validation fails.
func (s *Service) ValidateAnchor(ctx context.Context, cfg TransitionConfig) error {
	state, err := s.Store.GetPolicyState()
	if err != nil {
		return err
	}
	if state.Pending != nil && state.PendingChange != "" {
		change, err := s.Store.GetSecurityChange(state.PendingChange)
		if err == nil && state.Previous != nil && cfg.Evidence != nil {
			err = s.checkPendingRecovery(ctx, change, state, *state.Previous, cfg)
		} else {
			err = ErrRecovery
		}
		if err != nil {
			return ErrRecovery
		}
		return nil
	}
	m, err := readMarker(cfg.EnrollmentPath)
	enrolled, dbErr := s.Store.GovernanceEnrolled()
	if dbErr != nil {
		return dbErr
	}
	if errors.Is(err, os.ErrNotExist) && !enrolled {
		if state.Active.Version != 1 || state.Active.Policy.Profile != "standard" {
			return ErrRecovery
		}
		if cfg.Evidence == nil {
			return nil // Standalone Standard has never configured external governance.
		}
		if !auditrecord.ValidID(cfg.InstallationID) {
			return ErrRecovery
		}
		// Restoring an initial database and its absent marker must not erase an
		// enrollment already recorded by this installation's fixed authority.
		// Only its authenticated absence response permits initial Standard.
		if _, anchorErr := cfg.Evidence.Anchor(ctx, cfg.InstallationID); errors.Is(anchorErr, auditgate.ErrAnchorNotFound) {
			return nil
		}
		return ErrRecovery
	}
	if err != nil || cfg.Evidence == nil || m.InstallationID != cfg.InstallationID || m.Version != state.Active.Version || m.SHA256 != state.Active.SHA256 {
		return ErrRecovery
	}
	anchor, err := cfg.Evidence.Anchor(ctx, m.InstallationID)
	if err != nil || anchor.InstallationID != m.InstallationID || anchor.Version < m.Version || anchor.Version < state.Active.Version {
		return ErrRecovery
	}
	valid := anchor.Version == state.Active.Version && anchor.SHA256 == state.Active.SHA256
	if state.Pending != nil && anchor.Version == state.Pending.Version && anchor.SHA256 == state.Pending.SHA256 && anchor.RequestID == state.PendingChange {
		valid = true
	}
	if !valid {
		return ErrRecovery
	}
	return nil
}

// EnrollmentMarkerMatches reports actual outside-database marker evidence.
// Absence before initial enrollment is false and is not an enforcement failure;
// governance_enrolled in the policy response distinguishes that applicability.
func EnrollmentMarkerMatches(cfg TransitionConfig, state model.PolicyState) bool {
	m, err := readMarker(cfg.EnrollmentPath)
	if err != nil || m.InstallationID != cfg.InstallationID {
		return false
	}
	if m.Version == state.Active.Version && m.SHA256 == state.Active.SHA256 {
		return true
	}
	return state.Pending != nil && m.Version == state.Pending.Version && m.SHA256 == state.Pending.SHA256
}
func (s *Service) Apply(ctx context.Context, id, user, session, proof string, cfg TransitionConfig) (model.SecurityChange, error) {
	c, err := s.Store.GetSecurityChange(id)
	if err != nil {
		return c, err
	}
	if _, err = s.AuthorityForChange(c, user, ActionApply); err != nil {
		return c, err
	}
	if c.State == "applied" {
		return c, nil
	}
	if c.State == "applying" {
		return c, errors.New("transition applying; reconciliation required")
	}
	if _, err = s.AuthorityForChange(c, user, ActionApply); err != nil {
		return c, err
	}
	if err = s.ValidateQuorum(c); err != nil {
		return c, err
	}
	applier, err := s.AuthorityForChange(c, user, ActionApply)
	if err != nil {
		return c, err
	}
	applierUser, err := s.Store.GetUserByID(user)
	if err != nil {
		return c, err
	}
	if err = s.Store.ClaimSecurityApplier(c, user, applier.PersonID, applierUser.SecurityRevision, session, proof, s.Now()); err != nil {
		return c, err
	}
	c, err = s.Store.GetSecurityChange(id)
	if err != nil {
		return c, err
	}
	state, err := s.Store.GetPolicyState()
	if err != nil {
		return c, err
	}
	if state.Active.Version != c.ExpectedVersion {
		return c, store.ErrSecurityConflict
	}
	if state.Pending != nil || (state.State != "standard" && state.State != "enhanced" && state.State != "setup_pending") {
		return c, store.ErrSecurityConflict
	}
	p, err := DecodeChange(c.Payload)
	if err != nil {
		return c, err
	}
	// Resolve immutable secret references and validate prepared settings before
	// an intent is archived or a pending transition is installed. Prepared values
	// are transient; only the exact approved references are retained as evidence.
	if _, err = prepareTransitionPayload(p, cfg); err != nil {
		return c, err
	}
	candidate := state.Active.Policy
	if p.Policy != nil {
		candidate = *p.Policy
	}
	if cfg.Evidence == nil || cfg.EnrollmentPath == "" || !auditrecord.ValidID(cfg.InstallationID) {
		return c, ErrNotReady
	}
	if candidate.Profile == "enhanced" {
		if err = cfg.Evidence.Ready(ctx, candidate); err != nil {
			return c, err
		}
		if err = cfg.Evidence.Qualify(ctx, candidate); err != nil {
			return c, err
		}
	}
	if state.Active.Policy.Profile == "enhanced" {
		if err = s.CheckAnchor(ctx, cfg); err != nil {
			return c, err
		}
	}
	intent, err := s.archive(ctx, c, auditrecord.PolicyIntent, state.Active, cfg)
	if err != nil {
		return c, err
	}
	if err = s.Store.BeginSecurityApply(c, candidate, intent, s.Now()); err != nil {
		return c, err
	}
	return s.ReconcileChange(ctx, id, cfg)
}
func (s *Service) ReconcileChange(ctx context.Context, id string, cfg TransitionConfig) (model.SecurityChange, error) {
	c, err := s.Store.GetSecurityChange(id)
	if err != nil {
		return c, err
	}
	if c.State == "applied" {
		return c, nil
	}
	if c.State != "applying" || cfg.Evidence == nil {
		return c, ErrRecovery
	}
	state, err := s.Store.GetPolicyState()
	if err != nil || state.Pending == nil || state.PendingChange != id {
		return c, ErrRecovery
	}
	old, err := s.Store.GetPolicyVersion(c.ExpectedVersion)
	if err != nil {
		return c, err
	}
	// A local pending snapshot is not rollback evidence. Authenticate the latest
	// external anchor and the separate marker before retrying any side effect,
	// including finishing a transition whose active CAS already committed.
	if err = s.checkPendingRecovery(ctx, c, state, old, cfg); err != nil {
		_ = s.Store.RequirePolicyRecovery()
		return c, err
	}
	if state.State == "recovery_required" {
		if err = s.Store.ResumeSecurityApplying(id); err != nil {
			return c, err
		}
	}
	p, err := DecodeChange(c.Payload)
	if err != nil {
		return c, err
	}
	p, err = prepareTransitionPayload(p, cfg)
	if err != nil {
		return c, err
	}
	// Never re-run already activated role, identity or recovery side effects.
	if state.Active.Version == c.ExpectedVersion {
		if _, err = s.archive(ctx, c, auditrecord.PolicyIntent, old, cfg); err != nil {
			return c, err
		}
		if state.Pending.Policy.Profile == "enhanced" {
			if err = cfg.Evidence.Ready(ctx, state.Pending.Policy); err != nil {
				return c, err
			}
		}
		commit, err := s.archive(ctx, c, auditrecord.PolicyCommit, old, cfg)
		if err != nil {
			return c, err
		}
		if err = s.Store.RecordSecurityCommit(id, commit); err != nil {
			return c, err
		}
		if err = writeMarker(cfg.EnrollmentPath, EnrollmentMarker{cfg.InstallationID, state.Pending.Version, state.Pending.SHA256}); err != nil {
			return c, err
		}
		if _, err = s.archive(ctx, c, auditrecord.PolicyAnchor, *state.Pending, cfg); err != nil {
			return c, err
		}
		if err = s.Store.ActivateSecurityChange(c, p); err != nil {
			return c, err
		}
	}
	result, err := s.archive(ctx, c, auditrecord.PolicyResult, *state.Pending, cfg)
	if err != nil {
		return c, err
	}
	if err = s.Store.FinishSecurityChange(id, result); err != nil {
		return c, err
	}
	return s.Store.GetSecurityChange(id)
}

func prepareTransitionPayload(p model.SecurityChangePayload, cfg TransitionConfig) (model.SecurityChangePayload, error) {
	if p.Recovery != nil && p.Recovery.Operation == "password-reset" {
		if cfg.ResolveSecret == nil {
			return p, ErrNotReady
		}
		kind, value, err := cfg.ResolveSecret(p.Recovery.SecretRef)
		if err != nil || kind != "password" {
			return p, ErrNotReady
		}
		p.Recovery.PreparedPasswordHash = value
	}
	if p.LDAP != nil {
		if cfg.PrepareChange == nil {
			return p, ErrNotReady
		}
		return cfg.PrepareChange(p)
	}
	return p, nil
}

func (s *Service) checkPendingRecovery(ctx context.Context, c model.SecurityChange, state model.PolicyState, old model.PolicyVersion, cfg TransitionConfig) error {
	if !auditrecord.ValidID(cfg.InstallationID) || state.Pending == nil || state.Pending.Version != c.ExpectedVersion+1 || state.Pending.RequestID != c.ID || Digest(c.ApprovedBytes) != c.Digest || (state.Active.Version != old.Version && state.Active.Version != state.Pending.Version) {
		return ErrRecovery
	}
	payload, err := DecodeChange(c.Payload)
	if err != nil {
		return ErrRecovery
	}
	initial := payload.Kind == "bootstrap" && c.ExpectedVersion == 1 && old.Policy.Profile == "standard"
	activated := state.Active.Version == state.Pending.Version
	marker, markerErr := readMarker(cfg.EnrollmentPath)
	if markerErr != nil {
		if !initial || activated || !errors.Is(markerErr, os.ErrNotExist) {
			return ErrRecovery
		}
	} else if marker.InstallationID != cfg.InstallationID || !((marker.Version == old.Version && marker.SHA256 == old.SHA256) || (marker.Version == state.Pending.Version && marker.SHA256 == state.Pending.SHA256)) {
		return ErrRecovery
	}
	if activated && marker.Version != state.Pending.Version {
		return ErrRecovery
	}
	anchor, err := cfg.Evidence.Anchor(ctx, cfg.InstallationID)
	if err != nil {
		// This sentinel must denote the authenticated external service's absence
		// response. Timeouts, untrusted responses and failed admin lookup never
		// permit recovery, even when ingestion remains healthy.
		if initial && !activated && errors.Is(err, auditgate.ErrAnchorNotFound) {
			return nil
		}
		return ErrRecovery
	}
	if anchor.InstallationID != cfg.InstallationID {
		return ErrRecovery
	}
	if anchor.Version == state.Pending.Version && anchor.SHA256 == state.Pending.SHA256 && anchor.RequestID == c.ID && anchor.RequestSHA256 == c.Digest {
		return nil
	}
	if !activated && anchor.Version == old.Version && anchor.SHA256 == old.SHA256 && anchor.RequestID == old.RequestID && old.RequestID != "" {
		previous, err := s.Store.GetSecurityChange(old.RequestID)
		if err == nil && anchor.RequestSHA256 == previous.Digest {
			return nil
		}
	}
	return ErrRecovery
}
func (s *Service) archive(ctx context.Context, c model.SecurityChange, kind string, policy model.PolicyVersion, cfg TransitionConfig) (string, error) {
	u, err := s.Store.GetUserByID(c.ApplierID)
	if err != nil {
		return "", err
	}
	subject := u.ExternalID
	if subject == "" {
		subject = u.ID
	}
	requester, err := s.Store.GetUserByID(c.RequesterID)
	if err != nil {
		return "", err
	}
	requesterSubject := requester.ExternalID
	if requesterSubject == "" {
		requesterSubject = requester.ID
	}
	details := &auditrecord.Details{CorrelationID: c.ID, RequestID: c.ID, RequestSHA256: c.Digest, ExpectedPolicyVersion: c.ExpectedVersion, NewPolicyVersion: c.ExpectedVersion + 1, Reason: c.Reason, State: kind, ApprovedChange: c.ApprovedBytes}
	details.Requester = &auditrecord.Actor{UserID: requester.ID, PersonID: c.RequesterPersonID, Name: requester.Username, Provider: string(requester.AuthProvider), Subject: requesterSubject}
	for _, a := range c.Approvals {
		details.Approvals = append(details.Approvals, auditrecord.ApprovalEvidence{UserID: a.UserID, PersonID: a.PersonID, StepupProofSHA256: a.ProofSHA256, ApprovedAt: a.ApprovedAt})
	}
	e := auditrecord.Envelope{SchemaVersion: 1, EventID: c.ID + "-" + kind, EventType: kind, Actor: auditrecord.Actor{UserID: u.ID, PersonID: c.ApplierPersonID, Name: u.Username, Provider: string(u.AuthProvider), Subject: subject}, PolicyVersion: policy.Version, PolicySHA256: policy.SHA256, OccurredAt: s.Now(), Details: details}
	if kind == auditrecord.PolicyAnchor {
		details.CorrelationID = cfg.InstallationID
		details.InstallationID = cfg.InstallationID
		details.ApprovedChange = nil
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	raw, _, err = s.Store.SecurityEvidenceBytes(c.ID, kind, raw)
	if err != nil {
		return "", err
	}
	if _, _, err = auditrecord.ExpectedFor(raw); err != nil {
		return "", fmt.Errorf("governance record: %w", err)
	}
	reference, err := cfg.Evidence.Preserve(ctx, raw)
	if err != nil {
		return "", err
	}
	if reference == "" {
		return "", ErrRecovery
	}
	if err = s.Store.ConfirmSecurityEvidence(c.ID, kind, reference); err != nil {
		return "", err
	}
	return reference, nil
}

// Startup performs one bounded attempt to reconcile a recorded transition. A
// failed attempt leaves covered access closed; operators may retry the exact
// transition through the reconciliation API after restoring dependencies.
func (s *Service) Startup(ctx context.Context, cfg TransitionConfig) error {
	state, err := s.Store.GetPolicyState()
	if err != nil {
		return err
	}
	if state.Pending != nil && state.PendingChange != "" {
		if _, err := s.ReconcileChange(ctx, state.PendingChange, cfg); err != nil {
			return err
		}
	}
	return s.CheckAnchor(ctx, cfg)
}

// InitInstallation creates one private directory and fsyncs its existing parent.
// Its persistent identifier survives an application-database restore.
func InitInstallation(dir string) (string, error) {
	parent := filepath.Dir(dir)
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	parentFile, err := os.Open(parent)
	if err != nil {
		return "", err
	}
	err = parentFile.Sync()
	parentFile.Close()
	if err != nil {
		return "", err
	}
	root, err := openEnrollmentRoot(filepath.Join(dir, "installation-id"))
	if err != nil {
		return "", err
	}
	defer root.Close()
	read := func() (string, error) {
		f, err := root.OpenFile("installation-id", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return "", err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return "", ErrRecovery
		}
		raw, err := io.ReadAll(io.LimitReader(f, 129))
		if err != nil || !auditrecord.ValidID(string(raw)) {
			return "", ErrRecovery
		}
		return string(raw), nil
	}
	if id, err := read(); err == nil {
		return id, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	id := uuid.NewString()
	f, err := root.OpenFile("installation-id", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if errors.Is(err, os.ErrExist) {
		return read()
	}
	if err != nil {
		return "", err
	}
	if _, err = f.Write([]byte(id)); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	directory, err := root.Open(".")
	if err != nil {
		return "", err
	}
	err = directory.Sync()
	directory.Close()
	if err != nil {
		return "", err
	}
	return id, nil
}
