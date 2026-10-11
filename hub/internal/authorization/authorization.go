// Package authorization evaluates live database authority and protected policy.
package authorization

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

var ErrDenied = errors.New("security capability required")
var ErrIndependent = errors.New("requester and two approvers must be independent verified people")
var ErrInteractive = errors.New("covered interactive access cannot preserve submitted-command evidence")
var ErrRecovery = errors.New("enhanced policy reconciliation required")
var ErrTransition = errors.New("covered execution blocked while security transition reconciles")

var ErrNotReady = errors.New("enhanced enforcement and archive qualification are not ready")

const ActionRequest = "security.request"
const ActionApprove = "security.approve"
const ActionApply = "security.apply"

type Service struct {
	Store *store.Store
	Now   func() time.Time
}

func New(st *store.Store) *Service {
	return &Service{Store: st, Now: func() time.Time { return time.Now().UTC() }}
}
func Digest(raw []byte) string { return store.SecurityDigest(raw) }
func (s *Service) Effective(userID string) (model.EffectiveCapabilities, error) {
	e := model.EffectiveCapabilities{UserID: userID, Roles: []model.Role{}, Capabilities: []string{}}
	u, err := s.Store.GetUserByID(userID)
	if err != nil {
		return e, ErrDenied
	}
	state := account.Evaluate(account.InputFromUser(u), s.Now(), lockout.Load(s.Store.GetConfig))
	if _, refuse := account.Refusal(state); refuse {
		return e, ErrDenied
	}
	e.Roles, err = s.Store.UserRoles(userID)
	if err != nil {
		return e, err
	}
	e.PersonID, err = s.Store.PersonForUser(userID)
	if err != nil {
		return e, err
	}
	caps := map[string]bool{"nodes.read": true}
	for _, r := range e.Roles {
		switch r {
		case model.RoleAdmin:
			caps["operations.admin"] = true
			caps["audit.read"] = true
			caps["security.bootstrap"] = true
		case model.RoleAuditor:
			caps["audit.read"] = true
		case model.RoleSecurityOfficer:
			caps["security.request"] = true
			caps["security.read"] = true
			caps["security.apply"] = true
			caps["security.test"] = true
		case model.RoleSecurityApprover:
			caps["security.approve"] = true
			caps["security.read"] = true
		case model.RoleOriginalReader:
			caps["audit.original.read"] = true
			caps["audit.read"] = true
		}
	}
	if caps["operations.admin"] || u.AuthProvider == model.AuthProviderLDAP && u.TerminalAccess {
		caps["terminal.execute"] = true
	}
	for _, c := range []string{"nodes.read", "operations.admin", "audit.read", "terminal.execute", "security.bootstrap", "security.read", "security.request", "security.approve", "security.apply", "security.test", "audit.original.read"} {
		if caps[c] {
			e.Capabilities = append(e.Capabilities, c)
		}
	}
	return e, nil
}
func (s *Service) PolicyForExecution(actor, node string) (model.ExecutionPolicy, error) {
	state, err := s.Store.GetPolicyState()
	if err != nil {
		return model.ExecutionPolicy{}, err
	}
	p := model.ExecutionPolicy{Version: state.Active.Version, SHA256: state.Active.SHA256, Enhanced: state.Active.Policy.Covers(actor, node), RuntimeSeconds: state.Active.Policy.RuntimeSeconds, RecoveryRequired: state.State == "recovery_required"}
	if state.Pending != nil {
		p.Enhanced = p.Enhanced || state.Pending.Policy.Covers(actor, node)
		if state.Pending.Policy.RuntimeSeconds > 0 && (p.RuntimeSeconds <= 0 || state.Pending.Policy.RuntimeSeconds < p.RuntimeSeconds) {
			p.RuntimeSeconds = state.Pending.Policy.RuntimeSeconds
		}
	}
	if state.Previous != nil {
		p.Enhanced = p.Enhanced || state.Previous.Policy.Covers(actor, node)
	}
	if p.Enhanced && state.Pending != nil {
		return p, ErrTransition
	}
	if p.RecoveryRequired {
		return p, ErrRecovery
	}
	return p, nil
}
func (s *Service) GuardInteractive(actor, node string) error {
	p, err := s.PolicyForExecution(actor, node)
	if err != nil {
		return err
	}
	if p.Enhanced {
		return ErrInteractive
	}
	return nil
}

// DecodeChange validates JSON ambiguity before decoding a closed typed payload.
func DecodeChange(raw []byte) (model.SecurityChangePayload, error) {
	var p model.SecurityChangePayload
	if auditrecord.Decode(raw, &p, 48*1024) != nil {
		return p, errors.New("invalid or ambiguous typed change")
	}
	return p, validatePayload(p)
}
func validatePayload(p model.SecurityChangePayload) error {
	fields := 0
	if p.Policy != nil {
		fields++
	}
	if p.Role != nil {
		fields++
	}
	if p.Person != nil {
		fields++
	}
	if p.Recovery != nil {
		fields++
	}
	if p.AuditSettings != nil {
		fields++
	}
	if p.LDAP != nil {
		fields++
	}
	if fields != 1 {
		return errors.New("exactly one typed security change required")
	}
	switch p.Kind {
	case "bootstrap", "policy":
		if p.Policy == nil {
			return errors.New("policy required")
		}
		if p.Kind == "bootstrap" {
			if len(p.Nominations) < 3 || len(p.Nominations) > 32 || p.Policy.Profile != "enhanced" {
				return ErrIndependent
			}
		} else if len(p.Nominations) > 0 {
			return errors.New("nominations require bootstrap")
		}
		return validatePolicy(*p.Policy)
	case "role":
		if p.Role == nil || p.Role.UserID == "" || !model.IsSecurityRole(p.Role.Role) {
			return errors.New("security role assignment required")
		}
	case "person":
		if p.Person == nil || p.Person.UserID == "" || !validKey(p.Person.PersonID) || strings.TrimSpace(p.Person.Verification) == "" || len(p.Person.Verification) > 2048 {
			return errors.New("verified person link required")
		}
	case "audit-settings":
		if p.AuditSettings == nil {
			return errors.New("audit settings required")
		}
		return store.ValidateAuditSettings(*p.AuditSettings)
	case "ldap":
		if p.LDAP == nil || len(p.LDAP.URL) > 4096 || len(p.LDAP.CACertPEM) > 32768 {
			return errors.New("bounded LDAP settings required")
		}
		if p.LDAP.Enabled && !strings.HasPrefix(p.LDAP.URL, "ldaps://") && !p.LDAP.StartTLS {
			return errors.New("LDAP TLS required")
		}
		if p.LDAP.ClearBindPassword && p.LDAP.BindCredentialRef != "" {
			return errors.New("ambiguous LDAP credential reference")
		}
	case "recovery":
		if p.Recovery == nil || p.Recovery.UserID == "" {
			return errors.New("recovery target required")
		}
		switch p.Recovery.Operation {
		case "reenable", "mfa-reset", "password-reset":
		default:
			return errors.New("unsupported recovery operation")
		}
		if p.Recovery.Operation == "password-reset" && p.Recovery.SecretRef == "" {
			return errors.New("versioned credential reference required")
		}
	default:
		return errors.New("unsupported security change")
	}
	if len(p.Nominations) > 0 {
		return errors.New("unexpected nominations")
	}
	return nil
}
func validKey(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_:.", c)) {
			return false
		}
	}
	return true
}
func validatePolicy(p model.AuditPolicy) error {
	if p.Profile != "standard" && p.Profile != "enhanced" {
		return errors.New("unknown profile")
	}
	if p.RuntimeSeconds < 1 || p.RuntimeSeconds > 3600 || p.RetentionHours < 24 || p.RetentionHours > 24*3650 || len(p.Actors) > 1000 || len(p.Nodes) > 1000 || len(p.TrustKeyIDs) > 16 {
		return errors.New("policy limits exceeded")
	}
	for _, list := range [][]string{p.Actors, p.Nodes, p.TrustKeyIDs} {
		seen := map[string]bool{}
		for _, id := range list {
			if !validKey(id) || seen[id] {
				return errors.New("invalid or duplicate scope/key")
			}
			seen[id] = true
		}
	}
	if p.Profile == "enhanced" && (p.Destination == "" || p.CredentialRef == "" || len(p.TrustKeyIDs) == 0 || len(p.QualificationSHA256) != 64) {
		return ErrNotReady
	}
	return nil
}

type Proposal struct {
	Reason          string          `json:"reason"`
	ExpectedVersion uint64          `json:"expected_version"`
	Change          json.RawMessage `json:"change"`
}
type Preview struct {
	Digest   string   `json:"digest"`
	Proposal Proposal `json:"proposal"`
	Bytes    []byte   `json:"-"`
}

func Normalize(p Proposal) (Preview, error) {
	p.Reason = strings.TrimSpace(p.Reason)
	if p.Reason == "" || len(p.Reason) > 2048 || p.ExpectedVersion == 0 {
		return Preview{}, errors.New("reason and expected version required")
	}
	change, err := DecodeChange(p.Change)
	if err != nil {
		return Preview{}, err
	}
	p.Change, err = json.Marshal(change)
	if err != nil {
		return Preview{}, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return Preview{}, err
	}
	return Preview{Digest: Digest(raw), Proposal: p, Bytes: raw}, nil
}
func (s *Service) Request(user, session, proof string, proposal Proposal) (model.SecurityChange, error) {
	preview, err := Normalize(proposal)
	if err != nil {
		return model.SecurityChange{}, err
	}
	payload, _ := DecodeChange(preview.Proposal.Change)
	e, err := s.Effective(user)
	if err != nil {
		return model.SecurityChange{}, err
	}
	if payload.Kind == "bootstrap" {
		state, err := s.Store.GetPolicyState()
		if err != nil {
			return model.SecurityChange{}, err
		}
		enrolled, err := s.Store.GovernanceEnrolled()
		if err != nil {
			return model.SecurityChange{}, err
		}
		if enrolled || state.Active.Policy.Profile != "standard" || !e.Can("security.bootstrap") {
			return model.SecurityChange{}, ErrDenied
		}
		if err := s.validateNominations(payload.Nominations, user); err != nil {
			return model.SecurityChange{}, err
		}
		e.PersonID = nominationPerson(payload.Nominations, user)
	} else if !e.Can(ActionRequest) {
		return model.SecurityChange{}, ErrDenied
	}
	u, err := s.Store.GetUserByID(user)
	if err != nil {
		return model.SecurityChange{}, err
	}
	now := s.Now()
	c := model.SecurityChange{ID: uuid.NewString(), Revision: 1, RequesterID: user, RequesterPersonID: e.PersonID, RequesterGeneration: u.SecurityRevision, ExpectedVersion: preview.Proposal.ExpectedVersion, Digest: preview.Digest, Reason: preview.Proposal.Reason, Payload: preview.Proposal.Change, ApprovedBytes: preview.Bytes, State: "requested", CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour), Approvals: []model.SecurityApproval{}}
	if err = s.Store.CreateSecurityChange(c, payload.Nominations, session, proof, now); err != nil {
		return c, err
	}
	return c, nil
}
func nominationPerson(ns []model.SecurityNomination, user string) string {
	for _, n := range ns {
		if n.UserID == user {
			return n.PersonID
		}
	}
	return ""
}
func (s *Service) validateNominations(ns []model.SecurityNomination, requester string) error {
	people := map[string]bool{}
	users := map[string]bool{}
	approvers := 0
	officer := false
	for _, n := range ns {
		if !validKey(n.PersonID) || strings.TrimSpace(n.Verification) == "" || len(n.Verification) > 2048 || people[n.PersonID] || users[n.UserID] {
			return ErrIndependent
		}
		people[n.PersonID] = true
		users[n.UserID] = true
		u, err := s.Store.GetUserByID(n.UserID)
		if err != nil || !u.TOTPEnabled || u.TOTPSecret == nil || u.DisabledAt != nil || u.MustChangePassword {
			return errors.New("nominees require their own completed MFA identities")
		}
		linked, err := s.Store.PersonForUser(n.UserID)
		if err != nil {
			return err
		}
		if linked != "user:"+n.UserID && linked != n.PersonID {
			return store.ErrProtectedChange
		}
		roles := map[model.Role]bool{}
		for _, r := range n.Roles {
			if !model.IsSecurityRole(r) || roles[r] {
				return errors.New("invalid nomination roles")
			}
			roles[r] = true
		}
		if n.UserID == requester && roles[model.RoleSecurityOfficer] {
			officer = true
		}
		if n.UserID != requester && roles[model.RoleSecurityApprover] {
			approvers++
		}
	}
	if !officer || approvers < 2 {
		return ErrIndependent
	}
	return nil
}
func (s *Service) AuthorityForChange(c model.SecurityChange, user, action string) (model.EffectiveCapabilities, error) {
	e, err := s.Effective(user)
	if err != nil {
		return e, err
	}
	p, err := DecodeChange(c.Payload)
	if err != nil {
		return e, err
	}
	if p.Kind == "bootstrap" {
		e.PersonID = nominationPerson(p.Nominations, user)
		for _, n := range p.Nominations {
			if n.UserID == user {
				for _, r := range n.Roles {
					if action == ActionApprove && r == model.RoleSecurityApprover {
						return e, nil
					}
					if action != ActionApprove && r == model.RoleSecurityOfficer && user == c.RequesterID && e.Can("security.bootstrap") {
						return e, nil
					}
				}
			}
		}
		return e, ErrDenied
	}
	if !e.Can(action) {
		return e, ErrDenied
	}
	return e, nil
}
func (s *Service) Approve(id, user, session, proof string) (model.SecurityChange, error) {
	c, err := s.Store.GetSecurityChange(id)
	if err != nil {
		return c, err
	}
	e, err := s.AuthorityForChange(c, user, ActionApprove)
	if err != nil {
		return c, err
	}
	if user == c.RequesterID || e.PersonID == c.RequesterPersonID {
		return c, ErrIndependent
	}
	for _, a := range c.Approvals {
		if a.PersonID == e.PersonID {
			return c, ErrIndependent
		}
	}
	if s.Now().After(c.ExpiresAt) || Digest(c.ApprovedBytes) != c.Digest {
		return c, store.ErrSecurityConflict
	}
	u, err := s.Store.GetUserByID(user)
	if err != nil {
		return c, err
	}
	a := model.SecurityApproval{UserID: user, PersonID: e.PersonID, TokenGeneration: u.SecurityRevision}
	if err = s.Store.AddSecurityApproval(c, a, session, proof, s.Now()); err != nil {
		return c, err
	}
	return s.Store.GetSecurityChange(id)
}
func (s *Service) ValidateQuorum(c model.SecurityChange) error {
	if !s.Now().Before(c.ExpiresAt) || Digest(c.ApprovedBytes) != c.Digest || len(c.Approvals) < 2 {
		return store.ErrSecurityConflict
	}
	requester, err := s.AuthorityForChange(c, c.RequesterID, ActionRequest)
	if err != nil {
		return err
	}
	u, err := s.Store.GetUserByID(c.RequesterID)
	if err != nil || u.SecurityRevision != c.RequesterGeneration || requester.PersonID != c.RequesterPersonID {
		return ErrDenied
	}
	persons := map[string]bool{c.RequesterPersonID: true}
	valid := 0
	for _, a := range c.Approvals {
		if a.InvalidatedAt != nil {
			continue
		}
		e, err := s.AuthorityForChange(c, a.UserID, ActionApprove)
		if err != nil {
			return err
		}
		u, err := s.Store.GetUserByID(a.UserID)
		if err != nil || u.SecurityRevision != a.TokenGeneration || e.PersonID != a.PersonID || persons[e.PersonID] {
			return ErrIndependent
		}
		persons[e.PersonID] = true
		valid++
	}
	if valid < 2 {
		return ErrIndependent
	}
	return nil
}
func (s *Service) GuardMutation(user string) error { return s.Store.GuardSecurityUserMutation(user) }
func (s *Service) String() string                  { return fmt.Sprintf("live authorization(%p)", s.Store) }
