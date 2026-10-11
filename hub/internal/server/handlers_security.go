package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

type SecurityDestinationTester interface {
	Test(context.Context, model.AuditPolicy) error
}

func (s *Server) securityService() *authorization.Service {
	service := authorization.New(s.store)
	service.Now = s.now
	return service
}
func decodeSecurity(r *http.Request, v any) error {
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024+1))
	if err != nil {
		return err
	}
	return auditrecord.Decode(raw, v, 64*1024)
}
func securityError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, authorization.ErrDenied), errors.Is(err, authorization.ErrIndependent), errors.Is(err, store.ErrProtectedChange), errors.Is(err, store.ErrStepup):
		status = http.StatusForbidden
	case errors.Is(err, store.ErrSecurityConflict):
		status = http.StatusConflict
	case errors.Is(err, authorization.ErrNotReady), errors.Is(err, authorization.ErrRecovery):
		status = http.StatusServiceUnavailable
	}
	// Infrastructure errors are intentionally opaque, avoiding destination/credential leakage.
	if status == http.StatusBadRequest && !(strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "unsupported") || strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "bounded")) {
		respondError(w, http.StatusBadRequest, "security operation could not be completed")
		return
	}
	respondError(w, status, err.Error())
}
func (s *Server) securityReadAllowed(user string) bool {
	e, err := s.securityService().Effective(user)
	if err != nil {
		return false
	}
	if e.Can("security.read") {
		return true
	}
	state, err := s.store.GetPolicyState()
	if err != nil || state.Active.Policy.Profile != "standard" || !e.Can("security.bootstrap") {
		return false
	}
	enrolled, err := s.store.GovernanceEnrolled()
	return err == nil && !enrolled
}
func (s *Server) handleAuditPolicy(w http.ResponseWriter, r *http.Request) {
	e, err := s.securityService().Effective(UserIDFromContext(r.Context()))
	if err != nil {
		securityError(w, err)
		return
	}
	state, err := s.store.GetPolicyState()
	if err != nil {
		securityError(w, err)
		return
	}
	enrolled, err := s.store.GovernanceEnrolled()
	if err != nil {
		securityError(w, err)
		return
	}
	if !s.securityReadAllowed(e.UserID) {
		respondJSON(w, http.StatusOK, map[string]any{"version": state.Active.Version, "profile": state.Active.Policy.Profile, "state": state.State, "capabilities": e.Capabilities, "governance_enrolled": enrolled})
		return
	}
	ready, governanceReady := false, false
	if s.securityTransition.Evidence != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		governance := make(chan bool, 1)
		go func() {
			checker, ok := s.securityTransition.Evidence.(interface{ GovernanceReady(context.Context) error })
			governance <- ok && checker.GovernanceReady(ctx) == nil && s.securityService().ValidateAnchor(ctx, s.securityTransition) == nil
		}()
		if state.Active.Policy.Profile == "enhanced" {
			ready = s.securityTransition.Evidence.Ready(ctx, state.Active.Policy) == nil
		}
		governanceReady = <-governance
		cancel()
	}
	respondJSON(w, http.StatusOK, map[string]any{"policy": state.Active, "state": state.State, "pending": state.Pending, "capabilities": e.Capabilities, "governance_enrolled": enrolled, "credential_set": state.Active.Policy.CredentialRef != "", "readiness": map[string]bool{"governance": governanceReady, "archive_and_transport": ready, "enrollment_marker": authorization.EnrollmentMarkerMatches(s.securityTransition, state)}})
}
func (s *Server) handleSecurityPreview(w http.ResponseWriter, r *http.Request) {
	if !s.securityReadAllowed(UserIDFromContext(r.Context())) {
		securityError(w, authorization.ErrDenied)
		return
	}
	var req struct {
		Reason          string                      `json:"reason"`
		ExpectedVersion uint64                      `json:"expected_version"`
		Change          model.SecurityChangePayload `json:"change"`
	}
	if err := decodeSecurity(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	change, _ := json.Marshal(req.Change)
	preview, err := authorization.Normalize(authorization.Proposal{Reason: req.Reason, ExpectedVersion: req.ExpectedVersion, Change: change})
	if err != nil {
		securityError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, preview)
}
func (s *Server) handleSecurityStepup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action   string `json:"action"`
		Digest   string `json:"digest"`
		Code     string `json:"code"`
		ChangeID string `json:"change_id,omitempty"`
	}
	if err := decodeSecurity(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	userID := UserIDFromContext(r.Context())
	sid := SessionIDFromContext(r.Context())
	if TokenTypeFromContext(r.Context()) != auth.TokenTypeAccess || sid == "" || !auditrecord.ValidHash(req.Digest) {
		securityError(w, store.ErrStepup)
		return
	}
	service := s.securityService()
	e, err := service.Effective(userID)
	if err != nil {
		securityError(w, err)
		return
	}
	switch req.Action {
	case authorization.ActionRequest:
		if !e.Can(req.Action) && !e.Can("security.bootstrap") {
			securityError(w, authorization.ErrDenied)
			return
		}
	case authorization.ActionApprove, authorization.ActionApply:
		c, err := s.store.GetSecurityChange(req.ChangeID)
		if err != nil || c.Digest != req.Digest {
			securityError(w, store.ErrSecurityConflict)
			return
		}
		if _, err = service.AuthorityForChange(c, userID, req.Action); err != nil {
			securityError(w, err)
			return
		}
	default:
		securityError(w, authorization.ErrDenied)
		return
	}
	user, err := s.store.GetUserByID(userID)
	if err != nil || !user.TOTPEnabled || user.TOTPSecret == nil {
		securityError(w, store.ErrStepup)
		return
	}
	secret, err := s.decryptTOTPSecret(*user.TOTPSecret)
	if err != nil || !auth.ValidateTOTPWithReplayAt(s.totpCache, userID, secret, req.Code, s.now()) {
		securityError(w, store.ErrStepup)
		return
	}
	proof, err := s.store.IssueStepup(userID, sid, req.Action, req.Digest, s.now())
	if err != nil {
		securityError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"proof": proof, "expires_at": s.now().Add(5 * time.Minute)})
}
func (s *Server) handleSecurityRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason          string                      `json:"reason"`
		ExpectedVersion uint64                      `json:"expected_version"`
		Change          model.SecurityChangePayload `json:"change"`
		Proof           string                      `json:"step_up_proof"`
	}
	if err := decodeSecurity(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	change, _ := json.Marshal(req.Change)
	c, err := s.securityService().Request(UserIDFromContext(r.Context()), SessionIDFromContext(r.Context()), req.Proof, authorization.Proposal{Reason: req.Reason, ExpectedVersion: req.ExpectedVersion, Change: change})
	if err != nil {
		securityError(w, err)
		return
	}
	s.auditSecurity(r, "security.change_requested", c.ID, c.Digest)
	respondJSON(w, http.StatusCreated, c)
}
func (s *Server) handleSecurityList(w http.ResponseWriter, r *http.Request) {
	if !s.securityReadAllowed(UserIDFromContext(r.Context())) {
		securityError(w, authorization.ErrDenied)
		return
	}
	_ = s.store.ExpireSecurityChanges(s.now())
	limit, offset := parsePagination(r.URL.Query(), 50)
	changes, err := s.store.ListSecurityChanges(limit, offset)
	if err != nil {
		securityError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"changes": changes, "limit": limit, "offset": offset})
}
func (s *Server) handleSecurityGet(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetSecurityChange(r.PathValue("id"))
	if err != nil {
		respondError(w, http.StatusNotFound, "security change not found")
		return
	}
	user := UserIDFromContext(r.Context())
	if !s.securityReadAllowed(user) {
		if _, err := s.securityService().AuthorityForChange(c, user, authorization.ActionApprove); err != nil {
			securityError(w, err)
			return
		}
	}
	respondJSON(w, http.StatusOK, c)
}
func (s *Server) handleSecurityApprove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proof string `json:"step_up_proof"`
	}
	if err := decodeSecurity(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	c, err := s.securityService().Approve(r.PathValue("id"), UserIDFromContext(r.Context()), SessionIDFromContext(r.Context()), req.Proof)
	if err != nil {
		securityError(w, err)
		return
	}
	s.auditSecurity(r, "security.change_approved", c.ID, c.Digest)
	respondJSON(w, http.StatusOK, c)
}
func (s *Server) handleSecurityApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proof string `json:"step_up_proof"`
	}
	if err := decodeSecurity(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	c, err := s.securityService().Apply(r.Context(), r.PathValue("id"), UserIDFromContext(r.Context()), SessionIDFromContext(r.Context()), req.Proof, s.securityTransition)
	if err != nil {
		securityError(w, err)
		return
	}
	s.endNewlyCoveredShells()
	s.auditSecurity(r, "security.change_applied", c.ID, c.Digest)
	respondJSON(w, http.StatusOK, c)
}
func (s *Server) endNewlyCoveredShells() {
	if s.terminalSessions == nil {
		return
	}
	users, err := s.store.ListUsers()
	if err != nil {
		return
	}
	for _, u := range users {
		for _, shell := range s.terminalSessions.ListByUser(u.ID) {
			if shell.Kind == grpcserver.TerminalKindExec {
				continue
			}
			if s.securityService().GuardInteractive(u.ID, shell.ServerID) != nil {
				s.terminalSessions.EndOne(shell.ServerID, shell.SessionID, 1, "Security policy changed; protected command execution required.")
			}
		}
	}
}
func (s *Server) auditSecurity(r *http.Request, action, id, digest string) {
	user := UserIDFromContext(r.Context())
	detail := "request_digest=" + digest
	s.auditLogRequest(r, model.AuditEntry{UserID: &user, Action: action, Target: &id, Detail: &detail})
}
func (s *Server) testAuthority(user string) bool {
	e, err := s.securityService().Effective(user)
	if err != nil {
		return false
	}
	state, err := s.store.GetPolicyState()
	if e.Can("security.test") {
		return true
	}
	if err != nil || state.Active.Policy.Profile != "standard" || !e.Can("security.bootstrap") {
		return false
	}
	enrolled, err := s.store.GovernanceEnrolled()
	return err == nil && !enrolled
}
func (s *Server) handleSecuritySecret(w http.ResponseWriter, r *http.Request) {
	user := UserIDFromContext(r.Context())
	if !s.testAuthority(user) {
		securityError(w, authorization.ErrDenied)
		return
	}
	var req struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	}
	if err := decodeSecurity(r, &req); err != nil || req.Value == "" || len(req.Value) > 8192 || (req.Kind != "destination" && req.Kind != "password") {
		respondError(w, http.StatusBadRequest, "bounded secret kind and value required")
		return
	}
	if req.Kind == "password" {
		if err := auth.ValidatePasswordPolicy(req.Value); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		hash, err := auth.HashPassword(req.Value)
		if err != nil {
			securityError(w, err)
			return
		}
		req.Value = hash
	}
	raw, _ := json.Marshal(req)
	encrypted, err := auth.Encrypt(raw, auth.DeriveKey(s.storageKey))
	if err != nil {
		securityError(w, err)
		return
	}
	ref := "secret:" + uuid.NewString()
	if err = s.store.SaveSecuritySecret(ref, encrypted, user, s.now()); err != nil {
		securityError(w, err)
		return
	}
	s.auditSecurity(r, "security.secret_created", ref, authorization.Digest([]byte(ref)))
	respondJSON(w, http.StatusCreated, map[string]any{"credential_ref": ref, "credential_set": true})
}
func (s *Server) handleAuditPolicyTest(w http.ResponseWriter, r *http.Request) {
	if !s.testAuthority(UserIDFromContext(r.Context())) {
		securityError(w, authorization.ErrDenied)
		return
	}
	var p model.AuditPolicy
	if err := decodeSecurity(r, &p); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	u, err := url.Parse(p.Destination)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		respondError(w, http.StatusBadRequest, "allowed HTTPS destination required")
		return
	}
	allowed := false
	for _, host := range s.securityAllowedHosts {
		if host == u.Host {
			allowed = true
		}
	}
	if !allowed {
		respondError(w, http.StatusForbidden, "destination is outside the operator allowlist")
		return
	}
	if s.securityDestinationTester == nil {
		securityError(w, authorization.ErrNotReady)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := s.securityDestinationTester.Test(ctx, p); err != nil {
		respondError(w, http.StatusServiceUnavailable, "destination TLS, write and retention qualification failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]bool{"ready": true})
}
func (s *Server) populateAuthority(user *model.User) {
	e, err := s.securityService().Effective(user.ID)
	if err == nil {
		user.Roles = e.Roles
		user.Capabilities = e.Capabilities
		user.PersonID = e.PersonID
	}
}

func (s *Server) resolveSecuritySecret(ref string) (string, string, error) {
	return ResolveSecuritySecret(s.store, s.storageKey, ref)
}

// ResolveSecuritySecret exposes immutable encrypted credential references only
// to the backend runtime. There is no HTTP counterpart that reads their values.
func ResolveSecuritySecret(st *store.Store, storageKey, ref string) (string, string, error) {
	b, err := st.SecuritySecret(ref)
	if err != nil {
		return "", "", err
	}
	raw, err := auth.Decrypt(b, auth.DeriveKey(storageKey))
	if err != nil {
		return "", "", err
	}
	var secret struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &secret); err != nil {
		return "", "", err
	}
	return secret.Kind, secret.Value, nil
}

func (s *Server) prepareSecurityChange(p model.SecurityChangePayload) (model.SecurityChangePayload, error) {
	if p.LDAP == nil {
		return p, nil
	}
	l := p.LDAP
	req := ldapConfigRequest{Enabled: l.Enabled, URL: l.URL, BindDN: l.BindDN, ClearBindPassword: l.ClearBindPassword, UserBaseDN: l.UserBaseDN, GroupBaseDN: l.GroupBaseDN, UserSearchFilter: l.UserSearchFilter, GroupSearchFilter: l.GroupSearchFilter, UsernameAttribute: l.UsernameAttribute, EmailAttribute: l.EmailAttribute, ExternalIDAttribute: l.ExternalIDAttribute, GroupNameAttribute: l.GroupNameAttribute, StartTLS: l.StartTLS, TLSServerName: l.TLSServerName, CACertPEM: l.CACertPEM, AdminGroups: l.AdminGroups, AuditorGroups: l.AuditorGroups, ViewerGroups: l.ViewerGroups, TerminalGroups: l.TerminalGroups}
	if l.BindCredentialRef != "" {
		kind, value, err := s.resolveSecuritySecret(l.BindCredentialRef)
		if err != nil || kind != "destination" {
			return p, authorization.ErrNotReady
		}
		req.BindPassword = value
	}
	req = normalizeLDAPConfigRequest(req)
	password, err := s.bindPasswordForLDAPConfigRequest(req)
	if err != nil {
		return p, err
	}
	if err := validateLDAPSettings(ldapConfigFromRequest(req, password), req); err != nil {
		return p, err
	}
	p.PreparedConfig, err = ldapConfigStoreValues(req, s.storageKey)
	return p, err
}

func (s *Server) handleSecurityReconcile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := s.store.GetSecurityChange(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "security change not found")
		return
	}
	if _, err := s.securityService().AuthorityForChange(c, UserIDFromContext(r.Context()), authorization.ActionApply); err != nil {
		securityError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	c, err = s.securityService().ReconcileChange(ctx, id, s.securityTransition)
	if err != nil {
		securityError(w, err)
		return
	}
	s.endNewlyCoveredShells()
	respondJSON(w, http.StatusOK, c)
}
