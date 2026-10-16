package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/applicationtransport"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/proto/applicationproxy"
)

type applicationPolicy struct {
	IdleSeconds int   `json:"idle_seconds"`
	MaxSeconds  int   `json:"max_seconds"`
	Version     int64 `json:"version"`
}

func (s *Server) applicationPolicy() applicationPolicy {
	p := applicationPolicy{2700, 43200, 1}
	if b, e := s.store.GetConfig("application.policy"); e == nil {
		if e = json.Unmarshal([]byte(b), &p); e != nil || p.IdleSeconds < 60 || p.MaxSeconds < 300 {
			p = applicationPolicy{60, 300, 1}
		}
	}
	return p
}
func appPagination(r *http.Request) (int, int) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit < 1 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
func applicationSecret() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func applicationPath(raw string) (string, error) {
	if raw == "" {
		return "/", nil
	}
	if len(raw) > 4096 || raw[0] != '/' || (len(raw) > 1 && (raw[1] == '/' || raw[1] == '\\')) || strings.ContainsAny(raw, "\\\x00\r\n") {
		return "", errApplicationDenied
	}
	u, e := url.ParseRequestURI(raw)
	if e != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" {
		return "", errApplicationDenied
	}
	decoded, e := url.PathUnescape(u.EscapedPath())
	if e != nil || strings.ContainsAny(decoded, "\\\x00\r\n") || (len(decoded) > 1 && (decoded[1] == '/' || decoded[1] == '\\')) || strings.HasPrefix(decoded, "/_veyport/") {
		return "", errApplicationDenied
	}
	for _, seg := range strings.Split(decoded, "/") {
		if seg == ".." || seg == "." {
			return "", errApplicationDenied
		}
	}
	return raw, nil
}

var applicationSlug = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func applicationTarget(a *model.Application) (applicationtransport.Target, error) {
	u, e := url.Parse(a.BackendURL)
	if e != nil {
		return applicationtransport.Target{}, e
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	n, e := strconv.ParseUint(port, 10, 16)
	if e != nil {
		return applicationtransport.Target{}, e
	}
	t := applicationtransport.Target{ApplicationID: a.ID, ConfigVersion: a.ConfigVersion, NodeID: a.NodeID, Scheme: u.Scheme, Hostname: strings.ToLower(u.Hostname()), Port: uint16(n), AllowedCIDRs: append([]string(nil), a.AllowedCIDRs...)}
	return t, applicationproxy.ValidateTarget(t)
}
func (s *Server) ValidateApplicationTarget(ctx context.Context, t applicationtransport.Target) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	a, e := s.store.GetApplication(t.ApplicationID)
	if e != nil || !a.Enabled || a.ConfigVersion != t.ConfigVersion {
		return errApplicationDenied
	}
	expected, e := applicationTarget(a)
	if e != nil {
		return e
	}
	b, _ := json.Marshal(expected)
	c, _ := json.Marshal(t)
	if string(b) != string(c) {
		return errApplicationDenied
	}
	return nil
}
func (s *Server) validateApplication(a *model.Application) error {
	if s.applicationDomain == "" || s.applicationPortalOrigin == "" {
		return fmt.Errorf("application domain and portal origin must be configured")
	}
	if len(a.Name) < 1 || len(a.Name) > 120 || len(a.Description) > 1000 || !applicationSlug.MatchString(a.Slug) {
		return fmt.Errorf("invalid application name, description or slug")
	}
	a.PublicHostname = a.Slug + "." + s.applicationDomain
	if a.Route != "hub" && a.Route != "node" {
		return fmt.Errorf("route must be hub or node")
	}
	if a.Route == "node" {
		node, e := s.store.GetServerByID(a.NodeID)
		if e != nil || node.RegistrationToken != nil {
			return fmt.Errorf("select an enrolled node")
		}
	} else if a.NodeID != "" {
		return fmt.Errorf("hub route must not specify a node")
	}
	u, e := url.Parse(a.BackendURL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(a.BackendURL, "\x00\r\n\\") {
		return fmt.Errorf("backend URL must be HTTP/HTTPS with an optional path prefix, without credentials, query or fragment")
	}
	if _, e = applicationPath(u.EscapedPath()); e != nil {
		return fmt.Errorf("invalid backend path prefix")
	}
	if a.ConfigVersion < 1 {
		a.ConfigVersion = 1
	}
	if _, e = applicationTarget(a); e != nil {
		return fmt.Errorf("invalid backend target or allowed CIDRs")
	}
	if len(a.CAPEM) > 65536 {
		return fmt.Errorf("CA exceeds64KiB")
	}
	if a.CAPEM != "" {
		roots := x509.NewCertPool()
		if u.Scheme != "https" || !applicationCertificatePEM(a.CAPEM) || !roots.AppendCertsFromPEM([]byte(a.CAPEM)) {
			return fmt.Errorf("invalid HTTPS CA trust")
		}
	}
	return nil
}
func (s *Server) applicationAudit(r *http.Request, action, appID, reason string) {
	defer s.auditApplicationSessionEnds()
	detail, _ := json.Marshal(map[string]string{"application_id": appID, "reason": reason})
	uid := UserIDFromContext(r.Context())
	var user *string
	if uid != "" {
		user = &uid
	}
	outcome := model.AuditOutcomeSuccess
	if action == "application.denied" {
		outcome = model.AuditOutcomeFailure
	}
	s.auditLogRequest(r, model.AuditEntry{Action: action, UserID: user, ResourceType: stringPtr("application"), Target: &appID, Detail: stringPtr(string(detail)), Outcome: outcome})
}
func (s *Server) registerApplicationRoutes(mux *http.ServeMux) {
	user := func(h http.HandlerFunc) http.Handler {
		return s.authMiddleware(auth.TokenTypeAccess, s.interactiveOnly(h))
	}
	admin := func(h http.HandlerFunc) http.Handler { return user(s.adminOnly(h).ServeHTTP) }
	mux.Handle("GET /api/admin/application-subjects/users", admin(s.handleApplicationUserSubjects))
	mux.Handle("GET /api/admin/application-subjects/directory-groups", admin(s.handleApplicationDirectorySubjects))
	mux.Handle("GET /api/applications", user(s.handleApplications))
	mux.Handle("POST /api/applications/{id}/launch", newRateLimiter(10, time.Minute).middleware(user(s.handleApplicationLaunch)))
	mux.Handle("GET /api/admin/applications", admin(s.handleAdminApplications))
	mux.Handle("POST /api/admin/applications", admin(s.handleApplicationCreate))
	mux.Handle("GET /api/admin/applications/{id}", admin(s.handleApplicationGet))
	mux.Handle("PUT /api/admin/applications/{id}", admin(s.handleApplicationUpdate))
	mux.Handle("DELETE /api/admin/applications/{id}", admin(s.handleApplicationDelete))
	mux.Handle("GET /api/admin/applications/{id}/grants", admin(s.handleApplicationGrants))
	mux.Handle("PUT /api/admin/applications/{id}/grants", admin(s.handleApplicationGrantsUpdate))
	mux.Handle("GET /api/admin/application-groups", admin(s.handleApplicationGroups))
	mux.Handle("POST /api/admin/application-groups", admin(s.handleApplicationGroupCreate))
	mux.Handle("GET /api/admin/application-groups/{id}", admin(s.handleApplicationGroup))
	mux.Handle("PUT /api/admin/application-groups/{id}", admin(s.handleApplicationGroupUpdate))
	mux.Handle("DELETE /api/admin/application-groups/{id}", admin(s.handleApplicationGroupDelete))
	mux.Handle("GET /api/admin/application-settings", admin(s.handleApplicationSettings))
	mux.Handle("PUT /api/admin/application-settings", admin(s.handleApplicationSettingsUpdate))
	mux.Handle("GET /api/auth/application-sessions", user(s.handleApplicationSessions))
	mux.Handle("DELETE /api/auth/application-sessions/{id}", user(s.handleApplicationSessionEnd))
}
func (s *Server) handleAdminApplications(w http.ResponseWriter, r *http.Request) {
	l, o := appPagination(r)
	apps, total, e := s.store.ListApplications(l, o)
	if e != nil {
		respondError(w, 500, "cannot list applications")
		return
	}
	respondJSON(w, 200, map[string]any{"applications": apps, "total": total})
}
func (s *Server) handleApplicationCreate(w http.ResponseWriter, r *http.Request) {
	var a model.Application
	if e := decodeJSON(r, &a); e != nil {
		respondError(w, 400, errInvalidRequestBody)
		return
	}
	a.ID = uuid.NewString()
	if e := s.validateApplication(&a); e != nil {
		respondError(w, 400, e.Error())
		return
	}
	if e := s.store.CreateApplication(&a, s.now()); e != nil {
		respondError(w, 409, "application name or hostname already exists")
		return
	}
	s.applicationAudit(r, "application.created", a.ID, "")
	respondJSON(w, 201, a)
}
func (s *Server) handleApplicationGet(w http.ResponseWriter, r *http.Request) {
	a, e := s.store.GetApplication(r.PathValue("id"))
	if e != nil {
		respondError(w, 404, "application not found")
		return
	}
	respondJSON(w, 200, a)
}
func (s *Server) handleApplicationUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		model.Application
		ExpectedVersion int64 `json:"expected_version"`
	}
	if e := decodeJSON(r, &req); e != nil {
		respondError(w, 400, errInvalidRequestBody)
		return
	}
	a, e := s.store.GetApplication(r.PathValue("id"))
	if e != nil {
		respondError(w, 404, "application not found")
		return
	}
	req.ID = a.ID
	req.CreatedAt = a.CreatedAt
	if req.ExpectedVersion == 0 {
		req.ExpectedVersion = req.ConfigVersion
	}
	if e = s.validateApplication(&req.Application); e != nil {
		respondError(w, 400, e.Error())
		return
	}
	if e = s.store.UpdateApplication(&req.Application, req.ExpectedVersion, s.now()); e != nil {
		respondError(w, 409, "application changed; reload before saving")
		return
	}
	s.applicationStreams.closeApp(a.ID)
	s.applicationAudit(r, "application.updated", a.ID, "")
	respondJSON(w, 200, req.Application)
}
func (s *Server) handleApplicationDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if e := s.store.BeginApplicationDeletion(id, s.now()); e != nil {
		respondError(w, 500, "cannot end application access")
		return
	}
	s.applicationStreams.closeApp(id)
	if e := s.auditApplicationSessionEnds(); e != nil {
		respondError(w, 503, "application audit unavailable; retry deletion")
		return
	}
	if pending, e := s.store.PendingApplicationEndAudits(id); e != nil || pending > 0 {
		respondError(w, 503, "application end audits pending; retry deletion")
		return
	}
	if e := s.store.DeleteApplication(id); e != nil {
		respondError(w, 500, "cannot delete application")
		return
	}
	s.applicationStreams.closeApp(id)
	s.applicationAudit(r, "application.deleted", id, "")
	respondJSON(w, 200, map[string]string{"status": "deleted"})
}
func (s *Server) handleApplicationGrants(w http.ResponseWriter, r *http.Request) {
	a, e := s.store.GetApplication(r.PathValue("id"))
	if e != nil {
		respondError(w, 404, "application not found")
		return
	}
	g, e := s.store.ApplicationGrants(a.ID)
	if e != nil {
		respondError(w, 500, "cannot load grants")
		return
	}
	respondJSON(w, 200, map[string]any{"grants": g, "config_version": a.ConfigVersion})
}
func (s *Server) validApplicationGrants(grants []model.ApplicationGrant) bool {
	if len(grants) > 500 {
		return false
	}
	seen := map[string]bool{}
	for _, g := range grants {
		if g.SubjectID == "" || len(g.SubjectID) > 1024 || seen[g.Kind+":"+g.SubjectID] {
			return false
		}
		seen[g.Kind+":"+g.SubjectID] = true
		switch g.Kind {
		case "user":
			if _, e := s.store.GetUserByID(g.SubjectID); e != nil {
				return false
			}
		case "role":
			if !model.IsValidRole(model.Role(g.SubjectID)) && g.SubjectID != string(model.RoleSecurityOfficer) && g.SubjectID != string(model.RoleSecurityApprover) && g.SubjectID != string(model.RoleOriginalReader) {
				return false
			}
		case "local_group":
			if _, e := s.store.GetApplicationGroup(g.SubjectID); e != nil {
				return false
			}
		case "directory_group":
			if g.SubjectID != strings.ToLower(strings.TrimSpace(g.SubjectID)) || strings.ContainsAny(g.SubjectID, "\x00\r\n") {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func (s *Server) handleApplicationGrantsUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Grants          []model.ApplicationGrant `json:"grants"`
		ExpectedVersion int64                    `json:"expected_version"`
	}
	if e := decodeJSON(r, &req); e != nil || !s.validApplicationGrants(req.Grants) {
		respondError(w, 400, "invalid grants")
		return
	}
	id := r.PathValue("id")
	if e := s.store.ReplaceApplicationGrants(id, req.Grants, req.ExpectedVersion, s.now()); e != nil {
		respondError(w, 409, "application changed; reload before saving")
		return
	}
	s.applicationStreams.closeApp(id)
	s.applicationAudit(r, "application.grants_changed", id, "")
	s.handleApplicationGrants(w, r)
}
func (s *Server) handleApplicationGroups(w http.ResponseWriter, r *http.Request) {
	l, o := appPagination(r)
	g, total, e := s.store.ListApplicationGroups(l, o)
	if e != nil {
		respondError(w, 500, "cannot list groups")
		return
	}
	respondJSON(w, 200, map[string]any{"groups": g, "total": total})
}
func (s *Server) handleApplicationGroup(w http.ResponseWriter, r *http.Request) {
	g, e := s.store.GetApplicationGroup(r.PathValue("id"))
	if e != nil {
		respondError(w, 404, "group not found")
		return
	}
	respondJSON(w, 200, g)
}
func (s *Server) putApplicationGroup(w http.ResponseWriter, r *http.Request, create bool) {
	var req struct {
		Name            string   `json:"name"`
		UserIDs         []string `json:"user_ids"`
		ExpectedVersion int64    `json:"expected_version"`
	}
	if e := decodeJSON(r, &req); e != nil || req.Name == "" || len(req.Name) > 120 || len(req.UserIDs) > 500 {
		respondError(w, 400, "invalid group")
		return
	}
	id := r.PathValue("id")
	status := 200
	if create {
		id = uuid.NewString()
		req.ExpectedVersion = 0
		status = 201
	}
	g := model.ApplicationGroup{ID: id, Name: req.Name, UserIDs: req.UserIDs}
	if e := s.store.PutApplicationGroup(&g, req.ExpectedVersion); e != nil {
		respondError(w, 409, "group changed or invalid members")
		return
	}
	s.applicationAudit(r, "application.group_changed", id, "")
	respondJSON(w, status, g)
}
func (s *Server) handleApplicationGroupCreate(w http.ResponseWriter, r *http.Request) {
	s.putApplicationGroup(w, r, true)
}
func (s *Server) handleApplicationGroupUpdate(w http.ResponseWriter, r *http.Request) {
	s.putApplicationGroup(w, r, false)
}
func (s *Server) handleApplicationGroupDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if e := s.store.DeleteApplicationGroup(id); e != nil {
		respondError(w, 500, "cannot delete group")
		return
	}
	s.applicationAudit(r, "application.group_changed", id, "deleted")
	respondJSON(w, 200, map[string]string{"status": "deleted"})
}
func (s *Server) handleApplicationSettings(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, 200, s.applicationPolicy())
}
func (s *Server) handleApplicationSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		applicationPolicy
		ExpectedVersion int64 `json:"expected_version"`
	}
	if e := decodeJSON(r, &req); e != nil || req.IdleSeconds < 60 || req.MaxSeconds < 300 || req.MaxSeconds > 86400 || req.IdleSeconds > req.MaxSeconds {
		respondError(w, 400, "idle must be60s or more and maximum300..86400s")
		return
	}
	old := s.applicationPolicy()
	if old.Version != req.ExpectedVersion {
		respondError(w, 409, "policy changed")
		return
	}
	req.Version = old.Version + 1
	b, _ := json.Marshal(req.applicationPolicy)
	if e := s.store.CompareApplicationPolicy(req.ExpectedVersion, string(b)); e != nil {
		respondError(w, 409, "policy changed")
		return
	}
	s.applicationAudit(r, "application.policy_changed", "policy", "")
	respondJSON(w, 200, req.applicationPolicy)
}
func (s *Server) handleApplicationSessions(w http.ResponseWriter, r *http.Request) {
	l, o := appPagination(r)
	ss, e := s.store.ListApplicationSessions(UserIDFromContext(r.Context()), l, o)
	if e != nil {
		respondError(w, 500, "cannot list app sessions")
		return
	}
	for i := range ss {
		deadline := ss[i].LastSeenAt.Add(time.Duration(s.applicationPolicy().IdleSeconds) * time.Second)
		ss[i].IdleDeadlineAt = &deadline
	}
	total, e := s.store.CountApplicationSessions(UserIDFromContext(r.Context()))
	if e != nil {
		respondError(w, 500, "cannot count app sessions")
		return
	}
	respondJSON(w, 200, map[string]any{"sessions": ss, "total": total})
}
func (s *Server) handleApplicationSessionEnd(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ss, e := s.store.ApplicationSessionByID(id)
	if e != nil || ss.UserID != UserIDFromContext(r.Context()) {
		respondError(w, 404, "application session not found")
		return
	}
	if e = s.store.EndApplicationSession(id, "revoked_self", s.now()); e != nil {
		respondError(w, 500, "cannot revoke session")
		return
	}
	s.applicationStreams.closeSession(id)
	s.applicationAudit(r, "application.session_revoked", ss.ApplicationID, "revoked_self")
	respondJSON(w, 200, map[string]string{"status": "ended"})
}
func (s *Server) handleApplicationLaunch(w http.ResponseWriter, r *http.Request) {
	a, e := s.store.GetApplication(r.PathValue("id"))
	if e != nil {
		respondError(w, 404, "application not found")
		return
	}
	u, e := s.store.GetUserByID(UserIDFromContext(r.Context()))
	if e != nil {
		respondError(w, 403, "application unavailable")
		return
	}
	revision, fp, e := s.applicationAuthorization(r.Context(), u, a)
	if e != nil {
		respondError(w, 403, "application unavailable")
		return
	}
	source, e := s.store.GetSession(SessionIDFromContext(r.Context()))
	if e != nil || source.Kind != model.SessionKindWeb {
		respondError(w, 403, "browser login required")
		return
	}
	policy := s.applicationPolicy()
	expires := source.CreatedAt.Add(time.Duration(policy.MaxSeconds) * time.Second)
	if !s.now().Before(expires) {
		respondError(w, 401, "application maximum reached; sign in again")
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if e = decodeJSON(r, &req); e != nil {
		respondError(w, 400, errInvalidRequestBody)
		return
	}
	path, e := applicationPath(req.Path)
	if e != nil {
		respondError(w, 400, "invalid application destination")
		return
	}
	anchor := model.ApplicationAnchor{ID: source.ID, UserID: u.ID, CompletedMFAAt: source.CreatedAt, TokenGeneration: u.TokenGeneration}
	if e = s.store.EnsureApplicationAnchor(anchor); e != nil {
		respondError(w, 403, "application login revoked")
		return
	}
	ticket, e := applicationSecret()
	if e != nil {
		respondError(w, 500, "cannot create launch")
		return
	}
	deadline := s.now().Add(30 * time.Second)
	if e = s.store.CreateApplicationTicket(model.ApplicationLaunchTicket{Digest: refreshDigest(ticket), ApplicationID: a.ID, UserID: u.ID, AnchorID: anchor.ID, Hostname: a.PublicHostname, Path: path, ConfigVersion: a.ConfigVersion, AccessRevision: revision, DirectoryFingerprint: fp, ExpiresAt: deadline}); e != nil {
		respondError(w, 500, "cannot create launch")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "strict-origin")
	s.applicationAudit(r, "application.launched", a.ID, "")
	respondJSON(w, 200, map[string]any{"launch_url": "https://" + a.PublicHostname + "/_veyport/launch", "ticket": ticket, "expires_at": deadline, "path": path})
}
func (s *Server) handleApplications(w http.ResponseWriter, r *http.Request) {
	u, e := s.store.GetUserByID(UserIDFromContext(r.Context()))
	if e != nil || s.accountAccessError(u) != nil {
		respondError(w, 403, "application access denied")
		return
	}
	roles, e := s.store.UserRoles(u.ID)
	if e != nil {
		respondError(w, 500, "cannot load applications")
		return
	}
	groups, e := s.store.ApplicationLocalMemberships(u.ID)
	if e != nil {
		respondError(w, 500, "cannot load applications")
		return
	}
	claims := []model.ApplicationGrant{{Kind: "user", SubjectID: u.ID}}
	for g := range groups {
		claims = append(claims, model.ApplicationGrant{Kind: "local_group", SubjectID: g})
	}
	for _, role := range roles {
		if u.AuthProvider == model.AuthProviderLDAP && (role == model.RoleAdmin || role == model.RoleAuditor || role == model.RoleViewer) {
			continue
		}
		claims = append(claims, model.ApplicationGrant{Kind: "role", SubjectID: string(role)})
	}
	if u.AuthProvider == model.AuthProviderLDAP {
		m, e := s.applicationMembership(r.Context(), u)
		if e != nil {
			respondError(w, 503, "directory identity unavailable")
			return
		}
		{
			if m.Role != "" {
				claims = append(claims, model.ApplicationGrant{Kind: "role", SubjectID: string(m.Role)})
			}
			for _, g := range m.Groups {
				claims = append(claims, model.ApplicationGrant{Kind: "directory_group", SubjectID: g})
			}
		}
	}
	l, o := appPagination(r)
	apps, total, e := s.store.ListAuthorizedApplications(claims, l, o)
	if e != nil {
		respondError(w, 500, "cannot load applications")
		return
	}
	out := []map[string]any{}
	for _, a := range apps {
		available := s.applicationDialer != nil
		reason := ""
		if available {
			supported, online := s.applicationDialer.ApplicationAvailability(a.NodeID)
			available = supported && online
			if !supported {
				reason = "agent upgrade required"
			} else if !online {
				reason = "node offline"
			}
		} else {
			reason = "proxy unavailable"
		}
		out = append(out, map[string]any{"id": a.ID, "name": a.Name, "description": a.Description, "public_url": "https://" + a.PublicHostname, "available": available, "availability_reason": reason})
	}
	respondJSON(w, 200, map[string]any{"applications": out, "total": total})
}

// SetApplicationDialer is used after constructing HTTP/gRPC services around one registry.
func (s *Server) SetApplicationDialer(d applicationtransport.Dialer) { s.applicationDialer = d }

// Configured portal authority is fixed; request Host/forwarded headers cannot supply it.
func (s *Server) applicationPortalHost() string {
	u, e := url.Parse(s.applicationPortalOrigin)
	if e != nil {
		return ""
	}
	return u.Host
}
func (s *Server) handleApplicationUserSubjects(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if len(q) > 120 {
		respondError(w, 400, "search too long")
		return
	}
	l, o := appPagination(r)
	users, total, e := s.store.ApplicationUserSubjects(q, l, o)
	if e != nil {
		respondError(w, 500, "cannot search app user subjects")
		return
	}
	respondJSON(w, 200, map[string]any{"users": users, "total": total})
}

func applicationCertificatePEM(value string) bool {
	rest := bytes.TrimSpace([]byte(value))
	count := 0
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return false
		}
		if _, e := x509.ParseCertificate(block.Bytes); e != nil {
			return false
		}
		count++
		rest = bytes.TrimSpace(next)
	}
	return count > 0
}
