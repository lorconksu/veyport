package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/model"
)

type securityPrincipal struct {
	ID          string       `json:"id"`
	Username    string       `json:"username"`
	PersonID    string       `json:"person_id"`
	Roles       []model.Role `json:"roles"`
	TOTPEnabled bool         `json:"totp_enabled"`
}

// This selector is separate from operations user administration. Its SQL never
// selects passwords, TOTP secrets, tokens, LDAP identities or account history.
func (s *Server) handleSecurityPrincipals(w http.ResponseWriter, r *http.Request) {
	effective, err := s.securityService().Effective(UserIDFromContext(r.Context()))
	if err != nil {
		securityError(w, authorization.ErrDenied)
		return
	}
	allowed := effective.Can("security.read")
	if !allowed && effective.Can("security.bootstrap") {
		enrolled, enrollmentErr := s.store.GovernanceEnrolled()
		state, stateErr := s.store.GetPolicyState()
		allowed = enrollmentErr == nil && stateErr == nil && !enrolled && state.Active.Policy.Profile == "standard"
	}
	if !allowed {
		securityError(w, authorization.ErrDenied)
		return
	}
	query := r.URL.Query()
	limit, offset := 50, 0
	for name, values := range query {
		if len(values) != 1 || (name != "limit" && name != "offset" && name != "search") {
			respondError(w, http.StatusBadRequest, "bounded principal pagination required")
			return
		}
	}
	if value := query.Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 100 {
			respondError(w, http.StatusBadRequest, "principal limit must be between 1 and 100")
			return
		}
	}
	if value := query.Get("offset"); value != "" {
		offset, err = strconv.Atoi(value)
		if err != nil || offset < 0 || offset > 1000000 {
			respondError(w, http.StatusBadRequest, "bounded principal offset required")
			return
		}
	}
	search := strings.TrimSpace(query.Get("search"))
	if len(search) > 128 || strings.ContainsAny(search, "\x00\r\n") {
		respondError(w, http.StatusBadRequest, "bounded principal search required")
		return
	}
	prefix := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(search) + "%"
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	const filter = ` WHERE (u.username LIKE ? ESCAPE '\' OR u.id = ?)`
	var total int
	if err := s.store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM users u`+filter, prefix, search).Scan(&total); err != nil {
		respondError(w, http.StatusServiceUnavailable, "principal selector unavailable")
		return
	}
	rows, err := s.store.DB().QueryContext(ctx, `SELECT u.id,u.username,COALESCE(l.person_id,''),u.totp_enabled,
		COALESCE((SELECT json_group_array(role) FROM (SELECT role FROM user_roles WHERE user_id=u.id ORDER BY role)),'[]')
		FROM users u LEFT JOIN security_identity_links l ON l.user_id=u.id`+filter+` ORDER BY u.username,u.id LIMIT ? OFFSET ?`, prefix, search, limit, offset)
	if err != nil {
		respondError(w, http.StatusServiceUnavailable, "principal selector unavailable")
		return
	}
	defer rows.Close()
	principals := []securityPrincipal{}
	for rows.Next() {
		var principal securityPrincipal
		var roles string
		if err := rows.Scan(&principal.ID, &principal.Username, &principal.PersonID, &principal.TOTPEnabled, &roles); err != nil || json.Unmarshal([]byte(roles), &principal.Roles) != nil {
			respondError(w, http.StatusServiceUnavailable, "principal selector unavailable")
			return
		}
		principals = append(principals, principal)
	}
	if rows.Err() != nil {
		respondError(w, http.StatusServiceUnavailable, "principal selector unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusOK, struct {
		Principals []securityPrincipal `json:"principals"`
		Total      int                 `json:"total"`
		Limit      int                 `json:"limit"`
		Offset     int                 `json:"offset"`
	}{principals, total, limit, offset})
}
