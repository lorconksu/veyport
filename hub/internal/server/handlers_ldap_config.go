package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

type ldapConfigResponse struct {
	Enabled             bool     `json:"enabled"`
	URL                 string   `json:"url"`
	BindDN              string   `json:"bind_dn"`
	BindPassword        string   `json:"bind_password"`
	BindPasswordSet     bool     `json:"bind_password_set"`
	UserBaseDN          string   `json:"user_base_dn"`
	GroupBaseDN         string   `json:"group_base_dn"`
	UserSearchFilter    string   `json:"user_search_filter"`
	GroupSearchFilter   string   `json:"group_search_filter"`
	UsernameAttribute   string   `json:"username_attribute"`
	EmailAttribute      string   `json:"email_attribute"`
	ExternalIDAttribute string   `json:"external_id_attribute"`
	GroupNameAttribute  string   `json:"group_name_attribute"`
	StartTLS            bool     `json:"start_tls"`
	TLSServerName       string   `json:"tls_server_name"`
	CACertPEM           string   `json:"ca_cert_pem"`
	AllowInsecure       bool     `json:"allow_insecure_transport"`
	AdminGroups         []string `json:"admin_groups"`
	AuditorGroups       []string `json:"auditor_groups"`
	ViewerGroups        []string `json:"viewer_groups"`
	TerminalGroups      []string `json:"terminal_groups"`
}

type ldapConfigRequest struct {
	Enabled             bool     `json:"enabled"`
	URL                 string   `json:"url"`
	BindDN              string   `json:"bind_dn"`
	BindPassword        string   `json:"bind_password"`
	ClearBindPassword   bool     `json:"clear_bind_password"`
	UserBaseDN          string   `json:"user_base_dn"`
	GroupBaseDN         string   `json:"group_base_dn"`
	UserSearchFilter    string   `json:"user_search_filter"`
	GroupSearchFilter   string   `json:"group_search_filter"`
	UsernameAttribute   string   `json:"username_attribute"`
	EmailAttribute      string   `json:"email_attribute"`
	ExternalIDAttribute string   `json:"external_id_attribute"`
	GroupNameAttribute  string   `json:"group_name_attribute"`
	StartTLS            bool     `json:"start_tls"`
	TLSServerName       string   `json:"tls_server_name"`
	CACertPEM           string   `json:"ca_cert_pem"`
	AllowInsecure       bool     `json:"allow_insecure_transport"`
	AdminGroups         []string `json:"admin_groups"`
	AuditorGroups       []string `json:"auditor_groups"`
	ViewerGroups        []string `json:"viewer_groups"`
	TerminalGroups      []string `json:"terminal_groups"`
}

func (s *Server) handleGetLDAPConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadLDAPConfig()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load LDAP configuration")
		return
	}
	mappings := s.loadLDAPGroupMappings()
	bindPassword, bindPasswordSet, err := s.store.LookupConfig("ldap.bind_password")
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load LDAP bind password state")
		return
	}
	bindPasswordSet = bindPasswordSet && bindPassword != ""

	respondJSON(w, http.StatusOK, ldapConfigResponse{
		Enabled:             cfg.Enabled,
		URL:                 cfg.URL,
		BindDN:              cfg.BindDN,
		BindPassword:        "",
		BindPasswordSet:     bindPasswordSet,
		UserBaseDN:          cfg.UserBaseDN,
		GroupBaseDN:         cfg.GroupBaseDN,
		UserSearchFilter:    cfg.UserSearchFilter,
		GroupSearchFilter:   cfg.GroupSearchFilter,
		UsernameAttribute:   cfg.UsernameAttribute,
		EmailAttribute:      cfg.EmailAttribute,
		ExternalIDAttribute: cfg.ExternalIDAttribute,
		GroupNameAttribute:  cfg.GroupNameAttribute,
		StartTLS:            cfg.StartTLS,
		TLSServerName:       cfg.TLSServerName,
		CACertPEM:           cfg.CACertPEM,
		AllowInsecure:       cfg.AllowInsecure,
		AdminGroups:         mappings.RoleGroups[model.RoleAdmin],
		AuditorGroups:       mappings.RoleGroups[model.RoleAuditor],
		ViewerGroups:        mappings.RoleGroups[model.RoleViewer],
		TerminalGroups:      mappings.TerminalGroups,
	})
}

func (s *Server) handleUpdateLDAPConfig(w http.ResponseWriter, r *http.Request) {
	var req ldapConfigRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	req = normalizeLDAPConfigRequest(req)
	bindPassword, err := s.bindPasswordForLDAPConfigRequest(req)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load existing LDAP bind password")
		return
	}
	cfg := ldapConfigFromRequest(req, bindPassword)
	if err := validateLDAPSettings(cfg, req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	configs, err := ldapConfigStoreValues(req, s.jwtSecret)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to encrypt LDAP bind password")
		return
	}
	if err := s.saveLDAPConfigValues(configs); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to save LDAP configuration")
		return
	}

	detail := ldapConfigAuditDetail(req)
	userID := UserIDFromContext(r.Context())
	s.auditLogRequest(r, model.AuditEntry{
		UserID:       &userID,
		Action:       model.AuditLDAPConfigUpdated,
		Detail:       &detail,
		Outcome:      model.AuditOutcomeSuccess,
		ActorType:    model.AuditActorTypeUser,
		ResourceType: stringPtr("ldap_config"),
	})

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleTestLDAPConfig(w http.ResponseWriter, r *http.Request) {
	var req ldapConfigRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}
	req = normalizeLDAPConfigRequest(req)

	bindPassword := req.BindPassword
	if bindPassword == "" || bindPassword == redactedValue {
		current, err := s.loadLDAPConfig()
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to load existing LDAP bind password")
			return
		}
		bindPassword = current.BindPassword
	}
	cfg := ldapConfigFromRequest(req, bindPassword)
	if err := validateLDAPSettings(cfg, req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.testLDAPConnection(cfg); err != nil {
		respondError(w, http.StatusBadGateway, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func normalizeLDAPConfigRequest(req ldapConfigRequest) ldapConfigRequest {
	req.URL = strings.TrimSpace(req.URL)
	req.BindDN = strings.TrimSpace(req.BindDN)
	req.UserBaseDN = strings.TrimSpace(req.UserBaseDN)
	req.GroupBaseDN = strings.TrimSpace(req.GroupBaseDN)
	req.UserSearchFilter = firstNonEmpty(strings.TrimSpace(req.UserSearchFilter), "(uid={username})")
	req.GroupSearchFilter = firstNonEmpty(strings.TrimSpace(req.GroupSearchFilter), "(|(member={dn})(memberUid={username}))")
	req.UsernameAttribute = firstNonEmpty(strings.TrimSpace(req.UsernameAttribute), "uid")
	req.EmailAttribute = firstNonEmpty(strings.TrimSpace(req.EmailAttribute), "mail")
	req.ExternalIDAttribute = firstNonEmpty(strings.TrimSpace(req.ExternalIDAttribute), "entryUUID")
	req.GroupNameAttribute = firstNonEmpty(strings.TrimSpace(req.GroupNameAttribute), "cn")
	req.TLSServerName = strings.TrimSpace(req.TLSServerName)
	req.CACertPEM = strings.TrimSpace(req.CACertPEM)
	req.AdminGroups = normalizeLDAPGroupList(req.AdminGroups)
	req.AuditorGroups = normalizeLDAPGroupList(req.AuditorGroups)
	req.ViewerGroups = normalizeLDAPGroupList(req.ViewerGroups)
	req.TerminalGroups = normalizeLDAPGroupList(req.TerminalGroups)
	return req
}

func (s *Server) bindPasswordForLDAPConfigRequest(req ldapConfigRequest) (string, error) {
	if req.ClearBindPassword || (req.BindPassword != "" && req.BindPassword != redactedValue) {
		return "", nil
	}
	current, err := s.loadLDAPConfig()
	if err != nil {
		return "", err
	}
	return current.BindPassword, nil
}

func ldapConfigFromRequest(req ldapConfigRequest, bindPassword string) LDAPConfig {
	if req.BindPassword != "" && req.BindPassword != redactedValue {
		bindPassword = req.BindPassword
	}
	if req.ClearBindPassword {
		bindPassword = ""
	}
	return LDAPConfig{
		Enabled:             req.Enabled,
		URL:                 req.URL,
		BindDN:              req.BindDN,
		BindPassword:        bindPassword,
		UserBaseDN:          req.UserBaseDN,
		GroupBaseDN:         req.GroupBaseDN,
		UserSearchFilter:    req.UserSearchFilter,
		GroupSearchFilter:   req.GroupSearchFilter,
		UsernameAttribute:   req.UsernameAttribute,
		EmailAttribute:      req.EmailAttribute,
		ExternalIDAttribute: req.ExternalIDAttribute,
		GroupNameAttribute:  req.GroupNameAttribute,
		StartTLS:            req.StartTLS,
		TLSServerName:       req.TLSServerName,
		CACertPEM:           req.CACertPEM,
		AllowInsecure:       req.AllowInsecure,
	}
}

func validateLDAPSettings(cfg LDAPConfig, req ldapConfigRequest) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.URL == "" {
		return fmt.Errorf("LDAP URL is required when LDAP is enabled")
	}
	if cfg.UserBaseDN == "" {
		return fmt.Errorf("LDAP user base DN is required when LDAP is enabled")
	}
	if cfg.GroupBaseDN == "" {
		return fmt.Errorf("LDAP group base DN is required when LDAP is enabled")
	}
	if cfg.BindDN != "" && cfg.BindPassword == "" {
		return fmt.Errorf("LDAP bind password is required when bind DN is set")
	}
	if len(req.AdminGroups)+len(req.AuditorGroups)+len(req.ViewerGroups) == 0 {
		return fmt.Errorf("at least one LDAP role group is required when LDAP is enabled")
	}
	if err := validateLDAPGroupMappings(req); err != nil {
		return err
	}
	if err := validateLDAPTransport(cfg); err != nil {
		return err
	}
	if _, err := buildLDAPTLSConfig(cfg); err != nil {
		return err
	}
	return nil
}

func validateLDAPGroupMappings(req ldapConfigRequest) error {
	for _, groups := range [][]string{req.AdminGroups, req.AuditorGroups, req.ViewerGroups, req.TerminalGroups} {
		if len(groups) > 64 {
			return fmt.Errorf("LDAP group mappings cannot contain more than 64 groups per field")
		}
		for _, group := range groups {
			if len(group) > 255 {
				return fmt.Errorf("LDAP group names cannot exceed 255 characters")
			}
		}
	}
	return nil
}

func ldapConfigStoreValues(req ldapConfigRequest, jwtSecret string) (map[string]string, error) {
	configs := map[string]string{
		"ldap.enabled":                  strconv.FormatBool(req.Enabled),
		"ldap.url":                      req.URL,
		"ldap.bind_dn":                  req.BindDN,
		"ldap.user_base_dn":             req.UserBaseDN,
		"ldap.group_base_dn":            req.GroupBaseDN,
		"ldap.user_search_filter":       req.UserSearchFilter,
		"ldap.group_search_filter":      req.GroupSearchFilter,
		"ldap.username_attribute":       req.UsernameAttribute,
		"ldap.email_attribute":          req.EmailAttribute,
		"ldap.external_id_attribute":    req.ExternalIDAttribute,
		"ldap.group_name_attribute":     req.GroupNameAttribute,
		"ldap.start_tls":                strconv.FormatBool(req.StartTLS),
		"ldap.tls_server_name":          req.TLSServerName,
		"ldap.ca_cert_pem":              req.CACertPEM,
		"ldap.allow_insecure_transport": strconv.FormatBool(req.AllowInsecure),
		"ldap.admin_groups":             ldapGroupListStoreValue(req.AdminGroups),
		"ldap.auditor_groups":           ldapGroupListStoreValue(req.AuditorGroups),
		"ldap.viewer_groups":            ldapGroupListStoreValue(req.ViewerGroups),
		"ldap.terminal_groups":          ldapGroupListStoreValue(req.TerminalGroups),
	}
	if req.ClearBindPassword {
		configs["ldap.bind_password"] = ""
	} else if req.BindPassword != "" && req.BindPassword != redactedValue {
		encrypted, err := encryptConfigSecret(jwtSecret, req.BindPassword)
		if err != nil {
			return nil, err
		}
		configs["ldap.bind_password"] = encrypted
	}
	return configs, nil
}

func ldapGroupListStoreValue(groups []string) string {
	if groups == nil {
		groups = []string{}
	}
	b, err := json.Marshal(groups)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func (s *Server) saveLDAPConfigValues(configs map[string]string) error {
	tx, err := s.store.DB().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range configs {
		if _, err := tx.Exec("INSERT INTO _config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Server) testLDAPConnection(cfg LDAPConfig) error {
	dial := s.ldapDial
	if dial == nil {
		dial = dialLDAP
	}
	conn, err := dial(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()
	conn.SetTimeout(10 * time.Second)
	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			return fmt.Errorf("failed to bind LDAP service account: %w", err)
		}
	}
	return nil
}

func ldapConfigAuditDetail(req ldapConfigRequest) string {
	detail := map[string]interface{}{
		"enabled":             req.Enabled,
		"url":                 req.URL,
		"start_tls":           req.StartTLS,
		"allow_insecure":      req.AllowInsecure,
		"admin_groups":        req.AdminGroups,
		"auditor_groups":      req.AuditorGroups,
		"viewer_groups":       req.ViewerGroups,
		"terminal_groups":     req.TerminalGroups,
		"bind_password_set":   req.BindPassword != "" && req.BindPassword != redactedValue,
		"bind_password_clear": req.ClearBindPassword,
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return "{}"
	}
	return string(b)
}
