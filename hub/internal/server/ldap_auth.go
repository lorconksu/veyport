package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wyiu/aerodocs/hub/internal/auth"
	"github.com/wyiu/aerodocs/hub/internal/model"
)

type LDAPIdentity struct {
	Username   string
	Email      string
	DN         string
	ExternalID string
	Groups     []string
}

type LDAPAuthenticator interface {
	Authenticate(ctx context.Context, username, password string) (LDAPIdentity, error)
}

type LDAPConfig struct {
	Enabled             bool
	URL                 string
	BindDN              string
	BindPassword        string
	UserBaseDN          string
	UserSearchFilter    string
	GroupBaseDN         string
	GroupSearchFilter   string
	UsernameAttribute   string
	EmailAttribute      string
	ExternalIDAttribute string
	GroupNameAttribute  string
	StartTLS            bool
	TLSServerName       string
	CACertPEM           string
	AllowInsecure       bool
}

type ldapConnection interface {
	Bind(username, password string) error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
	SetTimeout(timeout time.Duration)
	StartTLS(config *tls.Config) error
}

type ldapBindAuthenticator struct {
	cfg  LDAPConfig
	dial func(LDAPConfig) (ldapConnection, error)
}

var defaultLDAPRoleGroups = map[model.Role][]string{
	model.RoleAdmin:   {"aerodocs-admins"},
	model.RoleAuditor: {"aerodocs-auditors"},
	model.RoleViewer:  {"aerodocs-viewers"},
}

var defaultLDAPTerminalGroups = []string{"aerodocs-terminal-users"}

const errInvalidLDAPCredentials = "invalid LDAP credentials"

func (s *Server) authenticateLDAPLogin(ctx context.Context, username, password string) (*model.User, error) {
	authenticator := s.ldapAuthenticator
	if authenticator == nil {
		loaded, err := s.loadLDAPAuthenticator()
		if err != nil {
			return nil, err
		}
		authenticator = loaded
	}
	if authenticator == nil {
		return nil, fmt.Errorf("LDAP authentication is not configured")
	}
	identity, err := authenticator.Authenticate(ctx, username, password)
	if err != nil {
		return nil, err
	}
	role, ok := mapLDAPRole(identity.Groups)
	if !ok {
		return nil, fmt.Errorf("LDAP user is not authorized for AeroDocs")
	}
	return s.store.UpsertLDAPUser(&model.User{
		Username:       firstNonEmpty(identity.Username, username),
		Email:          identity.Email,
		Role:           role,
		ExternalID:     identity.ExternalID,
		LDAPDN:         identity.DN,
		LDAPUsername:   firstNonEmpty(identity.Username, username),
		TerminalAccess: hasAnyLDAPGroup(identity.Groups, defaultLDAPTerminalGroups),
	})
}

func (s *Server) loadLDAPAuthenticator() (LDAPAuthenticator, error) {
	cfg, err := s.loadLDAPConfig()
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.URL == "" || cfg.UserBaseDN == "" {
		return nil, fmt.Errorf("LDAP configuration is incomplete")
	}
	if err := validateLDAPTransport(cfg); err != nil {
		return nil, err
	}
	return &ldapBindAuthenticator{cfg: cfg}, nil
}

func (s *Server) loadLDAPConfig() (LDAPConfig, error) {
	cfg := LDAPConfig{
		UserSearchFilter:    "(uid={username})",
		GroupSearchFilter:   "(|(member={dn})(memberUid={username}))",
		UsernameAttribute:   "uid",
		EmailAttribute:      "mail",
		ExternalIDAttribute: "entryUUID",
		GroupNameAttribute:  "cn",
	}
	cfg.Enabled = s.configBool("ldap.enabled")
	cfg.URL = s.configString("ldap.url")
	cfg.BindDN = s.configString("ldap.bind_dn")
	cfg.BindPassword = s.configString("ldap.bind_password")
	if cfg.BindPassword != "" {
		decrypted, err := decryptConfigSecret(s.jwtSecret, cfg.BindPassword)
		if err != nil {
			return LDAPConfig{}, fmt.Errorf("decrypt LDAP bind password: %w", err)
		}
		cfg.BindPassword = decrypted
	}
	cfg.UserBaseDN = s.configString("ldap.user_base_dn")
	cfg.GroupBaseDN = s.configString("ldap.group_base_dn")
	cfg.UserSearchFilter = firstNonEmpty(s.configString("ldap.user_search_filter"), cfg.UserSearchFilter)
	cfg.GroupSearchFilter = firstNonEmpty(s.configString("ldap.group_search_filter"), cfg.GroupSearchFilter)
	cfg.UsernameAttribute = firstNonEmpty(s.configString("ldap.username_attribute"), cfg.UsernameAttribute)
	cfg.EmailAttribute = firstNonEmpty(s.configString("ldap.email_attribute"), cfg.EmailAttribute)
	cfg.ExternalIDAttribute = firstNonEmpty(s.configString("ldap.external_id_attribute"), cfg.ExternalIDAttribute)
	cfg.GroupNameAttribute = firstNonEmpty(s.configString("ldap.group_name_attribute"), cfg.GroupNameAttribute)
	cfg.StartTLS = s.configBool("ldap.start_tls")
	cfg.TLSServerName = s.configString("ldap.tls_server_name")
	cfg.CACertPEM = s.configString("ldap.ca_cert_pem")
	cfg.AllowInsecure = s.configBool("ldap.allow_insecure_transport")
	return cfg, nil
}

func (s *Server) configString(key string) string {
	value, ok, err := s.store.LookupConfig(key)
	if err != nil || !ok {
		return ""
	}
	return value
}

func (s *Server) configBool(key string) bool {
	value := strings.ToLower(strings.TrimSpace(s.configString(key)))
	return value == "true" || value == "1" || value == "yes" || value == "on"
}

func (a *ldapBindAuthenticator) Authenticate(_ context.Context, username, password string) (LDAPIdentity, error) {
	if strings.TrimSpace(username) == "" || password == "" {
		return LDAPIdentity{}, fmt.Errorf(errInvalidLDAPCredentials)
	}

	conn, err := a.connect()
	if err != nil {
		return LDAPIdentity{}, fmt.Errorf("connect LDAP: %w", err)
	}
	defer conn.Close()
	conn.SetTimeout(10 * time.Second)

	if a.cfg.BindDN != "" {
		if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
			return LDAPIdentity{}, fmt.Errorf("bind LDAP service account: %w", err)
		}
	}

	userEntry, err := a.findUser(conn, username)
	if err != nil {
		return LDAPIdentity{}, err
	}
	if err := conn.Bind(userEntry.DN, password); err != nil {
		return LDAPIdentity{}, fmt.Errorf(errInvalidLDAPCredentials)
	}
	if a.cfg.BindDN != "" {
		if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
			return LDAPIdentity{}, fmt.Errorf("rebind LDAP service account: %w", err)
		}
	}

	ldapUsername := firstNonEmpty(userEntry.GetAttributeValue(a.cfg.UsernameAttribute), username)
	identity := LDAPIdentity{
		Username:   ldapUsername,
		Email:      userEntry.GetAttributeValue(a.cfg.EmailAttribute),
		DN:         userEntry.DN,
		ExternalID: userEntry.GetAttributeValue(a.cfg.ExternalIDAttribute),
		Groups:     a.findGroups(conn, userEntry.DN, ldapUsername),
	}
	return identity, nil
}

func (a *ldapBindAuthenticator) connect() (ldapConnection, error) {
	if a.dial != nil {
		return a.dial(a.cfg)
	}
	return dialLDAP(a.cfg)
}

func dialLDAP(cfg LDAPConfig) (ldapConnection, error) {
	tlsConfig, err := buildLDAPTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, err
	}
	if cfg.StartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func validateLDAPTransport(cfg LDAPConfig) error {
	if cfg.AllowInsecure {
		return nil
	}
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return fmt.Errorf("invalid LDAP URL")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "ldaps":
		return nil
	case "ldap":
		if cfg.StartTLS {
			return nil
		}
		return fmt.Errorf("LDAP secure transport required: use ldaps:// or ldap.start_tls=true")
	default:
		return fmt.Errorf("unsupported LDAP URL scheme")
	}
}

func buildLDAPTLSConfig(cfg LDAPConfig) (*tls.Config, error) {
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid LDAP URL")
	}
	serverName := firstNonEmpty(cfg.TLSServerName, parsed.Hostname())
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
	if cfg.CACertPEM == "" {
		return tlsConfig, nil
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cfg.CACertPEM)) {
		return nil, fmt.Errorf("invalid LDAP CA certificate")
	}
	tlsConfig.RootCAs = roots
	return tlsConfig, nil
}

func (a *ldapBindAuthenticator) findUser(conn ldapConnection, username string) (*ldap.Entry, error) {
	filter := renderLDAPFilter(a.cfg.UserSearchFilter, map[string]string{
		"username": username,
	})
	attrs := []string{a.cfg.UsernameAttribute, a.cfg.EmailAttribute, a.cfg.ExternalIDAttribute}
	result, err := conn.Search(ldap.NewSearchRequest(
		a.cfg.UserBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		10,
		false,
		filter,
		attrs,
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("search LDAP user: %w", err)
	}
	if len(result.Entries) != 1 {
		return nil, fmt.Errorf(errInvalidLDAPCredentials)
	}
	return result.Entries[0], nil
}

func (a *ldapBindAuthenticator) findGroups(conn ldapConnection, userDN, username string) []string {
	if a.cfg.GroupBaseDN == "" {
		return nil
	}
	filter := renderLDAPFilter(a.cfg.GroupSearchFilter, map[string]string{
		"dn":       userDN,
		"username": username,
	})
	result, err := conn.Search(ldap.NewSearchRequest(
		a.cfg.GroupBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		10,
		false,
		filter,
		[]string{a.cfg.GroupNameAttribute},
		nil,
	))
	if err != nil {
		return nil
	}
	groups := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		if group := entry.GetAttributeValue(a.cfg.GroupNameAttribute); group != "" {
			groups = append(groups, group)
		}
	}
	return groups
}

func renderLDAPFilter(template string, values map[string]string) string {
	rendered := template
	for key, value := range values {
		rendered = strings.ReplaceAll(rendered, "{"+key+"}", ldap.EscapeFilter(value))
	}
	return rendered
}

func encryptConfigSecret(jwtSecret, secret string) (string, error) {
	key := auth.DeriveKey(jwtSecret)
	encrypted, err := auth.Encrypt([]byte(secret), key)
	if err != nil {
		return "", err
	}
	return "enc:" + hex.EncodeToString(encrypted), nil
}

func decryptConfigSecret(jwtSecret, stored string) (string, error) {
	if !strings.HasPrefix(stored, "enc:") {
		return stored, nil
	}
	data, err := hex.DecodeString(stored[4:])
	if err != nil {
		return "", fmt.Errorf("invalid encrypted secret format: %w", err)
	}
	key := auth.DeriveKey(jwtSecret)
	decrypted, err := auth.Decrypt(data, key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func mapLDAPRole(groups []string) (model.Role, bool) {
	for _, role := range []model.Role{model.RoleAdmin, model.RoleAuditor, model.RoleViewer} {
		if hasAnyLDAPGroup(groups, defaultLDAPRoleGroups[role]) {
			return role, true
		}
	}
	return "", false
}

func hasAnyLDAPGroup(groups, allowed []string) bool {
	groupSet := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		groupSet[group] = struct{}{}
	}
	for _, group := range allowed {
		if _, ok := groupSet[group]; ok {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
