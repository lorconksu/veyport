package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wyiu/veyport/hub/internal/model"
)

var errApplicationDenied = errors.New("application access denied — sign in again")

const applicationCookie = "__Host-veyport_app"

type ApplicationMembership struct {
	Groups      []string
	Role        model.Role
	Fingerprint string
	FetchedAt   time.Time
}
type ApplicationMembershipReader interface {
	LookupMembership(context.Context, *model.User) (ApplicationMembership, error)
}
type applicationDirectoryCache struct {
	mu      sync.Mutex
	entries map[string]ApplicationMembership
	flights map[string]chan struct{}
	slots   chan struct{}
}

func newApplicationDirectoryCache() *applicationDirectoryCache {
	return &applicationDirectoryCache{entries: map[string]ApplicationMembership{}, flights: map[string]chan struct{}{}, slots: make(chan struct{}, 16)}
}
func (s *Server) applicationMembership(ctx context.Context, u *model.User) (ApplicationMembership, error) {
	bounded, cancelBound := context.WithTimeout(ctx, time.Second)
	defer cancelBound()
	ctx = bounded
	key := u.ID + ":" + fmt.Sprint(u.TokenGeneration)
	c := s.applicationDirectory
	c.mu.Lock()
	if len(c.entries) >= 1024 {
		for k, v := range c.entries {
			if s.now().Sub(v.FetchedAt) > 2*time.Second {
				delete(c.entries, k)
			}
		}
	}
	if v, ok := c.entries[key]; ok && s.now().Sub(v.FetchedAt) < 2*time.Second {
		c.mu.Unlock()
		return v, nil
	}
	if ch, ok := c.flights[key]; ok {
		c.mu.Unlock()
		select {
		case <-ch:
			return s.applicationMembership(ctx, u)
		case <-ctx.Done():
			return ApplicationMembership{}, ctx.Err()
		}
	}
	select {
	case c.slots <- struct{}{}:
	default:
		c.mu.Unlock()
		return ApplicationMembership{}, errApplicationDenied
	}
	ch := make(chan struct{})
	c.flights[key] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.flights, key); close(ch); c.mu.Unlock(); <-c.slots }()
	lookup, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var v ApplicationMembership
	var e error
	if s.applicationMembershipReader != nil {
		v, e = s.applicationMembershipReader.LookupMembership(lookup, u)
	} else {
		v, e = s.lookupApplicationLDAP(lookup, u)
	}
	if e != nil {
		return v, e
	}
	if lookup.Err() != nil {
		return v, lookup.Err()
	}
	v.FetchedAt = s.now()
	sort.Strings(v.Groups)
	b, _ := json.Marshal([]any{v.Groups, v.Role})
	sum := sha256.Sum256(b)
	v.Fingerprint = hex.EncodeToString(sum[:])
	c.mu.Lock()
	if len(c.entries) < 1024 {
		c.entries[key] = v
	}
	c.mu.Unlock()
	return v, nil
}
func (s *Server) lookupApplicationLDAP(ctx context.Context, u *model.User) (ApplicationMembership, error) {
	cfg, e := s.loadLDAPConfig()
	if e != nil {
		return ApplicationMembership{}, e
	}
	if !cfg.Enabled || cfg.AllowInsecure || cfg.BindDN == "" || cfg.GroupBaseDN == "" {
		return ApplicationMembership{}, errApplicationDenied
	}
	if e = validateLDAPTransport(cfg); e != nil {
		return ApplicationMembership{}, e
	}
	a := ldapBindAuthenticator{cfg: cfg, dial: s.ldapDial}
	conn, e := a.connect()
	if e != nil {
		return ApplicationMembership{}, e
	}
	defer conn.Close()
	conn.SetTimeout(time.Second)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)
	if e = conn.Bind(cfg.BindDN, cfg.BindPassword); e != nil {
		return ApplicationMembership{}, errApplicationDenied
	}
	attrs := []string{cfg.UsernameAttribute, cfg.EmailAttribute, cfg.ExternalIDAttribute, "nsAccountLock", "pwdAccountLockedTime", "userAccountControl"}
	userResult, searchErr := conn.Search(ldap.NewSearchRequest(cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 1, false, renderLDAPFilter(cfg.UserSearchFilter, map[string]string{"username": u.LDAPUsername}), attrs, nil))
	if searchErr != nil || len(userResult.Entries) != 1 {
		return ApplicationMembership{}, errApplicationDenied
	}
	entry := userResult.Entries[0]
	if strings.EqualFold(entry.GetAttributeValue("nsAccountLock"), "true") || entry.GetAttributeValue("pwdAccountLockedTime") != "" {
		return ApplicationMembership{}, errApplicationDenied
	}
	if raw := entry.GetAttributeValue("userAccountControl"); raw != "" {
		bits, err := strconv.Atoi(raw)
		if err != nil || bits&2 != 0 {
			return ApplicationMembership{}, errApplicationDenied
		}
	}
	if u.ExternalID != "" && entry.GetAttributeValue(cfg.ExternalIDAttribute) != u.ExternalID {
		return ApplicationMembership{}, errApplicationDenied
	}
	if u.LDAPDN != "" && !strings.EqualFold(u.LDAPDN, entry.DN) {
		return ApplicationMembership{}, errApplicationDenied
	}
	filter := renderLDAPFilter(cfg.GroupSearchFilter, map[string]string{"dn": entry.DN, "username": u.LDAPUsername})
	res, e := conn.Search(ldap.NewSearchRequest(cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 500, 1, false, filter, []string{cfg.GroupNameAttribute, "entryUUID", "ipaUniqueID"}, nil))
	if e != nil || len(res.Entries) >= 500 {
		return ApplicationMembership{}, errApplicationDenied
	}
	groups := []string{}
	names := []string{}
	for _, g := range res.Entries {
		v := g.GetAttributeValue(cfg.GroupNameAttribute)
		if v == "" {
			return ApplicationMembership{}, errApplicationDenied
		}
		names = append(names, strings.ToLower(strings.TrimSpace(v)))
		groups = append(groups, applicationDirectoryGroupID(g))
	}
	role, ok := mapLDAPRole(names, s.loadLDAPGroupMappings())
	if !ok {
		role = ""
	}
	return ApplicationMembership{Groups: groups, Role: role}, nil
}
func (s *Server) applicationAuthorization(ctx context.Context, u *model.User, a *model.Application) (int64, string, error) {
	if !a.Enabled || s.accountAccessError(u) != nil || u.MustChangePassword || !u.TOTPEnabled {
		return 0, "", errApplicationDenied
	}
	grants, e := s.store.ApplicationGrants(a.ID)
	if e != nil {
		return 0, "", e
	}
	roles, e := s.store.UserRoles(u.ID)
	if e != nil {
		return 0, "", e
	}
	groups, e := s.store.ApplicationLocalMemberships(u.ID)
	if e != nil {
		return 0, "", e
	}
	var member ApplicationMembership
	var dirErr error
	needsDirectory := u.AuthProvider == model.AuthProviderLDAP
	for _, g := range grants {
		if u.AuthProvider == model.AuthProviderLDAP && (g.Kind == "role" || g.Kind == "directory_group") {
			needsDirectory = true
		}
	}
	if needsDirectory {
		member, dirErr = s.applicationMembership(ctx, u)
		if dirErr != nil {
			return 0, "", dirErr
		}
	}
	allowed := false
	for _, g := range grants {
		switch g.Kind {
		case "user":
			allowed = allowed || g.SubjectID == u.ID
		case "local_group":
			allowed = allowed || groups[g.SubjectID]
		case "role":
			for _, role := range roles {
				if u.AuthProvider == model.AuthProviderLDAP && (role == model.RoleAdmin || role == model.RoleAuditor || role == model.RoleViewer) {
					continue
				}
				allowed = allowed || string(role) == g.SubjectID
			}
			if u.AuthProvider == model.AuthProviderLDAP {
				allowed = allowed || string(member.Role) == g.SubjectID
			}
		case "directory_group":
			if u.AuthProvider == model.AuthProviderLDAP {
				for _, v := range member.Groups {
					allowed = allowed || v == g.SubjectID
				}
			}
		}
	}
	if !allowed {
		return 0, "", errApplicationDenied
	}
	revision, e := s.store.ApplicationAccessRevision(u.ID)
	return revision, member.Fingerprint, e
}
func (s *Server) checkApplicationSession(ctx context.Context, a *model.Application, ss *model.ApplicationSession, touch bool) error {
	now := s.now()
	if ss.EndedAt != nil || ss.ApplicationID != a.ID || ss.ConfigVersion != a.ConfigVersion {
		return errApplicationDenied
	}
	anchor, e := s.store.GetApplicationAnchor(ss.AnchorID)
	if e != nil || anchor.RevokedAt != nil || anchor.UserID != ss.UserID {
		return errApplicationDenied
	}
	u, e := s.store.GetUserByID(ss.UserID)
	if e != nil || u.TokenGeneration != anchor.TokenGeneration {
		return errApplicationDenied
	}
	policy := s.applicationPolicy()
	max := anchor.CompletedMFAAt.Add(time.Duration(policy.MaxSeconds) * time.Second)
	reason := ""
	if !now.Before(ss.ExpiresAt) || !now.Before(max) {
		reason = "expired_absolute"
	} else if now.Sub(ss.LastSeenAt) > time.Duration(policy.IdleSeconds)*time.Second {
		reason = "expired_idle"
	}
	if reason != "" {
		_ = s.store.EndApplicationSession(ss.ID, reason, now)
		return errApplicationDenied
	}
	revision, fingerprint, e := s.applicationAuthorization(ctx, u, a)
	if e != nil {
		// An aborted request is not evidence of directory authority loss.
		// A bounded lookup failure with a live caller fails closed permanently.
		if ctx.Err() != nil {
			return e
		}
		return errors.Join(e, s.endApplicationAccessChanged(ss.ID, now))
	}
	if revision != ss.AccessRevision || fingerprint != ss.DirectoryFingerprint {
		return errors.Join(errApplicationDenied, s.endApplicationAccessChanged(ss.ID, now))
	}
	if touch {
		return s.store.TouchApplicationSession(ss.ID, now)
	}
	return nil
}

// Authority restoration must require a new launch, never revive an old cookie.
// Close only this session's streams even if persistence is unavailable, and
// propagate write/audit failures so no successful access decision hides them.
func (s *Server) endApplicationAccessChanged(id string, now time.Time) error {
	s.applicationStreams.closeSession(id)
	if err := s.store.EndApplicationSession(id, "access_changed", now); err != nil {
		return err
	}
	return s.auditApplicationSessionEnds()
}
