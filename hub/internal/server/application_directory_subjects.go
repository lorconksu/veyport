package server

import (
	"encoding/hex"
	ldap "github.com/go-ldap/ldap/v3"
	"net/http"
	"strings"
	"time"
)

func applicationDirectoryGroupID(entry *ldap.Entry) string {
	for _, name := range []string{"entryUUID", "ipaUniqueID"} {
		if id := entry.GetAttributeValue(name); id != "" {
			return "ldap:" + strings.ToLower(id)
		}
	}
	return "ldap-dn:" + hex.EncodeToString([]byte(strings.ToLower(entry.DN)))
}
func (s *Server) handleApplicationDirectorySubjects(w http.ResponseWriter, r *http.Request) {
	cfg, e := s.loadLDAPConfig()
	if e != nil || !cfg.Enabled || cfg.AllowInsecure || cfg.BindDN == "" || cfg.GroupBaseDN == "" {
		respondError(w, 503, "secure directory group lookup unavailable")
		return
	}
	if e = validateLDAPTransport(cfg); e != nil {
		respondError(w, 503, "secure directory group lookup unavailable")
		return
	}
	q := r.URL.Query().Get("q")
	if len(q) > 120 {
		respondError(w, 400, "search too long")
		return
	}
	a := ldapBindAuthenticator{cfg: cfg, dial: s.ldapDial}
	conn, e := a.connect()
	if e != nil {
		respondError(w, 503, "directory unavailable")
		return
	}
	defer conn.Close()
	conn.SetTimeout(time.Second)
	if e = conn.Bind(cfg.BindDN, cfg.BindPassword); e != nil {
		respondError(w, 503, "directory unavailable")
		return
	}
	filter := "(" + cfg.GroupNameAttribute + "=*" + ldap.EscapeFilter(q) + "*)"
	res, e := conn.Search(ldap.NewSearchRequest(cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 101, 1, false, filter, []string{cfg.GroupNameAttribute, "entryUUID", "ipaUniqueID"}, nil))
	if e != nil {
		respondError(w, 503, "directory result exceeds bound or lookup failed; narrow search")
		return
	}
	if len(res.Entries) > 100 {
		respondError(w, 400, "narrow directory search to100 groups")
		return
	}
	out := []map[string]string{}
	for _, entry := range res.Entries {
		out = append(out, map[string]string{"subject_id": applicationDirectoryGroupID(entry), "name": entry.GetAttributeValue(cfg.GroupNameAttribute)})
	}
	respondJSON(w, 200, map[string]any{"groups": out, "total": len(out)})
}
