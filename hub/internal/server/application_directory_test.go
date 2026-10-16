package server

import (
	"context"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/wyiu/veyport/hub/internal/model"
	"net/http/httptest"
	"strings"
	"testing"
)

func appDirectoryConfig(t *testing.T, s *Server) {
	t.Helper()
	for k, v := range map[string]string{"ldap.enabled": "true", "ldap.url": "ldaps://directory.example.test", "ldap.bind_dn": "cn=service", "ldap.bind_password": "service-secret", "ldap.user_base_dn": "dc=example", "ldap.group_base_dn": "cn=groups,dc=example"} {
		if e := s.store.SetConfig(k, v); e != nil {
			t.Fatal(e)
		}
	}
}
func TestApplicationLDAPServiceIdentityAndCanonicalGroups(t *testing.T) {
	s := testServer(t)
	appDirectoryConfig(t, s)
	user := &model.User{LDAPUsername: "alice", LDAPDN: "uid=alice,dc=example", ExternalID: "user-uuid"}
	entry := ldap.NewEntry(user.LDAPDN, map[string][]string{"uid": {"alice"}, "entryUUID": {"user-uuid"}})
	group := ldap.NewEntry("cn=viewers,cn=groups,dc=example", map[string][]string{"cn": {"veyport-viewers"}, "entryUUID": {"group-uuid"}})
	conn := &fakeLDAPConn{results: []*ldap.SearchResult{{Entries: []*ldap.Entry{entry}}, {Entries: []*ldap.Entry{group}}}}
	s.SetLDAPDialer(func(LDAPConfig) (LDAPConnection, error) { return conn, nil })
	member, e := s.lookupApplicationLDAP(context.Background(), user)
	if e != nil || member.Role != model.RoleViewer || len(member.Groups) != 1 || member.Groups[0] != "ldap:group-uuid" {
		t.Fatal("directory snapshot", member, e)
	}
	if len(conn.binds) != 1 || conn.binds[0] != "cn=service\x00service-secret" {
		t.Fatal("lookup used user credentials")
	}
	if !conn.closed {
		t.Fatal("directory socket not closed")
	}
	if id := applicationDirectoryGroupID(ldap.NewEntry("CN=Fallback,DC=Example", nil)); !strings.HasPrefix(id, "ldap-dn:") {
		t.Fatal("missing canonical fallback")
	}
	if id := applicationDirectoryGroupID(ldap.NewEntry("cn=g", map[string][]string{"ipaUniqueID": {"IPA-ID"}})); id != "ldap:ipa-id" {
		t.Fatal(id)
	}
	for _, tc := range []struct {
		attributes map[string][]string
		error      bool
	}{{map[string][]string{"nsAccountLock": {"TRUE"}}, true}, {map[string][]string{"pwdAccountLockedTime": {"000001010000Z"}}, true}, {map[string][]string{"userAccountControl": {"514"}}, true}, {map[string][]string{"userAccountControl": {"bad"}}, true}, {map[string][]string{"entryUUID": {"different"}}, true}} {
		attrs := map[string][]string{"uid": {"alice"}, "entryUUID": {"user-uuid"}}
		for k, v := range tc.attributes {
			attrs[k] = v
		}
		conn = &fakeLDAPConn{results: []*ldap.SearchResult{{Entries: []*ldap.Entry{ldap.NewEntry(user.LDAPDN, attrs)}}}}
		if _, e = s.lookupApplicationLDAP(context.Background(), user); e == nil {
			t.Fatalf("disabled/ambiguous identity accepted %v", tc.attributes)
		}
	}
	conn = &fakeLDAPConn{searchErr: fmt.Errorf("search truncated")}
	if _, e = s.lookupApplicationLDAP(context.Background(), user); e == nil {
		t.Fatal("failed search accepted")
	}
	conn = &fakeLDAPConn{bindFailures: map[string]error{"cn=service\x00service-secret": fmt.Errorf("bind failed")}}
	if _, e = s.lookupApplicationLDAP(context.Background(), user); e == nil {
		t.Fatal("failed service bind accepted")
	}
}
func TestApplicationDirectoryGroupSelectorIsBoundedAndUsesStableIDs(t *testing.T) {
	s := testServer(t)
	appDirectoryConfig(t, s)
	conn := &fakeLDAPConn{results: []*ldap.SearchResult{{Entries: []*ldap.Entry{ldap.NewEntry("cn=g,dc=example", map[string][]string{"cn": {"Operators"}, "entryUUID": {"group-uuid"}})}}}}
	s.SetLDAPDialer(func(LDAPConfig) (LDAPConnection, error) { return conn, nil })
	w := httptest.NewRecorder()
	s.handleApplicationDirectorySubjects(w, httptest.NewRequest("GET", "/api/admin/application-subjects/directory-groups?q=Ops", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "ldap:group-uuid") || !strings.Contains(w.Body.String(), "Operators") {
		t.Fatal(w.Code, w.Body.String())
	}
	if conn.searches[0].SizeLimit != 101 {
		t.Fatal("unbounded group lookup")
	}
	conn = &fakeLDAPConn{searchErr: fmt.Errorf("size limit")}
	w = httptest.NewRecorder()
	s.handleApplicationDirectorySubjects(w, httptest.NewRequest("GET", "/?q=x", nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	conn = &fakeLDAPConn{results: []*ldap.SearchResult{{Entries: make([]*ldap.Entry, 101)}}}
	w = httptest.NewRecorder()
	s.handleApplicationDirectorySubjects(w, httptest.NewRequest("GET", "/?q=x", nil))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	s.handleApplicationDirectorySubjects(w, httptest.NewRequest("GET", "/?q="+strings.Repeat("x", 121), nil))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}
