package server

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestApplicationDirectoryRejectsIncompleteSnapshotsAndServiceFailures(t *testing.T) {
	for _, name := range []string{"disabled", "unsafe_transport", "bad_encrypted_bind", "dial_failure", "changed_DN", "group_search_failure", "group_limit", "unnamed_group", "unmapped_role"} {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			s.stopSessionPruner()
			appDirectoryConfig(t, s)
			user := &model.User{LDAPUsername: "alice", LDAPDN: "uid=alice,dc=example", ExternalID: "identity"}
			entry := ldap.NewEntry(user.LDAPDN, map[string][]string{"uid": {"alice"}, "entryUUID": {"identity"}})
			group := ldap.NewEntry("cn=group,dc=example", map[string][]string{"cn": {"native-app-users"}, "entryUUID": {"group"}})
			conn := &fakeLDAPConn{results: []*ldap.SearchResult{{Entries: []*ldap.Entry{entry}}, {Entries: []*ldap.Entry{group}}}}
			s.SetLDAPDialer(func(LDAPConfig) (LDAPConnection, error) { return conn, nil })
			switch name {
			case "disabled":
				if err := s.store.SetConfig("ldap.enabled", "false"); err != nil {
					t.Fatal(err)
				}
			case "unsafe_transport":
				if err := s.store.SetConfig("ldap.url", "ldap://directory.example.test"); err != nil {
					t.Fatal(err)
				}
			case "bad_encrypted_bind":
				if err := s.store.SetConfig("ldap.bind_password", "enc:malformed"); err != nil {
					t.Fatal(err)
				}
			case "dial_failure":
				s.SetLDAPDialer(func(LDAPConfig) (LDAPConnection, error) { return nil, errors.New("synthetic connection failure") })
			case "changed_DN":
				entry.DN = "uid=another,dc=example"
			case "group_search_failure":
				conn.searchErrs = []error{nil, errors.New("synthetic incomplete group result")}
			case "group_limit":
				conn.results[1] = &ldap.SearchResult{Entries: make([]*ldap.Entry, 500)}
			case "unnamed_group":
				conn.results[1] = &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("cn=g", map[string][]string{"entryUUID": {"group"}})}}
			}
			member, err := s.lookupApplicationLDAP(context.Background(), user)
			if name == "unmapped_role" {
				if err != nil || member.Role != "" || len(member.Groups) != 1 {
					t.Fatal("unmapped fresh identity acquired persisted role", member, err)
				}
				return
			}
			if err == nil {
				t.Fatal("incomplete or insecure directory snapshot accepted")
			}
		})
	}
}

func TestApplicationDirectorySelectorRejectsTransportDialAndBindFailures(t *testing.T) {
	for _, name := range []string{"transport", "dial", "bind"} {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			s.stopSessionPruner()
			appDirectoryConfig(t, s)
			conn := &fakeLDAPConn{}
			s.SetLDAPDialer(func(LDAPConfig) (LDAPConnection, error) { return conn, nil })
			if name == "transport" {
				if err := s.store.SetConfig("ldap.url", "ldap://directory.example.test"); err != nil {
					t.Fatal(err)
				}
			}
			if name == "dial" {
				s.SetLDAPDialer(func(LDAPConfig) (LDAPConnection, error) { return nil, errors.New("synthetic dial unavailable") })
			}
			if name == "bind" {
				conn.bindFailures = map[string]error{"cn=service\x00service-secret": errors.New("synthetic service bind unavailable")}
			}
			response := httptest.NewRecorder()
			s.handleApplicationDirectorySubjects(response, httptest.NewRequest(http.MethodGet, "/?q=operators", nil))
			if response.Code != 503 {
				t.Fatal("directory selector exposed incomplete identities", response.Code, response.Body.String())
			}
		})
	}
}

func TestApplicationMembershipSingleFlightAndCapacityProtectDirectory(t *testing.T) {
	s := testServer(t)
	s.stopSessionPruner()
	user := &model.User{ID: "synthetic", TokenGeneration: 1}
	entered, release := make(chan struct{}), make(chan struct{})
	var lookups atomic.Int32
	s.applicationMembershipReader = applicationMemberReaderFunc(func(ctx context.Context, _ *model.User) (ApplicationMembership, error) {
		if lookups.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
			return ApplicationMembership{Role: model.RoleViewer}, nil
		case <-ctx.Done():
			return ApplicationMembership{}, ctx.Err()
		}
	})
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		if _, err := s.applicationMembership(context.Background(), user); err != nil {
			t.Error(err)
		}
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.applicationMembership(ctx, user); err == nil {
		t.Fatal("cancelled waiter accepted incomplete snapshot")
	}
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := s.applicationMembership(context.Background(), user); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	workers.Wait()
	if lookups.Load() != 1 {
		t.Fatal("concurrent membership lookup was not coalesced", lookups.Load())
	}
	for i := 0; i < cap(s.applicationDirectory.slots); i++ {
		s.applicationDirectory.slots <- struct{}{}
	}
	if _, err := s.applicationMembership(context.Background(), &model.User{ID: "other"}); err == nil {
		t.Fatal("full directory capacity accepted another lookup")
	}
	if lookups.Load() != 1 {
		t.Fatal("capacity denial opened another directory lookup")
	}
	for i := 0; i < cap(s.applicationDirectory.slots); i++ {
		<-s.applicationDirectory.slots
	}
}

func TestApplicationMembershipEvictsExpiredCacheAndRejectsLateSuccess(t *testing.T) {
	s := testServer(t)
	s.stopSessionPruner()
	now := s.now()
	for i := 0; i < 1024; i++ {
		s.applicationDirectory.entries[fmt.Sprint(i)] = ApplicationMembership{FetchedAt: now.Add(-3 * time.Second)}
	}
	s.applicationMembershipReader = applicationMemberReaderFunc(func(context.Context, *model.User) (ApplicationMembership, error) {
		return ApplicationMembership{Role: model.RoleViewer}, nil
	})
	if _, err := s.applicationMembership(context.Background(), &model.User{ID: "fresh"}); err != nil {
		t.Fatal(err)
	}
	if len(s.applicationDirectory.entries) != 1 {
		t.Fatal("expired directory cache retained stale identities", len(s.applicationDirectory.entries))
	}
	s.applicationMembershipReader = applicationMemberReaderFunc(func(ctx context.Context, _ *model.User) (ApplicationMembership, error) {
		<-ctx.Done()
		return ApplicationMembership{Role: model.RoleAdmin}, nil
	})
	if _, err := s.applicationMembership(context.Background(), &model.User{ID: "late"}); err == nil {
		t.Fatal("late successful result bypassed bounded freshness deadline")
	}
	if _, cached := s.applicationDirectory.entries["late:0"]; cached {
		t.Fatal("timed-out identity entered cache")
	}
}

func TestLDAPTransportVerifiesPrivateCAAndPeerName(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer backend.Close()
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw}))
	cfg := LDAPConfig{URL: "ldaps://" + backend.Listener.Addr().String(), CACertPEM: certificate}
	conn, err := dialLDAP(cfg)
	if err != nil {
		t.Fatal("verified private-CA LDAP TLS handshake failed", err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []LDAPConfig{{URL: cfg.URL}, {URL: cfg.URL, CACertPEM: certificate, TLSServerName: "wrong.example.test"}} {
		if conn, err = dialLDAP(bad); err == nil {
			conn.Close()
			t.Fatal("untrusted LDAP TLS peer accepted")
		}
	}
}

type applicationLDAPBindSequence struct {
	fakeLDAPConn
	failAt, calls int
}

func (c *applicationLDAPBindSequence) Bind(user, password string) error {
	c.calls++
	if c.calls == c.failAt {
		return errors.New("synthetic service bind failed")
	}
	return c.fakeLDAPConn.Bind(user, password)
}
func TestLDAPLoginServiceBindAndRebindFailuresNeverReturnIdentity(t *testing.T) {
	for _, failAt := range []int{1, 3} {
		conn := &applicationLDAPBindSequence{failAt: failAt, fakeLDAPConn: fakeLDAPConn{results: []*ldap.SearchResult{{Entries: []*ldap.Entry{ldap.NewEntry("uid=alice,dc=example", map[string][]string{"uid": {"alice"}, "entryUUID": {"identity"}})}}}}}
		a := ldapBindAuthenticator{cfg: LDAPConfig{BindDN: "cn=service", BindPassword: "synthetic", UserBaseDN: "dc=example", UserSearchFilter: "(uid={username})", UsernameAttribute: "uid", ExternalIDAttribute: "entryUUID"}, dial: func(LDAPConfig) (LDAPConnection, error) { return conn, nil }}
		if identity, err := a.Authenticate(context.Background(), "alice", "synthetic-user"); err == nil || identity.Username != "" || !conn.closed {
			t.Fatal("failed service bind returned usable identity", identity, err)
		}
	}
}
