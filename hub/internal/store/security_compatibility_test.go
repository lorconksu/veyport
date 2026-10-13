package store_test

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

func TestDeletedOrdinaryLDAPPrincipalCanReprovisionStableSubject(t *testing.T) {
	s := testStore(t)
	first, err := s.UpsertLDAPUser(&model.User{ID: "old-ldap-user", Username: "directory-user", Email: "directory-user@test.invalid", ExternalID: "immutable-directory-subject", Role: model.RoleViewer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec("INSERT INTO audit_logs(id,user_id,action,detail) VALUES('directory-history',?,'test.history',?)", first.ID, first.Username); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(first.ID); err != nil {
		t.Fatal(err)
	}
	second, err := s.UpsertLDAPUser(&model.User{ID: "new-ldap-user", Username: "directory-user", Email: "directory-user@test.invalid", ExternalID: "immutable-directory-subject", Role: model.RoleViewer})
	if err != nil || second.ID == first.ID {
		t.Fatalf("deleted live identity blocked directory reprovision: %+v %v", second, err)
	}
	var persons, oldLinks, history int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM security_persons WHERE id=?", "user:"+first.ID).Scan(&persons); err != nil {
		t.Fatal(err)
	}
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM security_identity_links WHERE user_id=?", first.ID).Scan(&oldLinks); err != nil {
		t.Fatal(err)
	}
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM audit_logs WHERE id='directory-history' AND user_id IS NULL AND detail=?", first.Username).Scan(&history); err != nil {
		t.Fatal(err)
	}
	if persons != 1 || oldLinks != 0 || history != 1 {
		t.Fatalf("deletion lost history or retained live identity: persons=%d links=%d history=%d", persons, oldLinks, history)
	}
}
