package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestDisablePermanentlyRevokesSSHGeneration(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "actor", "actor", model.RoleAdmin)
	u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
	secret := "enrolled"
	if err := s.UpdateUserTOTP(u.ID, &secret, true); err != nil {
		t.Fatal(err)
	}
	u = mustGetUser(t, s, u.ID)
	if !s.TerminalCredentialLive(context.Background(), u.ID, u.SSHCredentialGeneration, true) {
		t.Fatal("original certificate generation was never live")
	}
	for round := 1; round <= 2; round++ {
		if _, err := s.DisableUser(u.ID, "actor", time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DisableUser(u.ID, "actor", time.Now()); !errors.Is(err, store.ErrAlreadyDisabled) {
			t.Fatalf("duplicate disable: %v", err)
		}
		if _, err := s.EnableUser(u.ID, time.Now()); err != nil {
			t.Fatal(err)
		}
		live := mustGetUser(t, s, u.ID)
		if live.SSHCredentialGeneration != u.SSHCredentialGeneration+round || live.TokenGeneration != u.TokenGeneration+round || live.DisabledAt != nil || !live.TOTPEnabled {
			t.Fatal("disable/enable did not atomically advance both generations")
		}
		if s.TerminalCredentialLive(context.Background(), u.ID, u.SSHCredentialGeneration, true) {
			t.Fatal("enable revived pre-disable SSH credentials")
		}
		if !s.TerminalCredentialLive(context.Background(), u.ID, live.SSHCredentialGeneration, true) {
			t.Fatal("enable prevented fresh certificate use")
		}
	}
}

func TestDisableSSHGenerationRollsBackWithTokenRevocation(t *testing.T) {
	f := newManagementMutationFixture(t, "reset")
	before := breakGlassState(t, f.s)
	managementExec(t, f.s, `CREATE TRIGGER disable_fault BEFORE UPDATE OF revoked_at ON api_tokens BEGIN SELECT RAISE(ABORT,'disable fault'); END`)
	if _, err := f.s.DisableUser(f.user.ID, "actor", time.Now()); err == nil {
		t.Fatal("failed disable committed")
	}
	if after := breakGlassState(t, f.s); after != before {
		t.Fatal("failed disable advanced credentials or changed durable authority")
	}
}
