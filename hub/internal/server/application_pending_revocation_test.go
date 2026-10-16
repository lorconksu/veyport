package server

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestApplicationPendingRevocationConcurrentRetryRetiresOnlyDurableMarker(t *testing.T) {
	s, app, session := directorySessionFixture(t, "user")
	s.stopSessionPruner()
	now := s.now()
	if _, err := s.store.DB().Exec(`CREATE TRIGGER fail_concurrent_end BEFORE UPDATE OF ended_at ON application_sessions BEGIN SELECT RAISE(ABORT,'synthetic end unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := s.endApplicationAccessChanged(session.ID, now); err == nil {
				t.Error("failed end write appeared durable")
			}
		}()
	}
	workers.Wait()
	s.applicationRevocations.mu.Lock()
	count := len(s.applicationRevocations.pending)
	s.applicationRevocations.mu.Unlock()
	if count != 1 {
		t.Fatal("concurrent observed loss did not keep one bounded marker", count)
	}
	if _, err := s.store.DB().Exec(`DROP TRIGGER fail_concurrent_end`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := s.checkApplicationSession(context.Background(), app, session, true); err == nil {
				t.Error("concurrent retry revived stale cookie snapshot")
			}
		}()
	}
	workers.Wait()
	s.applicationRevocations.mu.Lock()
	count = len(s.applicationRevocations.pending)
	s.applicationRevocations.mu.Unlock()
	if count != 0 {
		t.Fatal("durable marker not cleaned up", count)
	}
	if err := s.store.DB().QueryRow(`SELECT count(*) FROM audit_logs WHERE id=?`, "application-session-end:"+session.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("concurrent retry did not audit exactly once", count, err)
	}
}

func TestApplicationPendingRevocationBoundQuarantinesWithoutDroppingEvidence(t *testing.T) {
	s, _, cookie := applicationFixture(t, "http://127.0.0.1:9999")
	s.stopSessionPruner()
	r := s.applicationRevocations
	r.mu.Lock()
	for i := 0; i <= maxPendingApplicationRevocations; i++ {
		r.markLocked(strconv.Itoa(i), s.now())
	}
	count, quarantined := len(r.pending), r.quarantine
	r.mu.Unlock()
	if count != maxPendingApplicationRevocations || !quarantined {
		t.Fatal("revocation memory overflow lost evidence", count, quarantined)
	}
	if _, err := s.store.DB().Exec(`CREATE TRIGGER fail_overflow_end BEFORE UPDATE OF ended_at ON application_sessions BEGIN SELECT RAISE(ABORT,'synthetic end unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.retryPendingApplicationRevocations(); err == nil {
		t.Fatal("quarantine ignored storage failure")
	}
	if _, err := s.store.DB().Exec(`DROP TRIGGER fail_overflow_end`); err != nil {
		t.Fatal(err)
	}
	if err := s.retryPendingApplicationRevocations(); err != nil {
		t.Fatal(err)
	}
	current, err := s.store.GetApplicationSession(refreshDigest(cookie))
	if err != nil || current.EndedAt == nil {
		t.Fatal("overflow quarantine did not durably end old sessions", err)
	}
	r.mu.Lock()
	count, quarantined = len(r.pending), r.quarantine
	r.mu.Unlock()
	if count != 0 || quarantined {
		t.Fatal("durable bulk cleanup did not retire quarantine", count, quarantined)
	}
}

func TestApplicationPendingRevocationHousekeepingUsesBoundedBatch(t *testing.T) {
	s := testServer(t)
	s.stopSessionPruner()
	r := s.applicationRevocations
	r.mu.Lock()
	for i := 0; i < applicationRevocationCleanupBatch+1; i++ {
		r.markLocked(strconv.Itoa(i), s.now())
	}
	r.mu.Unlock()
	if err := s.retryPendingApplicationRevocations(); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	count := len(r.pending)
	r.mu.Unlock()
	if count != 1 {
		t.Fatal("housekeeping exceeded its bounded batch", count)
	}
	if err := s.retryPendingApplicationRevocations(); err != nil {
		t.Fatal(err)
	}
}

func restartApplicationServer(t *testing.T, original *Server) *Server {
	t.Helper()
	original.stopSessionPruner()
	restarted := New(Config{Store: original.store, JWTSecret: original.jwtSecret, IsDev: true, ApplicationDomain: original.applicationDomain, ApplicationPortalOrigin: original.applicationPortalOrigin, ApplicationDialer: original.applicationDialer, ApplicationMembershipReader: original.applicationMembershipReader})
	restarted.stopSessionPruner()
	t.Cleanup(func() { _ = restarted.Shutdown(context.Background()) })
	return restarted
}

func TestApplicationRestartEndsSessionsAndTicketsPreservesMFAAnchor(t *testing.T) {
	s, app, session := directorySessionFixture(t, "user")
	anchor, err := s.store.GetApplicationAnchor(session.AnchorID)
	if err != nil {
		t.Fatal(err)
	}
	ticket := model.ApplicationLaunchTicket{Digest: uuid.NewString(), ApplicationID: app.ID, UserID: session.UserID, AnchorID: session.AnchorID, Hostname: app.PublicHostname, ConfigVersion: app.ConfigVersion, AccessRevision: session.AccessRevision, DirectoryFingerprint: session.DirectoryFingerprint, Path: "/", ExpiresAt: s.now().Add(time.Minute)}
	if err := s.store.CreateApplicationTicket(ticket); err != nil {
		t.Fatal(err)
	}
	restarted := restartApplicationServer(t, s)
	if err := restarted.checkApplicationSession(context.Background(), app, session, false); err == nil {
		t.Fatal("Hub restart reused an old cookie")
	}
	ended, err := s.store.ApplicationSessionByID(session.ID)
	if err != nil || ended.EndedAt == nil || ended.EndReason != "hub_restart" {
		t.Fatal("startup did not durably end session", err)
	}
	var count int
	if err := s.store.DB().QueryRow(`SELECT count(*) FROM application_launch_tickets WHERE digest=?`, ticket.Digest).Scan(&count); err != nil || count != 0 {
		t.Fatal("startup retained pre-restart launch tickets", err)
	}
	preserved, err := s.store.GetApplicationAnchor(session.AnchorID)
	if err != nil || !preserved.CompletedMFAAt.Equal(anchor.CompletedMFAAt) || preserved.RevokedAt != nil || preserved.TokenGeneration != anchor.TokenGeneration {
		t.Fatal("startup changed the source MFA maximum anchor", err)
	}
	audited, err := s.store.ApplicationAuditExists("application-session-end:" + session.ID)
	if err != nil || !audited {
		t.Fatal("startup end audit missing", err)
	}
}

func TestApplicationRestartStorageFailureKeepsAdmissionClosedUntilDurableCleanup(t *testing.T) {
	s, app, session := directorySessionFixture(t, "user")
	if _, err := s.store.DB().Exec(`CREATE TRIGGER fail_restart_end BEFORE UPDATE OF ended_at ON application_sessions BEGIN SELECT RAISE(ABORT,'synthetic end unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	restarted := restartApplicationServer(t, s)
	if err := restarted.checkApplicationSession(context.Background(), app, session, true); err == nil {
		t.Fatal("startup write failure allowed old cookie")
	}
	user, err := s.store.GetUserByID(session.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.applicationAuthorization(context.Background(), user, app); err == nil {
		t.Fatal("startup write failure allowed new launch authority")
	}
	if _, err := s.store.DB().Exec(`DROP TRIGGER fail_restart_end`); err != nil {
		t.Fatal(err)
	}
	if err := restarted.checkApplicationSession(context.Background(), app, session, true); err == nil {
		t.Fatal("startup recovery revived the old cookie")
	}
	if _, _, err := restarted.applicationAuthorization(context.Background(), user, app); err != nil {
		t.Fatal("fresh launch remained blocked after durable startup cleanup", err)
	}
}

func TestApplicationRestartAuditFailureRetriesDurableSessionEnd(t *testing.T) {
	s, _, session := directorySessionFixture(t, "user")
	if _, err := s.store.DB().Exec(`CREATE TRIGGER fail_restart_audit BEFORE INSERT ON audit_logs WHEN NEW.action='application.session_ended' BEGIN SELECT RAISE(ABORT,'synthetic audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	restarted := restartApplicationServer(t, s)
	current, err := s.store.ApplicationSessionByID(session.ID)
	if err != nil || current.EndedAt == nil || current.EndReason != "hub_restart" {
		t.Fatal("startup audit failure undid durable end", err)
	}
	if _, err := s.store.DB().Exec(`DROP TRIGGER fail_restart_audit`); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := restarted.runSessionPrune(30 * 24 * time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := s.store.DB().QueryRow(`SELECT count(*) FROM audit_logs WHERE id=?`, "application-session-end:"+session.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("startup audit retry did not emit exactly one end", count, err)
	}
}
