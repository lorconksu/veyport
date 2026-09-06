package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

const (
	testCreateSessionFmt = "create session: %v"
	testGetSessionFmt    = "get session: %v"
	testListSessionsFmt  = "list sessions: %v"
)

// sessionBase is the reference instant the session tests are written around.
var sessionBase = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

// newSessionUser creates the owner a session row needs, since sessions carry a
// foreign key onto users.
func newSessionUser(t *testing.T, s *store.Store, id string) string {
	t.Helper()
	newLifecycleUser(t, s, id, id, model.RoleViewer)
	return id
}

// newSession inserts a live session for userID and returns the stored row.
func newSession(t *testing.T, s *store.Store, id, userID string, created time.Time, expires *time.Time) *model.Session {
	t.Helper()
	sess := &model.Session{
		ID:         id,
		UserID:     userID,
		Kind:       model.SessionKindWeb,
		IP:         "10.0.0.5",
		UserAgent:  "Mozilla/5.0",
		CreatedAt:  created,
		LastSeenAt: created,
		ExpiresAt:  expires,
	}
	if err := s.CreateSession(sess); err != nil {
		t.Fatalf(testCreateSessionFmt, err)
	}
	got, err := s.GetSession(id)
	if err != nil {
		t.Fatalf(testGetSessionFmt, err)
	}
	return got
}

// mustGetSession re-reads a session or fails the test.
func mustGetSession(t *testing.T, s *store.Store, id string) *model.Session {
	t.Helper()
	got, err := s.GetSession(id)
	if err != nil {
		t.Fatalf(testGetSessionFmt, err)
	}
	return got
}

// endReasonOf reads the stored end reason, where the empty string means no
// reason was recorded.
func endReasonOf(s *model.Session) string {
	return s.EndReason
}

// endedByOf reads the stored actor, mapping NULL onto the empty string.
func endedByOf(s *model.Session) string {
	if s.EndedBy == nil {
		return ""
	}
	return *s.EndedBy
}

// assertEndReason compares the stored end reason against an expected value,
// treating the empty string as "no reason recorded".
func assertEndReason(t *testing.T, got *model.Session, want string) {
	t.Helper()
	if reason := endReasonOf(got); reason != want {
		t.Fatalf("end_reason: expected %q, got %q", want, reason)
	}
}

// assertEndedBy compares the stored actor against an expected value, treating
// the empty string as NULL.
func assertEndedBy(t *testing.T, got *model.Session, want string) {
	t.Helper()
	if by := endedByOf(got); by != want {
		t.Fatalf("ended_by: expected %q, got %q", want, by)
	}
}

// assertLive fails when the session carries any end marker.
func assertLive(t *testing.T, got *model.Session) {
	t.Helper()
	if got.EndedAt != nil {
		t.Fatalf("expected a live session, got ended_at %v", got.EndedAt)
	}
	assertEndReason(t, got, "")
	assertEndedBy(t, got, "")
}

// TestCreateSession_RoundTrip covers the insert and read of a full row: every
// field survives, and the timestamps come back at the store's second
// precision (FR-001).
func TestCreateSession_RoundTrip(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-owner")

	created := sessionBase.Add(123 * time.Millisecond)
	expires := created.Add(12 * time.Hour)
	sess := &model.Session{
		ID:         "sess-full",
		UserID:     uid,
		Kind:       model.SessionKindCLI,
		IP:         "203.0.113.9",
		UserAgent:  "vey/2.0.37",
		CreatedAt:  created,
		LastSeenAt: created,
		ExpiresAt:  &expires,
	}
	if err := s.CreateSession(sess); err != nil {
		t.Fatalf(testCreateSessionFmt, err)
	}

	got := mustGetSession(t, s, "sess-full")
	if got.UserID != uid {
		t.Fatalf("user_id: expected %q, got %q", uid, got.UserID)
	}
	if got.Kind != model.SessionKindCLI {
		t.Fatalf("kind: expected %q, got %q", model.SessionKindCLI, got.Kind)
	}
	if got.IP != "203.0.113.9" {
		t.Fatalf("ip: got %q", got.IP)
	}
	if got.UserAgent != "vey/2.0.37" {
		t.Fatalf("user_agent: got %q", got.UserAgent)
	}
	if !got.CreatedAt.Equal(created.UTC().Truncate(time.Second)) {
		t.Fatalf("created_at: got %s", got.CreatedAt.Format(time.RFC3339))
	}
	if !got.LastSeenAt.Equal(created.UTC().Truncate(time.Second)) {
		t.Fatalf("last_seen_at: got %s", got.LastSeenAt.Format(time.RFC3339))
	}
	assertSecond(t, "expires_at", got.ExpiresAt, expires)
	assertLive(t, got)
}

// TestCreateSession_NoAbsoluteLimit covers the policy-0 case: a NULL
// expires_at reads back as nil, and the address and agent may be empty.
func TestCreateSession_NoAbsoluteLimit(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-owner2")

	if err := s.CreateSession(&model.Session{
		ID:         "sess-noexp",
		UserID:     uid,
		Kind:       model.SessionKindWeb,
		CreatedAt:  sessionBase,
		LastSeenAt: sessionBase,
	}); err != nil {
		t.Fatalf(testCreateSessionFmt, err)
	}

	got := mustGetSession(t, s, "sess-noexp")
	if got.ExpiresAt != nil {
		t.Fatalf("expected nil expires_at, got %v", got.ExpiresAt)
	}
	if got.IP != "" || got.UserAgent != "" {
		t.Fatalf("expected empty ip/user_agent, got %q/%q", got.IP, got.UserAgent)
	}
}

// TestGetSession_NotFound covers the sentinel the middleware relies on to tell
// "no such session" apart from a database failure.
func TestGetSession_NotFound(t *testing.T) {
	s := testStore(t)

	_, err := s.GetSession("nope")
	if !errors.Is(err, store.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

// TestListUserSessions covers the two-section listing: live rows by most
// recently seen, then, only when asked, the ended rows inside the retention
// window, most recently ended first, and never another user's rows (FR-007).
func TestListUserSessions(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-list")
	other := newSessionUser(t, s, "sess-other")

	newSession(t, s, "live-old", uid, sessionBase, nil)
	newSession(t, s, "live-new", uid, sessionBase.Add(time.Minute), nil)
	newSession(t, s, "ended-recent", uid, sessionBase, nil)
	newSession(t, s, "ended-stale", uid, sessionBase, nil)
	newSession(t, s, "other-live", other, sessionBase, nil)

	if _, err := s.EndSession("ended-recent", "revoked_admin", nil, sessionBase.Add(2*time.Hour)); err != nil {
		t.Fatalf("end session: %v", err)
	}
	if _, err := s.EndSession("ended-stale", "logout", nil, sessionBase.Add(-40*24*time.Hour)); err != nil {
		t.Fatalf("end session: %v", err)
	}

	since := sessionBase.Add(-30 * 24 * time.Hour)

	live, err := s.ListUserSessions(uid, false, since)
	if err != nil {
		t.Fatalf(testListSessionsFmt, err)
	}
	assertSessionIDs(t, live, "live-new", "live-old")

	all, err := s.ListUserSessions(uid, true, since)
	if err != nil {
		t.Fatalf(testListSessionsFmt, err)
	}
	assertSessionIDs(t, all, "live-new", "live-old", "ended-recent")
	assertEndReason(t, &all[2], "revoked_admin")

	none, err := s.ListUserSessions("ghost", true, since)
	if err != nil {
		t.Fatalf(testListSessionsFmt, err)
	}
	if len(none) != 0 {
		t.Fatalf("expected no rows for an unknown user, got %d", len(none))
	}
}

// assertSessionIDs compares a listing against the exact ids expected, in order.
func assertSessionIDs(t *testing.T, got []model.Session, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		ids := make([]string, len(got))
		for i := range got {
			ids[i] = got[i].ID
		}
		t.Fatalf("expected %v, got %v", want, ids)
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("position %d: expected %q, got %q", i, want[i], got[i].ID)
		}
	}
}

// TestTouchSession_Throttle covers the throttled activity write at the two
// intervals the server asks for: a touch inside the window is dropped and one
// past it lands, whether the window is the minute a long idle limit gets or
// the few seconds a short one gets (FR-003).
func TestTouchSession_Throttle(t *testing.T) {
	cases := []struct {
		name     string
		interval time.Duration
		inside   time.Duration
		past     time.Duration
	}{
		{name: "minute", interval: 60 * time.Second, inside: 30 * time.Second, past: 61 * time.Second},
		{name: "short", interval: 6 * time.Second, inside: 3 * time.Second, past: 7 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			uid := newSessionUser(t, s, "sess-touch-"+tc.name)
			newSession(t, s, "touch-1", uid, sessionBase, nil)

			if err := s.TouchSession("touch-1", sessionBase.Add(tc.inside), tc.interval); err != nil {
				t.Fatalf("touch session: %v", err)
			}
			if got := mustGetSession(t, s, "touch-1"); !got.LastSeenAt.Equal(sessionBase) {
				t.Fatalf("expected last_seen_at unchanged inside the throttle, got %s",
					got.LastSeenAt.Format(time.RFC3339))
			}

			later := sessionBase.Add(tc.past)
			if err := s.TouchSession("touch-1", later, tc.interval); err != nil {
				t.Fatalf("touch session: %v", err)
			}
			if got := mustGetSession(t, s, "touch-1"); !got.LastSeenAt.Equal(later) {
				t.Fatalf("expected last_seen_at %s, got %s",
					later.Format(time.RFC3339), got.LastSeenAt.Format(time.RFC3339))
			}
		})
	}
}

// TestTouchSession_UnthrottledStampsEveryTime covers the zero interval: the
// caller has asked for the exact clock, so consecutive touches all land.
func TestTouchSession_UnthrottledStampsEveryTime(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-touch-exact")
	newSession(t, s, "touch-exact", uid, sessionBase, nil)

	for _, d := range []time.Duration{time.Second, 2 * time.Second} {
		at := sessionBase.Add(d)
		if err := s.TouchSession("touch-exact", at, 0); err != nil {
			t.Fatalf("touch session: %v", err)
		}
		if got := mustGetSession(t, s, "touch-exact"); !got.LastSeenAt.Equal(at) {
			t.Fatalf("expected last_seen_at %s with no throttle, got %s",
				at.Format(time.RFC3339), got.LastSeenAt.Format(time.RFC3339))
		}
	}
}

// TestTouchSession_NeverResurrects covers the two guards that hold whatever
// the interval: an ended session is not touched, and an unknown id is a no-op
// rather than an error, because a request must never fail over the activity
// clock (FR-003).
func TestTouchSession_NeverResurrects(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-touch-ended")
	newSession(t, s, "touch-ended", uid, sessionBase, nil)
	if _, err := s.EndSession("touch-ended", "logout", nil, sessionBase.Add(time.Minute)); err != nil {
		t.Fatalf("end session: %v", err)
	}

	for _, interval := range []time.Duration{60 * time.Second, 6 * time.Second, 0} {
		if err := s.TouchSession("touch-ended", sessionBase.Add(2*time.Hour), interval); err != nil {
			t.Fatalf("touch ended session: %v", err)
		}
		if got := mustGetSession(t, s, "touch-ended"); !got.LastSeenAt.Equal(sessionBase) {
			t.Fatalf("expected an ended session never to be touched, got %s",
				got.LastSeenAt.Format(time.RFC3339))
		}
		if err := s.TouchSession("no-such-session", sessionBase, interval); err != nil {
			t.Fatalf("expected touching an unknown session to be a no-op, got %v", err)
		}
	}
}

// TestEndSession_Idempotent covers revocation: the first call reports it ended
// a live session and stamps the markers, and a second call changes nothing and
// reports that there was nothing to end (spec Edge Cases, concurrent revokes).
func TestEndSession_Idempotent(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-end")
	newSession(t, s, "end-1", uid, sessionBase, nil)

	actor := "admin-1"
	endedAt := sessionBase.Add(time.Hour)
	wasLive, err := s.EndSession("end-1", "revoked_admin", &actor, endedAt)
	if err != nil {
		t.Fatalf("end session: %v", err)
	}
	if !wasLive {
		t.Fatal("expected the first end to report a live session")
	}

	got := mustGetSession(t, s, "end-1")
	assertSecond(t, "ended_at", got.EndedAt, endedAt)
	assertEndReason(t, got, "revoked_admin")
	assertEndedBy(t, got, actor)

	second := "admin-2"
	wasLive, err = s.EndSession("end-1", "revoked_self", &second, sessionBase.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("end session again: %v", err)
	}
	if wasLive {
		t.Fatal("expected the second end to report the session was already ended")
	}

	got = mustGetSession(t, s, "end-1")
	assertSecond(t, "ended_at", got.EndedAt, endedAt)
	assertEndReason(t, got, "revoked_admin")
	assertEndedBy(t, got, actor)
}

// TestEndSession_NotFound distinguishes "already ended" from "never existed",
// which is what lets the handler answer 404 rather than "already_ended".
func TestEndSession_NotFound(t *testing.T) {
	s := testStore(t)

	_, err := s.EndSession("ghost", "revoked_admin", nil, sessionBase)
	if !errors.Is(err, store.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

// TestEndSession_SystemActor covers the disable and expiry paths, where there
// is no acting user: ended_by stays NULL.
func TestEndSession_SystemActor(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-sys")
	newSession(t, s, "sys-1", uid, sessionBase, nil)

	if _, err := s.EndSession("sys-1", "revoked_disable", nil, sessionBase.Add(time.Minute)); err != nil {
		t.Fatalf("end session: %v", err)
	}
	got := mustGetSession(t, s, "sys-1")
	assertEndReason(t, got, "revoked_disable")
	assertEndedBy(t, got, "")
}

// TestEndUserSessions covers "log out everywhere": every live session of the
// target ends, the caller's own session can be spared, other users are
// untouched, and the ended ids come back for auditing (FR-007, FR-008).
func TestEndUserSessions(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-all")
	other := newSessionUser(t, s, "sess-all-other")

	newSession(t, s, "all-1", uid, sessionBase, nil)
	newSession(t, s, "all-2", uid, sessionBase, nil)
	newSession(t, s, "all-current", uid, sessionBase, nil)
	newSession(t, s, "all-done", uid, sessionBase, nil)
	newSession(t, s, "all-other", other, sessionBase, nil)

	if _, err := s.EndSession("all-done", "logout", nil, sessionBase.Add(time.Minute)); err != nil {
		t.Fatalf("end session: %v", err)
	}

	current := "all-current"
	actor := uid
	endedAt := sessionBase.Add(time.Hour)
	ids, err := s.EndUserSessions(uid, &current, "revoked_self", &actor, endedAt)
	if err != nil {
		t.Fatalf("end user sessions: %v", err)
	}
	assertIDSet(t, ids, "all-1", "all-2")

	for _, id := range []string{"all-1", "all-2"} {
		got := mustGetSession(t, s, id)
		assertSecond(t, "ended_at", got.EndedAt, endedAt)
		assertEndReason(t, got, "revoked_self")
		assertEndedBy(t, got, actor)
	}
	assertLive(t, mustGetSession(t, s, "all-current"))
	assertLive(t, mustGetSession(t, s, "all-other"))
	assertEndReason(t, mustGetSession(t, s, "all-done"), "logout")

	// Nothing live left except the spared one: a repeat ends nothing.
	ids, err = s.EndUserSessions(uid, &current, "revoked_self", &actor, endedAt)
	if err != nil {
		t.Fatalf("end user sessions again: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no further sessions to end, got %v", ids)
	}
}

// TestEndUserSessions_All covers the no-exception form used by an admin
// revoke-all and by an account disable.
func TestEndUserSessions_All(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-disable")
	newSession(t, s, "dis-1", uid, sessionBase, nil)
	newSession(t, s, "dis-2", uid, sessionBase, nil)

	ids, err := s.EndUserSessions(uid, nil, "revoked_disable", nil, sessionBase.Add(time.Minute))
	if err != nil {
		t.Fatalf("end user sessions: %v", err)
	}
	assertIDSet(t, ids, "dis-1", "dis-2")
	for _, id := range ids {
		assertEndedBy(t, mustGetSession(t, s, id), "")
	}

	ids, err = s.EndUserSessions("ghost", nil, "revoked_disable", nil, sessionBase)
	if err != nil {
		t.Fatalf("end sessions of an unknown user: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no ids for an unknown user, got %v", ids)
	}
}

// assertIDSet compares a set of returned ids irrespective of order.
func assertIDSet(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	seen := make(map[string]bool, len(got))
	for _, id := range got {
		seen[id] = true
	}
	for _, id := range want {
		if !seen[id] {
			t.Fatalf("expected %q among %v", id, got)
		}
	}
}

// TestMarkExpired covers the first-detection flag that keeps the audit trail
// to exactly one session.expired event per session (FR-005).
func TestMarkExpired(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-exp")
	newSession(t, s, "exp-1", uid, sessionBase, nil)

	at := sessionBase.Add(time.Hour)
	first, err := s.MarkExpired("exp-1", "expired_idle", at)
	if err != nil {
		t.Fatalf("mark expired: %v", err)
	}
	if !first {
		t.Fatal("expected the first detection to report true")
	}
	got := mustGetSession(t, s, "exp-1")
	assertSecond(t, "ended_at", got.EndedAt, at)
	assertEndReason(t, got, "expired_idle")
	assertEndedBy(t, got, "")

	first, err = s.MarkExpired("exp-1", "expired_absolute", sessionBase.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("mark expired again: %v", err)
	}
	if first {
		t.Fatal("expected a repeat detection to report false")
	}
	got = mustGetSession(t, s, "exp-1")
	assertSecond(t, "ended_at", got.EndedAt, at)
	assertEndReason(t, got, "expired_idle")

	if _, err := s.MarkExpired("ghost", "expired_idle", at); !errors.Is(err, store.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

// TestPruneEndedSessions covers retention: ended rows older than the cutoff go,
// newer ended rows stay visible as history, and live rows are never pruned
// however old they are (FR-013).
func TestPruneEndedSessions(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-prune")

	newSession(t, s, "prune-old", uid, sessionBase.Add(-90*24*time.Hour), nil)
	newSession(t, s, "prune-recent", uid, sessionBase.Add(-2*24*time.Hour), nil)
	newSession(t, s, "prune-live", uid, sessionBase.Add(-90*24*time.Hour), nil)

	if _, err := s.EndSession("prune-old", "logout", nil, sessionBase.Add(-89*24*time.Hour)); err != nil {
		t.Fatalf("end session: %v", err)
	}
	if _, err := s.EndSession("prune-recent", "logout", nil, sessionBase.Add(-24*time.Hour)); err != nil {
		t.Fatalf("end session: %v", err)
	}

	deleted, err := s.PruneEndedSessions(sessionBase.Add(-30 * 24 * time.Hour))
	if err != nil {
		t.Fatalf("prune ended sessions: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 pruned row, got %d", deleted)
	}
	if _, err := s.GetSession("prune-old"); !errors.Is(err, store.ErrSessionNotFound) {
		t.Fatalf("expected the stale ended session to be gone, got %v", err)
	}
	mustGetSession(t, s, "prune-recent")
	mustGetSession(t, s, "prune-live")

	deleted, err = s.PruneEndedSessions(sessionBase.Add(-30 * 24 * time.Hour))
	if err != nil {
		t.Fatalf("prune ended sessions again: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("expected nothing left to prune, got %d", deleted)
	}
}

// TestSessions_CascadeOnUserDelete covers the foreign key: deleting a user
// takes their session rows with it (spec Edge Cases).
func TestSessions_CascadeOnUserDelete(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-cascade")
	keeper := newSessionUser(t, s, "sess-keeper")

	newSession(t, s, "cascade-1", uid, sessionBase, nil)
	newSession(t, s, "cascade-2", uid, sessionBase, nil)
	newSession(t, s, "cascade-keep", keeper, sessionBase, nil)

	if err := s.DeleteUser(uid); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	for _, id := range []string{"cascade-1", "cascade-2"} {
		if _, err := s.GetSession(id); !errors.Is(err, store.ErrSessionNotFound) {
			t.Fatalf("expected %s to be removed with its user, got %v", id, err)
		}
	}
	mustGetSession(t, s, "cascade-keep")
}

// TestCreateSession_Rejects covers the two constraints the table enforces on a
// write: session ids are unique, and a session must belong to a real user.
func TestCreateSession_Rejects(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-reject")
	newSession(t, s, "reject-1", uid, sessionBase, nil)

	if err := s.CreateSession(&model.Session{
		ID:         "reject-1",
		UserID:     uid,
		Kind:       model.SessionKindWeb,
		CreatedAt:  sessionBase,
		LastSeenAt: sessionBase,
	}); err == nil {
		t.Fatal("expected a duplicate session id to be refused")
	}

	if err := s.CreateSession(&model.Session{
		ID:         "reject-2",
		UserID:     "no-such-user",
		Kind:       model.SessionKindWeb,
		CreatedAt:  sessionBase,
		LastSeenAt: sessionBase,
	}); err == nil {
		t.Fatal("expected a session for an unknown user to be refused")
	}
}

// TestGetSession_UnparsableTimestamps covers a corrupted row: a timestamp that
// does not parse reads back as the zero time rather than failing the request,
// so one bad row cannot lock a user out of the session list.
func TestGetSession_UnparsableTimestamps(t *testing.T) {
	s := testStore(t)
	uid := newSessionUser(t, s, "sess-corrupt")

	if _, err := s.DB().Exec(
		`INSERT INTO sessions (id, user_id, kind, ip, user_agent, created_at, last_seen_at)
		 VALUES (?, ?, ?, '', '', 'not-a-time', 'also-not-a-time')`,
		"corrupt-1", uid, model.SessionKindWeb,
	); err != nil {
		t.Fatalf("insert corrupt session: %v", err)
	}

	got := mustGetSession(t, s, "corrupt-1")
	if !got.CreatedAt.IsZero() || !got.LastSeenAt.IsZero() {
		t.Fatalf("expected zero times, got created=%v last_seen=%v", got.CreatedAt, got.LastSeenAt)
	}
}
