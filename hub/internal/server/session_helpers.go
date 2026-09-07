package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
	"github.com/wyiu/veyport/hub/internal/store"
)

// Server-side session helpers (feature 009).
//
// Everything the hub does with a session record — create one at sign-in,
// decide whether an already issued token may still be used, end one or all of
// them, and render them for the panel — routes through this file. The
// authentication middleware, the refresh path, the sign-out path and the
// session endpoints therefore agree by construction about what a live session
// is, which of the two refusal messages a caller gets, and what lands in the
// audit trail.
//
// The decision itself is not made here: internal/session owns the precedence
// (ended > absolute > idle > ok) and the wording. This file is the part that
// touches the store, the terminal registry and the audit log.

const (
	// cliUserAgentPrefix is how the vey CLI identifies itself. Kind detection
	// is deliberately best-effort: anything that does not announce itself as
	// the CLI is recorded as a web client (spec Edge Cases).
	cliUserAgentPrefix = "vey/"

	// maxUserAgentLength bounds what a client can write into the session row.
	// The value is only ever displayed, so a long agent string is truncated
	// rather than rejected.
	maxUserAgentLength = 256

	// sessionHistoryWindow is how far back ended sessions stay listable
	// (FR-013). It must match sessionPruneRetention in session_prune.go: rows
	// older than this are deleted, so listing further back would show a
	// window that empties itself.
	sessionHistoryWindow = 30 * 24 * time.Hour

	// shellRowPrefix marks a session-list row that is an open shell from the
	// terminal registry rather than a row in the sessions table. The full id
	// is shellRowPrefix + serverID + ":" + terminal session id.
	shellRowPrefix = "shell:"

	// shellExitCode is the status a forcibly closed shell reports to its
	// client. Non-zero, because the shell did not end on the user's terms.
	shellExitCode = 1

	// sessionResourceType is the audit resource type the three session events
	// share; it matches the catalog entries in model/audit_catalog.go.
	sessionResourceType = "session"

	// maxTouchInterval caps how rarely last_seen_at is written, and
	// touchIntervalFraction is the share of the idle limit the write may lag
	// by. See touchInterval.
	maxTouchInterval      = 60 * time.Second
	touchIntervalFraction = 10
)

// touchInterval is the minimum gap between two writes of a session's
// last_seen_at, given the configured policy.
//
// The throttle exists to keep the per-request cost down, but it is also the
// error bar on the idle clock: a stamp may lag real activity by a whole
// interval, so a session can be judged idle that much before the limit truly
// elapsed. A fixed minute is invisible against the 15-minute default and
// brutal against a 1-minute one, where a request seconds old could be read as
// idle. Scaling the interval to a tenth of the idle limit keeps the early
// expiry proportional at any setting, and the minute cap keeps the write rate
// bounded for long limits.
//
// An idle limit of zero means idle expiry is switched off, so nothing depends
// on the stamp's freshness and the cheapest throttle applies.
func touchInterval(p lockout.Policy) time.Duration {
	if p.SessionIdle <= 0 {
		return maxTouchInterval
	}
	if scaled := p.SessionIdle / touchIntervalFraction; scaled < maxTouchInterval {
		return scaled
	}
	return maxTouchInterval
}

// Messages written to a shell's client as it is forcibly closed, so the person
// at the terminal learns why it went away instead of seeing a bare disconnect
// (FR-009, FR-010).
const (
	shellMsgAdminRevoked    = "veyport: session ended by an administrator"
	shellMsgSignedOut       = "veyport: signed out everywhere"
	shellMsgAccountDisabled = "veyport: account disabled"
)

// clientKind classifies a request as a CLI or a web client from its user
// agent. Only the CLI is identified positively; everything else is web.
func clientKind(r *http.Request) string {
	if strings.HasPrefix(r.UserAgent(), cliUserAgentPrefix) {
		return model.SessionKindCLI
	}
	return model.SessionKindWeb
}

// truncateUserAgent caps a user-agent string at maxUserAgentLength bytes
// without leaving a partial UTF-8 sequence behind, so the stored value is
// always valid text for the panel to render.
func truncateUserAgent(ua string) string {
	if len(ua) <= maxUserAgentLength {
		return ua
	}
	cut := ua[:maxUserAgentLength]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// newSession records a session for a completed sign-in and audits its
// creation (FR-001).
//
// The absolute expiry is stamped once, here, from the policy in force at
// sign-in: a later policy change never rewrites it, which is what makes
// "absolute changes apply to sessions created afterwards" true (FR-004). A
// policy of 0 leaves it NULL, meaning the session has no absolute limit at all.
//
// A storage failure is returned, because a sign-in that cannot record its
// session must not hand out tokens bound to a session that does not exist.
func (s *Server) newSession(r *http.Request, user *model.User) (*model.Session, error) {
	now := s.now().UTC()
	sess := &model.Session{
		ID:         uuid.NewString(),
		UserID:     user.ID,
		Kind:       clientKind(r),
		IP:         clientIP(r),
		UserAgent:  truncateUserAgent(r.UserAgent()),
		CreatedAt:  now,
		LastSeenAt: now,
	}
	if maxLifetime := s.lockoutPolicy().SessionMax; maxLifetime > 0 {
		expiresAt := now.Add(maxLifetime)
		sess.ExpiresAt = &expiresAt
	}

	if err := s.store.CreateSession(sess); err != nil {
		return nil, err
	}

	ip := clientIP(r)
	detail := sessionAuditDetail(map[string]string{
		"session_id": sess.ID,
		"kind":       sess.Kind,
	})
	s.auditLogRequest(r, model.AuditEntry{
		UserID:       &user.ID,
		Action:       model.AuditSessionCreated,
		Target:       &user.ID,
		Detail:       &detail,
		IPAddress:    &ip,
		Outcome:      model.AuditOutcomeSuccess,
		ActorType:    model.AuditActorTypeUser,
		ResourceType: stringPtr(sessionResourceType),
	})
	return sess, nil
}

// sessionAccessError is the refusal carried back from the token-bearing paths,
// which cannot write a response themselves — the same shape 008's
// accountAccessError uses, so the middleware unwraps both the same way.
type sessionAccessError struct {
	// Msg is the canonical message for the refusal: session.MsgExpired for a
	// missing, unknown or timed-out session, session.MsgEnded for one that was
	// deliberately ended.
	Msg string
}

func (e *sessionAccessError) Error() string { return e.Msg }

// sessionAccessError decides whether the session behind an already issued
// token may still be used, and records the session's activity when it may
// (FR-003).
//
// It returns nil for a live session within both limits, and a
// *sessionAccessError otherwise. Four cases refuse:
//
//   - the token carries no session id — every token minted before this feature
//     shipped, which is the one-time re-sign-in at upgrade (FR-002, R10);
//   - the session row is gone (pruned, or the user was deleted);
//   - the session was ended deliberately — the only case that says "ended";
//   - the session passed its absolute or idle limit, which also marks the row
//     expired and audits the expiry exactly once (FR-005).
//
// A store read that fails for any other reason refuses too: the hub cannot
// establish that the session is live, and a session check that fails open
// would be no check at all.
func (s *Server) sessionAccessError(claims *auth.Claims) error {
	if claims.SessionID == "" {
		return &sessionAccessError{Msg: session.MsgExpired}
	}

	sess, err := s.store.GetSession(claims.SessionID)
	if err != nil {
		if !isSessionNotFound(err) {
			log.Printf("warning: failed to read session %s: %v", claims.SessionID, err)
		}
		return &sessionAccessError{Msg: session.MsgExpired}
	}

	now := s.now().UTC()
	policy := s.lockoutPolicy()
	verdict := session.Evaluate(session.StateFromModel(sess), now, policy)
	switch verdict {
	case session.VerdictOK:
		// Throttled inside the store, so this costs at most one cheap guarded
		// UPDATE per session per touchInterval however fast requests arrive.
		if touchErr := s.store.TouchSession(sess.ID, now, touchInterval(policy)); touchErr != nil {
			log.Printf("warning: failed to touch session %s: %v", sess.ID, touchErr)
		}
		return nil
	case session.VerdictEnded:
		return &sessionAccessError{Msg: endedSessionMessage(sess.EndReason)}
	default:
		s.markSessionExpired(sess, verdict, now)
		return &sessionAccessError{Msg: session.MsgExpired}
	}
}

// isSessionNotFound reports whether err is the store's "no such session".
func isSessionNotFound(err error) bool {
	return errors.Is(err, store.ErrSessionNotFound)
}

// auditSession writes an audit entry raised outside a request — the expiry
// events, which are the hub noticing a timer rather than anyone calling it, so
// there is no request id to correlate with.
func (s *Server) auditSession(entry model.AuditEntry) {
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	_ = s.store.LogAudit(entry)
}

// markSessionExpired persists an expiry verdict on the row and audits it once.
//
// The store's guarded UPDATE is what makes "once" true: several requests of
// the same expired session can arrive together, and only the one that actually
// flipped ended_at writes the audit entry (FR-005). Expiry is the hub's own
// decision, so it is attributed to the system actor with a failure outcome —
// the request it describes was refused.
func (s *Server) markSessionExpired(sess *model.Session, verdict session.Verdict, now time.Time) {
	reason := verdict.String()
	first, err := s.store.MarkExpired(sess.ID, reason, now)
	if err != nil {
		log.Printf("warning: failed to mark session %s expired: %v", sess.ID, err)
		return
	}
	if !first {
		return
	}

	detail := sessionAuditDetail(map[string]string{
		"session_id": sess.ID,
		"reason":     expiryAuditReason(verdict),
	})
	s.auditSession(model.AuditEntry{
		UserID:       &sess.UserID,
		Action:       model.AuditSessionExpired,
		Target:       &sess.UserID,
		Detail:       &detail,
		Outcome:      model.AuditOutcomeFailure,
		ActorType:    model.AuditActorTypeSystem,
		ResourceType: stringPtr(sessionResourceType),
	})
}

// endedSessionMessage picks the wording for a session that is already ended.
//
// An expiry marks the row ended, so every request after the first one that
// noticed a timer sees an ended session — but the caller's session ran out of
// time rather than being taken away, and must keep being told so. Only a
// deliberate end (a revoke, a sign-out, an account disable) says "ended".
func endedSessionMessage(endReason string) string {
	switch endReason {
	case model.SessionEndExpiredIdle, model.SessionEndExpiredAbsolute:
		return session.MsgExpired
	default:
		return session.MsgEnded
	}
}

// expiryAuditReason renders the cause an expiry is audited with. The audit
// detail names which timer ran out even though the refused caller is not told
// (session.MsgExpired covers both), because that is what an operator
// investigating "why was I signed out" needs.
func expiryAuditReason(verdict session.Verdict) string {
	if verdict == session.VerdictExpiredAbsolute {
		return "absolute"
	}
	return "idle"
}

// endSessions ends sessions and closes the shells that go with them, auditing
// one session.revoked per session that was actually live (FR-007, FR-008,
// FR-010).
//
// Either a specific set of ids is ended, or — with all set — every live
// session of the target user except exceptID. actorID is the acting user, or
// nil when nothing but the hub itself acted; the audit entry is then
// attributed to the target so it still appears on that account's trail.
//
// It returns how many sessions and how many shells it closed. It deliberately
// does not distinguish "already ended" from "no such session": a caller that
// needs that difference (the single-session endpoint, which answers 404 versus
// already_ended) reads the row first and calls this only for the ending.
func (s *Server) endSessions(
	r *http.Request, actorID *string, target *model.User,
	ids []string, all bool, exceptID *string, reason string,
) (ended, shells int) {
	now := s.now().UTC()
	endedIDs := s.endSessionRows(target, ids, all, exceptID, reason, actorID, now)

	message := shellCloseMessage(reason)
	for _, id := range endedIDs {
		s.auditSessionRevoked(r, actorID, target, id, reason)
		shells += s.endShellsBySession(id, message)
	}
	// A user's SSH shells belong to no web or CLI session, so ending every
	// session has to sweep the registry by user as well. Shells already closed
	// by the per-session pass are not counted twice — the registry only counts
	// the ones it actually closed.
	if all {
		shells += s.endShellsByUser(target.ID, message)
	}
	return len(endedIDs), shells
}

// endSessionRows performs the store side of endSessions and returns the ids it
// actually ended. A storage failure is logged and treated as "ended nothing":
// the caller is a revocation path, and reporting a smaller count is safer than
// claiming sessions were ended when they were not.
func (s *Server) endSessionRows(
	target *model.User, ids []string, all bool, exceptID *string,
	reason string, actorID *string, now time.Time,
) []string {
	if all {
		endedIDs, err := s.store.EndUserSessions(target.ID, exceptID, reason, actorID, now)
		if err != nil {
			log.Printf("warning: failed to end sessions for user %s: %v", target.ID, err)
			return nil
		}
		return endedIDs
	}

	var endedIDs []string
	for _, id := range ids {
		wasLive, err := s.store.EndSession(id, reason, actorID, now)
		if err != nil && !isSessionNotFound(err) {
			log.Printf("warning: failed to end session %s: %v", id, err)
		}
		if wasLive {
			endedIDs = append(endedIDs, id)
		}
	}
	return endedIDs
}

// auditSessionRevoked writes the one entry a revocation produces. The kind is
// read back from the row so the trail says what was ended (a browser or a CLI)
// without the caller having to carry it; a row that cannot be re-read is still
// audited, with the kind left out.
func (s *Server) auditSessionRevoked(
	r *http.Request, actorID *string, target *model.User, sessionID, reason string,
) {
	fields := map[string]string{"session_id": sessionID, "reason": reason}
	if sess, err := s.store.GetSession(sessionID); err == nil {
		fields["kind"] = sess.Kind
	}
	detail := sessionAuditDetail(fields)

	actor := actorID
	if actor == nil {
		actor = &target.ID
	}
	entry := model.AuditEntry{
		UserID:       actor,
		Action:       model.AuditSessionRevoked,
		Target:       &target.ID,
		Detail:       &detail,
		Outcome:      model.AuditOutcomeSuccess,
		ActorType:    model.AuditActorTypeUser,
		ResourceType: stringPtr(sessionResourceType),
	}
	if r == nil {
		s.auditSession(entry)
		return
	}
	ip := clientIP(r)
	entry.IPAddress = &ip
	s.auditLogRequest(r, entry)
}

// shellCloseMessage maps an end reason to what the person at a forcibly closed
// shell is told. The wording is the only explanation they get, so it says who
// or what ended the session rather than naming the internal reason.
func shellCloseMessage(reason string) string {
	switch reason {
	case model.SessionEndRevokedSelf, model.SessionEndLogout:
		return shellMsgSignedOut
	case model.SessionEndRevokedDisable:
		return shellMsgAccountDisabled
	default:
		return shellMsgAdminRevoked
	}
}

// endShellsBySession closes the shells opened under one server-side session.
func (s *Server) endShellsBySession(sessionID, message string) int {
	if s.terminalSessions == nil {
		return 0
	}
	return s.terminalSessions.EndBySession(sessionID, shellExitCode, message)
}

// endShellsByUser closes every live shell a user has open, whatever session
// (if any) opened it.
func (s *Server) endShellsByUser(userID, message string) int {
	if s.terminalSessions == nil {
		return 0
	}
	return s.terminalSessions.EndByUser(userID, shellExitCode, message)
}

// shellRows renders a user's open shells as session-list rows.
//
// Shells live in the terminal registry rather than the sessions table, so
// their ids are synthesised with the shell: prefix and carry no expiry: they
// are not subject to the idle or absolute timers in this stage, only to
// revocation (spec Edge Cases). CreatedAt and LastSeenAt mirror the shell's
// own start and activity times so a mixed list sorts and renders uniformly.
func (s *Server) shellRows(userID string) []model.Session {
	if s.terminalSessions == nil {
		return nil
	}
	infos := s.terminalSessions.ListByUser(userID)
	rows := make([]model.Session, 0, len(infos))
	for _, info := range infos {
		startedAt := info.StartedAt
		lastActivity := info.LastActivity
		rows = append(rows, model.Session{
			ID:             shellRowID(info.ServerID, info.SessionID),
			UserID:         userID,
			Kind:           shellRowKind(info.Kind),
			Server:         s.serverDisplayName(info.ServerID),
			CreatedAt:      startedAt,
			LastSeenAt:     lastActivity,
			StartedAt:      &startedAt,
			LastActivityAt: &lastActivity,
		})
	}
	return rows
}

// shellRowID builds the synthetic id a shell is addressed by in the session
// endpoints.
func shellRowID(serverID, terminalSessionID string) string {
	return shellRowPrefix + serverID + ":" + terminalSessionID
}

// shellRowKind maps a registry transport onto the kind the panel shows.
func shellRowKind(kind string) string {
	if kind == grpcserver.TerminalKindSSH {
		return model.SessionKindSSH
	}
	return model.SessionKindTerminal
}

// serverDisplayName resolves a server id to its name, falling back to the id
// when the server has since been deleted — a row that names an id is more use
// than one that names nothing.
func (s *Server) serverDisplayName(serverID string) string {
	srv, err := s.store.GetServerByID(serverID)
	if err != nil || srv == nil || srv.Name == "" {
		return serverID
	}
	return srv.Name
}

// sessionsFor assembles the session list for one user: the stored web and CLI
// sessions first, then the open shells.
//
// currentSID marks the caller's own session, so the panel can say "this
// session" and refuse to let a user end the one they are using through the
// wrong control. includeEnded adds the ended rows of the retention window,
// which is an administrator-only view. The idle deadline is derived on read
// from the live policy, so it moves with both the session's activity and any
// change to the limit, and is omitted entirely when the idle limit is off.
func (s *Server) sessionsFor(userID, currentSID string, includeEnded bool) ([]model.Session, error) {
	policy := s.lockoutPolicy()
	since := s.now().UTC().Add(-sessionHistoryWindow)

	stored, err := s.store.ListUserSessions(userID, includeEnded, since)
	if err != nil {
		return nil, err
	}

	rows := make([]model.Session, 0, len(stored))
	for i := range stored {
		row := stored[i]
		if row.EndedAt == nil {
			row.IdleDeadlineAt = session.IdleDeadline(session.StateFromModel(&row), policy)
		}
		row.Current = currentSID != "" && row.ID == currentSID
		rows = append(rows, row)
	}
	return append(rows, s.shellRows(userID)...), nil
}

// sessionAuditDetail renders an audit detail payload with stable key order.
// A marshalling failure cannot realistically happen for a map of strings, but
// a degraded detail still beats losing the entry, so it falls back to the
// session id alone.
func sessionAuditDetail(fields map[string]string) string {
	encoded, err := json.Marshal(fields)
	if err != nil {
		log.Printf("warning: failed to encode session audit detail: %v", err)
		return fields["session_id"]
	}
	return string(encoded)
}
