package server

import (
	"log"
	"net/http"

	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/model"
)

// Account-lifecycle enforcement helpers (feature 008).
//
// Every access path — both sign-in stages, refresh, the authentication
// middleware for access and API tokens, SSH certificate issuance and the SSH
// gateway's shell — asks the same question through this file: is this account
// usable right now? Concentrating the question here is what makes the answer
// identical everywhere, and it is why the refusal wording cannot drift between
// the web app, the CLI and SSH.
//
// The order is fixed in every branch: disabled/dormant first, then the 007
// lock check, then the credential check (research R4). Refusing before the
// lock check means a disabled account's attempts never accrue lock state, and
// refusing before the credential check means neither the stored hash nor the
// directory is ever consulted on behalf of an account that cannot sign in.

// Audit details for a refusal. They name the account state, never the
// credential, and are the strings the audit trail is queried by.
const (
	detailAccountDisabled = "account disabled"
	detailAccountDormant  = "account dormant"
)

// accountStatus derives the caller's live lifecycle status. The policy is read
// fresh on every call (as lockoutPolicy does), so an administrator's change to
// the dormancy window takes effect on the very next request.
func (s *Server) accountStatus(u *model.User) account.Status {
	return account.Evaluate(account.InputFromUser(u), s.now(), s.lockoutPolicy())
}

// accountRefuses reports whether st denies access at every path. It is the
// predicate call sites branch on before calling refuseAccount.
func accountRefuses(st account.Status) bool {
	_, refuse := account.Refusal(st)
	return refuse
}

// accountRefusalDetail is the audit detail recorded for a refusal on st, or
// the empty string for a status that does not refuse.
func accountRefusalDetail(st account.Status) string {
	switch st {
	case account.StatusDisabled:
		return detailAccountDisabled
	case account.StatusDormant:
		return detailAccountDormant
	default:
		return ""
	}
}

// refuseAccount answers a sign-in attempt made on behalf of an unusable
// account: it records the attempt as a login failure carrying the account-state
// detail and responds 403 with the canonical message.
//
// Like refuseLocked it leaves the failure counter alone — the attempt never
// reached a credential check — and raises no notification, because an account
// that is disabled or dormant would otherwise mail its owner once per attempt.
//
// Callers must have established that the status refuses (accountRefuses); the
// guard below only stops a future caller from silently returning an empty 200.
func (s *Server) refuseAccount(w http.ResponseWriter, r *http.Request, u *model.User, st account.Status) {
	msg, refuse := account.Refusal(st)
	if !refuse {
		log.Printf("warning: refuseAccount called for user %s with non-refusing status %q", u.ID, st)
		return
	}
	detail := accountRefusalDetail(st)
	s.recordLoginFailure(r, &u.ID, u.Username, &detail, false)
	respondError(w, http.StatusForbidden, msg)
}

// accountAccessError is the refusal carried back from the token-bearing paths,
// which cannot write a response themselves. Its message is the canonical one,
// so the handler that unwraps it needs to know nothing about lifecycle states.
type accountAccessError struct {
	// Status is the status that refused the request.
	Status account.Status
	// Msg is the canonical operator-facing message for that status.
	Msg string
}

func (e *accountAccessError) Error() string { return e.Msg }

// accountAccessError returns a non-nil error when u may not use an already
// issued credential, and nil when the account is usable. A locked account is
// deliberately usable here: a lock is enforced at the two sign-in stages only
// (FR-010), so it must not kill sessions that already exist.
func (s *Server) accountAccessError(u *model.User) error {
	st := s.accountStatus(u)
	msg, refuse := account.Refusal(st)
	if !refuse {
		return nil
	}
	return &accountAccessError{Status: st, Msg: msg}
}
