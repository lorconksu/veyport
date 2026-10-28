package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
)

var ErrProtectedChange = errors.New("protected security change requires /api/security/changes")
var ErrSecurityConflict = errors.New("security state changed; create a new request")
var ErrStepup = errors.New("fresh action-bound interactive MFA required")
var ErrPolicyIntegrity = errors.New("stored audit policy integrity check failed")

// Migration 025 predates policy digests. Only its exact initial record may use
// that legacy exception; an approved or later record always has a digest.
const initialStandardPolicy = `{"profile":"standard","actors":[],"nodes":[],"runtime_seconds":3600,"retention_hours":24,"destination":"","credential_ref":"","trust_key_ids":[],"qualification_sha256":""}`

func SecurityDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func (s *Store) UserRoles(userID string) ([]model.Role, error) {
	rows, err := s.db.Query("SELECT role FROM user_roles WHERE user_id=? ORDER BY role", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := []model.Role{}
	for rows.Next() {
		var r model.Role
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}
func (s *Store) PersonForUser(userID string) (string, error) {
	var id string
	err := s.db.QueryRow("SELECT person_id FROM security_identity_links WHERE user_id=?", userID).Scan(&id)
	return id, err
}
func (s *Store) IsProtectedUser(userID string) (bool, error) {
	var n int
	err := s.db.QueryRow(protectedPersonSQL, userID, userID, userID, userID, userID).Scan(&n)
	return n > 0, err
}
func (s *Store) GuardSecurityUserMutation(userID string) error {
	p, err := s.IsProtectedUser(userID)
	if err != nil {
		return err
	}
	if p {
		return ErrProtectedChange
	}
	return nil
}
func (s *Store) GovernanceEnrolled() (bool, error) {
	return governanceEnrolled(s.policyContext(), s.policyDB())
}

func governanceEnrolled(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (bool, error) {
	rows, err := db.QueryContext(ctx, "SELECT version,payload,digest,request_id FROM audit_policy_versions ORDER BY version")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	enrolled := false
	for rows.Next() {
		var p model.PolicyVersion
		var raw []byte
		if err := rows.Scan(&p.Version, &raw, &p.SHA256, &p.RequestID); err != nil {
			return false, err
		}
		if err := decodePolicyVersion(&p, raw); err != nil {
			return false, err
		}
		// Every legitimate post-initial version follows Enhanced bootstrap.
		// An approved later Standard profile does not remove its governance.
		enrolled = enrolled || p.Version > 1 || p.RequestID != "" || p.Policy.Profile == "enhanced"
	}
	return enrolled, rows.Err()
}
func (s *Store) GetPolicyState() (model.PolicyState, error) {
	var state model.PolicyState
	var active uint64
	var pending sql.NullInt64
	err := s.policyDB().QueryRowContext(s.policyContext(), "SELECT active_version,state,pending_version,pending_change FROM audit_policy_state WHERE id=1").Scan(&active, &state.State, &pending, &state.PendingChange)
	if err != nil {
		return state, err
	}
	state.Active, err = s.GetPolicyVersion(active)
	if err != nil {
		return state, err
	}
	if pending.Valid {
		p, err := s.GetPolicyVersion(uint64(pending.Int64))
		if err != nil {
			return state, err
		}
		state.Pending = &p
		var previous uint64
		if err := s.policyDB().QueryRowContext(s.policyContext(), "SELECT expected_version FROM security_changes WHERE id=?", state.PendingChange).Scan(&previous); err != nil {
			return state, err
		}
		old, err := s.GetPolicyVersion(previous)
		if err != nil {
			return state, err
		}
		state.Previous = &old
	}
	return state, nil
}
func (s *Store) GetPolicyVersion(version uint64) (model.PolicyVersion, error) {
	return readPolicyVersion(s.policyDB().QueryRowContext(s.policyContext(), "SELECT payload,digest,request_id FROM audit_policy_versions WHERE version=?", version), version)
}

func readPolicyVersion(row *sql.Row, version uint64) (model.PolicyVersion, error) {
	p := model.PolicyVersion{Version: version}
	var raw []byte
	if err := row.Scan(&raw, &p.SHA256, &p.RequestID); err != nil {
		return p, err
	}
	if err := decodePolicyVersion(&p, raw); err != nil {
		return model.PolicyVersion{}, err
	}
	return p, nil
}

func decodePolicyVersion(p *model.PolicyVersion, raw []byte) error {
	digest := SecurityDigest(raw)
	if p.SHA256 == "" {
		if p.Version != 1 || p.RequestID != "" || string(raw) != initialStandardPolicy {
			return ErrPolicyIntegrity
		}
		p.SHA256 = digest
	} else if p.SHA256 != digest {
		return ErrPolicyIntegrity
	}
	if err := json.Unmarshal(raw, &p.Policy); err != nil {
		return ErrPolicyIntegrity
	}
	return nil
}

// InstallExecutionPolicyValidator binds this store to one immutable outside-DB
// continuity authority. Later constructors cannot replace or clear that binding.
func (s *Store) InstallExecutionPolicyValidator(key string, validate func(*Store, model.PolicyState) error) error {
	if key == "" || validate == nil {
		return ErrPolicyIntegrity
	}
	s.executionPolicyMu.Lock()
	defer s.executionPolicyMu.Unlock()
	if s.executionPolicyValidator != nil {
		if s.executionPolicyKey != key {
			return ErrPolicyIntegrity
		}
		return nil
	}
	s.executionPolicyKey = key
	s.executionPolicyValidator = validate
	return nil
}

// ValidateExecutionPolicy runs outside database transactions and the binding
// mutex. Validators may perform local reads, but must never perform network I/O.
func (s *Store) ValidateExecutionPolicy(state model.PolicyState) error {
	s.executionPolicyMu.RLock()
	validate := s.executionPolicyValidator
	s.executionPolicyMu.RUnlock()
	if validate != nil {
		return validate(s, state)
	}
	raw, err := json.Marshal(state.Active.Policy)
	if err != nil || state.Active.Version != 1 || state.Active.RequestID != "" || string(raw) != initialStandardPolicy || state.Active.SHA256 != SecurityDigest([]byte(initialStandardPolicy)) {
		return ErrPolicyIntegrity
	}
	if state.Pending != nil || state.Previous != nil || state.PendingChange != "" || (state.State != "standard" && state.State != "setup_pending" && state.State != "recovery_required") {
		return ErrPolicyIntegrity
	}
	if enrolled, err := s.GovernanceEnrolled(); err != nil || enrolled {
		return ErrPolicyIntegrity
	}
	return nil
}
func (s *Store) IssueStepup(user, session, action, digest string, now time.Time) (string, error) {
	if user == "" || session == "" || action == "" || len(digest) != 64 {
		return "", ErrStepup
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	handle := hex.EncodeToString(b)
	_, err := s.db.Exec("INSERT INTO stepup_proofs(hash,user_id,session_id,action,digest,created_at,expires_at,token_generation) VALUES(?,?,?,?,?,?,?,COALESCE((SELECT token_generation FROM users WHERE id=?),-1))", SecurityDigest([]byte(handle)), user, session, action, digest, now.Unix(), now.Add(5*time.Minute).Unix(), user)
	return handle, err
}
func consumeStepupWithPolicy(ctx context.Context, conn *sql.Conn, proof, user, session, action, digest string, now time.Time, loadPolicy func() lockout.Policy) error {
	clock := advancingClock(now)
	if err := consumeStepupWithClock(ctx, conn, proof, user, session, action, digest, clock, loadPolicy); err != nil {
		return err
	}
	return recheckStepupSession(ctx, conn, user, session, clock, loadPolicy)
}

func consumeStepupWithClock(ctx context.Context, conn *sql.Conn, proof, user, session, action, digest string, clock func() time.Time, loadPolicy func() lockout.Policy) error {
	if proof == "" || session == "" {
		return ErrStepup
	}
	policy := loadPolicy()
	// Policy loading is part of the authorization boundary. The owning session
	// can expire while those reads are blocked, so carry that elapsed time into
	// the session validator instead of restarting from the caller's timestamp.
	if err := guardLiveSession(ctx, conn, session, user, clock(), policy); err != nil {
		return ErrStepup
	}

	// The session and proof may expire while their final authority reads are in
	// progress. Use one freshly sampled instant for the consuming mutation.
	now := clock()
	result, err := conn.ExecContext(ctx, "UPDATE stepup_proofs SET consumed_at=? WHERE hash=? AND user_id=? AND session_id=? AND action=? AND digest=? AND consumed_at IS NULL AND created_at<=? AND expires_at>? AND token_generation=(SELECT token_generation FROM users WHERE id=stepup_proofs.user_id)", now.Unix(), SecurityDigest([]byte(proof)), user, session, action, digest, now.Unix(), now.Unix())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrStepup
	}
	return nil
}

func recheckStepupSession(ctx context.Context, conn *sql.Conn, user, session string, clock func() time.Time, loadPolicy func() lockout.Policy) error {
	policy := loadPolicy()
	// The writer transaction keeps the captured session stable. Re-read it and
	// evaluate its deadlines after every later authority read and mutation so a
	// request cannot commit merely because the session was live when its proof
	// was consumed.
	if err := guardLiveSession(ctx, conn, session, user, clock(), policy); err != nil {
		return ErrStepup
	}
	return nil
}
func (s *Store) ConsumeStepup(proof, user, session, action, digest string, now time.Time) error {
	return s.withImmediateTxClock(now, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		policy, err := accountManagementPolicyStrict(ctx, conn)
		if err != nil {
			return err
		}
		loadPolicy := func() lockout.Policy {
			return policy
		}
		if err := consumeStepupWithClock(ctx, conn, proof, user, session, action, digest, clock, loadPolicy); err != nil {
			return err
		}
		return recheckStepupSession(ctx, conn, user, session, clock, loadPolicy)
	})
}

func (s *Store) CreateSecurityChange(c model.SecurityChange, nominations []model.SecurityNomination, session, proof string, now time.Time) error {
	return s.withImmediateTxClock(now, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		if !clock().Before(c.ExpiresAt) {
			return ErrSecurityConflict
		}
		var proposal struct {
			Change model.SecurityChangePayload `json:"change"`
		}
		if err := json.Unmarshal(c.ApprovedBytes, &proposal); err != nil {
			return err
		}
		if err := validateSecurityRecoveryTarget(ctx, conn, proposal.Change); err != nil {
			return err
		}
		principalGuard, err := checkSecurityPrincipal(ctx, conn, c, c.RequesterID, c.RequesterPersonID, c.RequesterGeneration, "security.request", clock)
		if err != nil {
			return err
		}
		policy, err := accountManagementPolicyStrict(ctx, conn)
		if err != nil {
			return err
		}
		loadPolicy := func() lockout.Policy {
			return policy
		}
		if err := consumeStepupWithClock(ctx, conn, proof, c.RequesterID, session, "security.request", c.Digest, clock, loadPolicy); err != nil {
			return err
		}
		var version uint64
		var state string
		if err := conn.QueryRowContext(ctx, "SELECT active_version,state FROM audit_policy_state WHERE id=1").Scan(&version, &state); err != nil {
			return err
		}
		if version != c.ExpectedVersion || state == "applying" || state == "recovery_required" {
			return ErrSecurityConflict
		}
		if len(nominations) > 0 {
			var n int
			if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_changes WHERE state IN ('requested','partially_approved','approved','applying') AND id IN (SELECT request_id FROM security_nominations)").Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return ErrSecurityConflict
			}
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO security_changes(id,revision,requester_id,requester_person,requester_generation,expected_version,digest,reason,payload,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,'requested',?,?)`, c.ID, c.Revision, c.RequesterID, c.RequesterPersonID, c.RequesterGeneration, c.ExpectedVersion, c.Digest, c.Reason, c.ApprovedBytes, c.CreatedAt.Unix(), c.ExpiresAt.Unix())
		if err != nil {
			return err
		}
		for _, n := range nominations {
			// Recheck before creating the freeze in this writer transaction. An
			// earlier service read cannot authorize a concurrent reset or relink.
			var complete bool
			var linked string
			if err := conn.QueryRowContext(ctx, "SELECT u.totp_enabled AND u.totp_secret IS NOT NULL AND u.disabled_at IS NULL AND NOT u.must_change_password,l.person_id FROM users u JOIN security_identity_links l ON l.user_id=u.id WHERE u.id=?", n.UserID).Scan(&complete, &linked); err != nil {
				return err
			}
			if !complete || (linked != "user:"+n.UserID && linked != n.PersonID) {
				return ErrSecurityConflict
			}
			roles, _ := json.Marshal(n.Roles)
			if _, err := conn.ExecContext(ctx, "INSERT INTO security_nominations VALUES(?,?,?,?,?)", c.ID, n.UserID, n.PersonID, roles, n.Verification); err != nil {
				return err
			}
		}
		if len(nominations) > 0 {
			_, err = conn.ExecContext(ctx, "UPDATE audit_policy_state SET state='setup_pending' WHERE id=1 AND state='standard'")
		}
		if err == nil && !clock().Before(c.ExpiresAt) {
			return ErrSecurityConflict
		}
		if err != nil {
			return err
		}
		if err := recheckStepupSession(ctx, conn, c.RequesterID, session, clock, loadPolicy); err != nil {
			return err
		}
		if err := recheckSecurityPrincipalGuards(clock, principalGuard); err != nil {
			return err
		}
		if !clock().Before(c.ExpiresAt) {
			return ErrSecurityConflict
		}
		return nil
	})
}
func scanSecurityChange(row interface{ Scan(...any) error }) (model.SecurityChange, error) {
	var c model.SecurityChange
	var created, expires int64
	err := row.Scan(&c.ID, &c.Revision, &c.RequesterID, &c.RequesterPersonID, &c.RequesterGeneration, &c.ExpectedVersion, &c.Digest, &c.Reason, &c.ApprovedBytes, &c.State, &created, &expires, &c.IntentRef, &c.CommitRef, &c.ResultRef, &c.ApplierID, &c.ApplierPersonID, &c.ApplierRevision)
	if err != nil {
		return c, err
	}
	c.CreatedAt = time.Unix(created, 0).UTC()
	c.ExpiresAt = time.Unix(expires, 0).UTC()
	var request struct {
		Change json.RawMessage `json:"change"`
	}
	if err = json.Unmarshal(c.ApprovedBytes, &request); err != nil {
		return c, err
	}
	c.Payload = request.Change
	return c, nil
}

const securityChangeColumns = "id,revision,requester_id,requester_person,requester_generation,expected_version,digest,reason,payload,state,created_at,expires_at,intent_ref,commit_ref,result_ref,applier_id,applier_person,applier_revision"

func (s *Store) GetSecurityChange(id string) (model.SecurityChange, error) {
	c, err := scanSecurityChange(s.policyDB().QueryRowContext(s.policyContext(), "SELECT "+securityChangeColumns+" FROM security_changes WHERE id=?", id))
	if err != nil {
		return c, err
	}
	rows, err := s.policyDB().QueryContext(s.policyContext(), "SELECT user_id,person_id,proof_sha256,token_generation,approved_at,invalidated_at FROM security_approvals WHERE request_id=? AND revision=? AND digest=? ORDER BY approved_at,user_id", id, c.Revision, c.Digest)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	c.Approvals = []model.SecurityApproval{}
	for rows.Next() {
		var a model.SecurityApproval
		var stamp int64
		var invalidated sql.NullInt64
		if err := rows.Scan(&a.UserID, &a.PersonID, &a.ProofSHA256, &a.TokenGeneration, &stamp, &invalidated); err != nil {
			return c, err
		}
		a.ApprovedAt = time.Unix(stamp, 0).UTC()
		if invalidated.Valid {
			at := time.Unix(invalidated.Int64, 0).UTC()
			a.InvalidatedAt = &at
		}
		c.Approvals = append(c.Approvals, a)
	}
	return c, rows.Err()
}
func (s *Store) ListSecurityChanges(limit, offset int) ([]model.SecurityChange, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query("SELECT "+securityChangeColumns+" FROM security_changes ORDER BY created_at DESC,id LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.SecurityChange{}
	for rows.Next() {
		c, err := scanSecurityChange(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *Store) AddSecurityApproval(c model.SecurityChange, a model.SecurityApproval, session, proof string, now time.Time) error {
	return s.withImmediateTxClock(now, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		principalGuard, err := checkSecurityPrincipal(ctx, conn, c, a.UserID, a.PersonID, a.TokenGeneration, "security.approve", clock)
		if err != nil {
			return err
		}
		policy, err := accountManagementPolicyStrict(ctx, conn)
		if err != nil {
			return err
		}
		loadPolicy := func() lockout.Policy {
			return policy
		}
		if err := consumeStepupWithClock(ctx, conn, proof, a.UserID, session, "security.approve", c.Digest, clock, loadPolicy); err != nil {
			return err
		}
		var digest, state string
		var version uint64
		var expires int64
		if err := conn.QueryRowContext(ctx, "SELECT digest,state,expected_version,expires_at FROM security_changes WHERE id=? AND revision=?", c.ID, c.Revision).Scan(&digest, &state, &version, &expires); err != nil {
			return err
		}
		// Freeze the first two independent votes. Later votes cannot change the
		// archived quorum or revoke an otherwise complete decision.
		if digest != c.Digest || expires <= clock().Unix() || (state != "requested" && state != "partially_approved") {
			return ErrSecurityConflict
		}
		var active uint64
		if err := conn.QueryRowContext(ctx, "SELECT active_version FROM audit_policy_state WHERE id=1").Scan(&active); err != nil {
			return err
		}
		if active != version {
			return ErrSecurityConflict
		}
		now := clock()
		if expires <= now.Unix() {
			return ErrSecurityConflict
		}
		_, err = conn.ExecContext(ctx, "INSERT INTO security_approvals(request_id,revision,digest,user_id,person_id,proof_sha256,token_generation,approved_at) VALUES(?,?,?,?,?,?,?,?)", c.ID, c.Revision, c.Digest, a.UserID, a.PersonID, SecurityDigest([]byte(proof)), a.TokenGeneration, now.Unix())
		if err != nil {
			return fmt.Errorf("independent approval already recorded: %w", err)
		}
		now = clock()
		result, err := conn.ExecContext(ctx, "UPDATE security_changes SET state=CASE WHEN (SELECT COUNT(*) FROM security_approvals WHERE request_id=? AND revision=? AND invalidated_at IS NULL)>=2 THEN 'approved' ELSE 'partially_approved' END WHERE id=? AND expires_at>?", c.ID, c.Revision, c.ID, now.Unix())
		if err != nil {
			return err
		}
		updated, err := result.RowsAffected()
		if err != nil || updated != 1 {
			return ErrSecurityConflict
		}
		if err := recheckStepupSession(ctx, conn, a.UserID, session, clock, loadPolicy); err != nil {
			return err
		}
		if err := recheckSecurityPrincipalGuards(clock, principalGuard); err != nil {
			return err
		}
		if expires <= clock().Unix() {
			return ErrSecurityConflict
		}
		return nil
	})
}
func (s *Store) InvalidateSecurityVotes(user string) error {
	_, err := s.db.Exec("UPDATE security_approvals SET invalidated_at=unixepoch() WHERE user_id=?", user)
	return err
}
func (s *Store) ExpireSecurityChanges(now time.Time) error {
	return s.withImmediateTxAt(now, func(ctx context.Context, conn *sql.Conn, now time.Time) error {
		if _, err := conn.ExecContext(ctx, "UPDATE security_changes SET state='expired' WHERE expires_at<=? AND state IN ('requested','partially_approved','approved')", now.Unix()); err != nil {
			return err
		}
		_, err := conn.ExecContext(ctx, "UPDATE audit_policy_state SET state='standard' WHERE state='setup_pending' AND NOT EXISTS(SELECT 1 FROM security_changes c JOIN security_nominations n ON n.request_id=c.id WHERE c.state IN ('requested','partially_approved','approved','applying'))")
		return err
	})
}

type securityPrincipalGuard func(time.Time) error

// checkSecurityPrincipal executes inside the same writer transaction as the
// vote/CAS and returns captured dormancy authority for a final commit check.
func checkSecurityPrincipal(ctx context.Context, conn *sql.Conn, c model.SecurityChange, user, person string, generation int, action string, clock func() time.Time) (securityPrincipalGuard, error) {
	var gen int
	var enabled bool
	var disabled sql.NullString
	var mustChange bool
	var created string
	var lastActivity, reactivated sql.NullString
	var dormancyExempt bool
	if err := conn.QueryRowContext(ctx, "SELECT security_revision,totp_enabled,disabled_at,must_change_password,created_at,last_activity_at,reactivated_at,dormancy_exempt FROM users WHERE id=?", user).Scan(&gen, &enabled, &disabled, &mustChange, &created, &lastActivity, &reactivated, &dormancyExempt); err != nil {
		return nil, err
	}
	if gen != generation || !enabled || disabled.Valid || mustChange {
		return nil, ErrSecurityConflict
	}
	var proposal struct {
		Change model.SecurityChangePayload `json:"change"`
	}
	if err := json.Unmarshal(c.ApprovedBytes, &proposal); err != nil {
		return nil, err
	}
	role := "security-officer"
	if action == "security.approve" {
		role = "security-approver"
	}
	if proposal.Change.Kind == "bootstrap" {
		for _, n := range proposal.Change.Nominations {
			if n.UserID == user && n.PersonID == person {
				for _, r := range n.Roles {
					if string(r) == role {
						if action != "security.approve" {
							var count int
							if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM user_roles WHERE user_id=? AND role='admin'", user).Scan(&count); err != nil || count != 1 {
								return nil, ErrSecurityConflict
							}
						}
						return checkSecurityPrincipalDormancy(ctx, conn, created, lastActivity, reactivated, dormancyExempt, clock)
					}
				}
			}
		}
		return nil, ErrSecurityConflict
	}
	var actual string
	if err := conn.QueryRowContext(ctx, "SELECT person_id FROM security_identity_links WHERE user_id=?", user).Scan(&actual); err != nil || actual != person {
		return nil, ErrSecurityConflict
	}
	var count int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM user_roles WHERE user_id=? AND role=?", user, role).Scan(&count); err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, ErrSecurityConflict
	}
	return checkSecurityPrincipalDormancy(ctx, conn, created, lastActivity, reactivated, dormancyExempt, clock)
}

func checkSecurityPrincipalDormancy(ctx context.Context, conn *sql.Conn, created string, lastActivity, reactivated sql.NullString, exempt bool, clock func() time.Time) (securityPrincipalGuard, error) {
	policy, err := accountManagementPolicyStrict(ctx, conn)
	if err != nil {
		return nil, err
	}
	input := account.Input{
		CreatedAt:      parseSQLiteTimeValue(created),
		LastActivityAt: parseSQLiteTime(lastActivity),
		ReactivatedAt:  parseSQLiteTime(reactivated),
		DormancyExempt: exempt,
	}
	guard := func(now time.Time) error {
		if input.CreatedAt.IsZero() || account.IsDormant(input, now, policy.DormantDays) {
			return ErrSecurityConflict
		}
		return nil
	}
	return guard, guard(clock())
}

func recheckSecurityPrincipalGuards(clock func() time.Time, guards ...securityPrincipalGuard) error {
	now := clock()
	for _, guard := range guards {
		if guard == nil || guard(now) != nil {
			return ErrSecurityConflict
		}
	}
	return nil
}
func (s *Store) BeginSecurityApply(c model.SecurityChange, newPolicy model.AuditPolicy, intentRef string, now time.Time) error {
	clock := advancingClock(now)
	return s.changeInteractivePolicy(func() error { return s.beginSecurityApply(c, newPolicy, intentRef, clock()) })
}
func (s *Store) beginSecurityApply(c model.SecurityChange, newPolicy model.AuditPolicy, intentRef string, now time.Time) error {
	clock := advancingClock(now)
	raw, err := json.Marshal(newPolicy)
	if err != nil {
		return err
	}
	return s.withImmediateTxClock(clock(), func(ctx context.Context, conn *sql.Conn, txClock func() time.Time) error {
		if _, err := readPolicyVersion(conn.QueryRowContext(ctx, "SELECT payload,digest,request_id FROM audit_policy_versions WHERE version=?", c.ExpectedVersion), c.ExpectedVersion); err != nil {
			return err
		}
		var state, digest string
		var expires int64
		var stored []byte
		if err := conn.QueryRowContext(ctx, "SELECT state,digest,expires_at,payload FROM security_changes WHERE id=?", c.ID).Scan(&state, &digest, &expires, &stored); err != nil {
			return err
		}
		if state != "approved" || digest != c.Digest || SecurityDigest(stored) != c.Digest || expires <= txClock().Unix() || intentRef == "" {
			return ErrSecurityConflict
		}
		applierGuard, err := checkSecurityPrincipal(ctx, conn, c, c.ApplierID, c.ApplierPersonID, c.ApplierRevision, "security.apply", txClock)
		if err != nil {
			return err
		}
		quorumGuards, err := s.validateSecurityQuorumConn(ctx, conn, c, txClock)
		if err != nil {
			return err
		}
		principalGuards := append([]securityPrincipalGuard{applierGuard}, quorumGuards...)
		if err := recheckSecurityPrincipalGuards(txClock, principalGuards...); err != nil {
			return err
		}
		if expires <= txClock().Unix() {
			return ErrSecurityConflict
		}
		result, err := conn.ExecContext(ctx, "UPDATE audit_policy_state SET state='applying',pending_version=NULL,pending_change=? WHERE id=1 AND active_version=? AND state IN ('standard','enhanced','setup_pending') AND pending_change=''", c.ID, c.ExpectedVersion)
		if err != nil {
			return err
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return ErrSecurityConflict
		}
		if _, err = conn.ExecContext(ctx, "INSERT INTO audit_policy_versions(version,payload,digest,request_id) VALUES(?,?,?,?)", c.ExpectedVersion+1, raw, SecurityDigest(raw), c.ID); err != nil {
			return err
		}
		if _, err = conn.ExecContext(ctx, "UPDATE audit_policy_state SET pending_version=? WHERE id=1", c.ExpectedVersion+1); err != nil {
			return err
		}
		now := txClock()
		result, err = conn.ExecContext(ctx, "UPDATE security_changes SET state='applying',intent_ref=? WHERE id=? AND state='approved' AND expires_at>?", intentRef, c.ID, now.Unix())
		if err != nil {
			return err
		}
		n, err = result.RowsAffected()
		if err != nil || n != 1 {
			return ErrSecurityConflict
		}
		if err := recheckSecurityPrincipalGuards(txClock, principalGuards...); err != nil {
			return err
		}
		if expires <= txClock().Unix() {
			return ErrSecurityConflict
		}
		return nil
	})
}
func (s *Store) RecordSecurityCommit(id, reference string) error {
	if reference == "" {
		return ErrSecurityConflict
	}
	_, err := s.db.Exec("UPDATE security_changes SET commit_ref=? WHERE id=? AND state='applying'", reference, id)
	return err
}
func (s *Store) ActivateSecurityChange(c model.SecurityChange, p model.SecurityChangePayload) error {
	return s.changeInteractivePolicy(func() error { return s.activateSecurityChange(c, p) })
}
func (s *Store) activateSecurityChange(c model.SecurityChange, p model.SecurityChangePayload) error {
	clock := func() time.Time { return time.Now().UTC() }
	return s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
		var active uint64
		var pending sql.NullInt64
		var id string
		if err := conn.QueryRowContext(ctx, "SELECT active_version,pending_version,pending_change FROM audit_policy_state WHERE id=1 AND state='applying'").Scan(&active, &pending, &id); err != nil {
			return err
		}
		if id != c.ID || !pending.Valid || uint64(pending.Int64) != c.ExpectedVersion+1 {
			return ErrSecurityConflict
		}
		for _, version := range []uint64{active, uint64(pending.Int64)} {
			if _, err := readPolicyVersion(conn.QueryRowContext(ctx, "SELECT payload,digest,request_id FROM audit_policy_versions WHERE version=?", version), version); err != nil {
				return err
			}
		}
		if active == c.ExpectedVersion+1 {
			return nil
		}
		if active != c.ExpectedVersion {
			return ErrSecurityConflict
		}
		var commit string
		if err := conn.QueryRowContext(ctx, "SELECT commit_ref FROM security_changes WHERE id=? AND state='applying'", c.ID).Scan(&commit); err != nil || commit == "" {
			return ErrSecurityConflict
		}
		applierGuard, err := checkSecurityPrincipal(ctx, conn, c, c.ApplierID, c.ApplierPersonID, c.ApplierRevision, "security.apply", clock)
		if err != nil {
			return err
		}
		quorumGuards, err := s.validateSecurityQuorumConn(ctx, conn, c, clock)
		if err != nil {
			return err
		}
		principalGuards := append([]securityPrincipalGuard{applierGuard}, quorumGuards...)
		if err := recheckSecurityPrincipalGuards(clock, principalGuards...); err != nil {
			return err
		}
		if err := applySecurityPayload(ctx, conn, c, p); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, "UPDATE audit_policy_state SET active_version=? WHERE id=1 AND active_version=? AND pending_change=?", c.ExpectedVersion+1, c.ExpectedVersion, c.ID); err != nil {
			return err
		}
		return recheckSecurityPrincipalGuards(clock, principalGuards...)
	})
}
func applySecurityPayload(ctx context.Context, conn *sql.Conn, c model.SecurityChange, p model.SecurityChangePayload) error {
	invalidate := func(user string) error {
		if _, err := conn.ExecContext(ctx, "UPDATE users SET token_generation=token_generation+1 WHERE id=?", user); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, "UPDATE api_tokens SET revoked_at=datetime('now') WHERE user_id=? AND revoked_at IS NULL", user); err != nil {
			return err
		}
		_, err := conn.ExecContext(ctx, "UPDATE stepup_proofs SET consumed_at=COALESCE(consumed_at,?) WHERE user_id=?", time.Now().Unix(), user)
		return err
	}
	link := func(user, person, verification string) error {
		if _, err := conn.ExecContext(ctx, "INSERT INTO security_persons(id,verification) VALUES(?,?) ON CONFLICT(id) DO NOTHING", person, verification); err != nil {
			return err
		}
		result, err := conn.ExecContext(ctx, "UPDATE security_identity_links SET person_id=?,granting_request=? WHERE user_id=?", person, c.ID, user)
		if err != nil {
			return err
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return ErrSecurityConflict
		}
		return invalidate(user)
	}
	switch p.Kind {
	case "audit-settings", "ldap":
		configs := p.PreparedConfig
		if p.AuditSettings != nil {
			configs = AuditSettingsConfig(*p.AuditSettings)
		}
		if len(configs) == 0 {
			return ErrSecurityConflict
		}
		for key, value := range configs {
			if _, err := conn.ExecContext(ctx, "INSERT INTO _config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value); err != nil {
				return err
			}
		}
	case "bootstrap":
		for _, n := range p.Nominations {
			if err := link(n.UserID, n.PersonID, n.Verification); err != nil {
				return err
			}
			for _, r := range n.Roles {
				if _, err := conn.ExecContext(ctx, "INSERT INTO user_roles(user_id,role,granting_request) VALUES(?,?,?)", n.UserID, r, c.ID); err != nil {
					return err
				}
			}
		}
	case "role":
		if p.Role.Grant {
			if _, err := conn.ExecContext(ctx, "INSERT INTO user_roles(user_id,role,granting_request) VALUES(?,?,?) ON CONFLICT(user_id,role) DO NOTHING", p.Role.UserID, p.Role.Role, c.ID); err != nil {
				return err
			}
		} else {
			if _, err := conn.ExecContext(ctx, "DELETE FROM user_roles WHERE user_id=? AND role=?", p.Role.UserID, p.Role.Role); err != nil {
				return err
			}
		}
		return invalidate(p.Role.UserID)
	case "person":
		return link(p.Person.UserID, p.Person.PersonID, p.Person.Verification)
	case "recovery":
		r := p.Recovery
		var err error
		switch r.Operation {
		case "reenable":
			_, err = conn.ExecContext(ctx, "UPDATE users SET disabled_at=NULL,disabled_by=NULL,locked_until=NULL,failed_login_count=0,reactivated_at=datetime('now') WHERE id=?", r.UserID)
		case "mfa-reset":
			err = removeUserTOTPConn(ctx, conn, r.UserID, &c.ApplierID, time.Now().UTC())
		case "password-reset":
			if err := validateSecurityRecoveryTarget(ctx, conn, p); err != nil {
				return err
			}
			if len(r.PreparedPasswordHash) != 60 || !strings.HasPrefix(r.PreparedPasswordHash, "$2") {
				return ErrSecurityConflict
			}
			var currentHash string
			var temporary bool
			if err := conn.QueryRowContext(ctx, "SELECT password_hash,must_change_password FROM users WHERE id=?", r.UserID).Scan(&currentHash, &temporary); err != nil {
				return err
			}
			var history int
			if err := conn.QueryRowContext(ctx, "SELECT COALESCE((SELECT value FROM _config WHERE key=?),?)", configAuthPasswordHistoryCount, defaultPasswordHistoryLimit).Scan(&history); err != nil {
				return err
			}
			if err := appendPasswordHistoryConn(ctx, conn, r.UserID, currentHash, temporary, history, time.Now().UTC()); err != nil {
				return err
			}
			_, err = conn.ExecContext(ctx, "UPDATE users SET password_hash=?,must_change_password=1,temp_password_expires_at=datetime('now','+24 hours'),ssh_credential_generation=ssh_credential_generation+1 WHERE id=?", r.PreparedPasswordHash, r.UserID)
		}
		if err != nil {
			return err
		}
		// Carry MFA authority across this exact password reset only if it was live
		// before the reset. Revoked grants never cross an unrelated generation.
		if r.Operation == "password-reset" {
			if _, err := conn.ExecContext(ctx, `UPDATE security_mfa_recoveries SET token_generation=token_generation+1 WHERE user_id=? AND token_generation=(SELECT token_generation FROM users WHERE id=?)`, r.UserID, r.UserID); err != nil {
				return err
			}
		}
		if r.Operation != "mfa-reset" {
			if err := invalidate(r.UserID); err != nil {
				return err
			}
		}
		if r.Operation == "password-reset" {
			_, err = conn.ExecContext(ctx, "INSERT INTO security_password_recoveries(user_id,request_id,password_hash) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET request_id=excluded.request_id,password_hash=excluded.password_hash", r.UserID, c.ID, r.PreparedPasswordHash)
		}
		if r.Operation == "mfa-reset" {
			_, err = conn.ExecContext(ctx, "INSERT INTO security_mfa_recoveries(user_id,request_id,token_generation) SELECT id,?,token_generation FROM users WHERE id=? ON CONFLICT(user_id) DO UPDATE SET request_id=excluded.request_id,token_generation=excluded.token_generation", c.ID, r.UserID)
		}
		return err
	}
	return nil
}
func (s *Store) FinishSecurityChange(id, resultRef string) error {
	return s.changeInteractivePolicy(func() error { return s.finishSecurityChange(id, resultRef) })
}
func (s *Store) finishSecurityChange(id, resultRef string) error {
	if resultRef == "" {
		return ErrSecurityConflict
	}
	return s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
		var active, pending uint64
		if err := conn.QueryRowContext(ctx, "SELECT active_version,pending_version FROM audit_policy_state WHERE pending_change=? AND state='applying'", id).Scan(&active, &pending); err != nil {
			return err
		}
		if active != pending {
			return ErrSecurityConflict
		}
		policy, err := readPolicyVersion(conn.QueryRowContext(ctx, "SELECT payload,digest,request_id FROM audit_policy_versions WHERE version=?", active), active)
		if err != nil {
			return err
		}
		state := "standard"
		if policy.Policy.Profile == "enhanced" {
			state = "enhanced"
		}
		if _, err := conn.ExecContext(ctx, "UPDATE security_changes SET state='applied',result_ref=? WHERE id=? AND state='applying'", resultRef, id); err != nil {
			return err
		}
		_, err = conn.ExecContext(ctx, "UPDATE audit_policy_state SET state=?,pending_version=NULL,pending_change='' WHERE id=1 AND pending_change=?", state, id)
		return err
	})
}
func (s *Store) RequirePolicyRecovery() error {
	return s.changeInteractivePolicy(func() error { return s.requirePolicyRecovery() })
}
func (s *Store) requirePolicyRecovery() error {
	_, err := s.db.Exec("UPDATE audit_policy_state SET state='recovery_required' WHERE id=1")
	return err
}
func (s *Store) SaveSecuritySecret(ref string, encrypted []byte, user string, now time.Time) error {
	_, err := s.db.Exec("INSERT INTO security_secrets VALUES(?,?,?,?)", ref, encrypted, user, now.Unix())
	return err
}
func (s *Store) SecuritySecret(ref string) ([]byte, error) {
	var b []byte
	err := s.db.QueryRow("SELECT encrypted FROM security_secrets WHERE ref=?", ref).Scan(&b)
	return b, err
}
func (s *Store) SecurityEvidenceBytes(id, kind string, raw []byte) ([]byte, string, error) {
	_, err := s.db.Exec("INSERT INTO security_evidence(request_id,event_type,exact_record) VALUES(?,?,?) ON CONFLICT DO NOTHING", id, kind, raw)
	if err != nil {
		return nil, "", err
	}
	var stored []byte
	var ref string
	err = s.db.QueryRow("SELECT exact_record,reference FROM security_evidence WHERE request_id=? AND event_type=?", id, kind).Scan(&stored, &ref)
	return stored, ref, err
}
func (s *Store) ConfirmSecurityEvidence(id, kind, reference string) error {
	_, err := s.db.Exec("UPDATE security_evidence SET reference=? WHERE request_id=? AND event_type=?", reference, id, kind)
	return err
}

type securityQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// ValidateSecurityRecoveryTarget supplies store-backed preview feedback. Request,
// apply and completion independently enforce the same boundary in their writes.
func (s *Store) ValidateSecurityRecoveryTarget(p model.SecurityChangePayload) error {
	return validateSecurityRecoveryTarget(context.Background(), s.db, p)
}

func validateSecurityRecoveryTarget(ctx context.Context, q securityQuerier, p model.SecurityChangePayload) error {
	if p.Kind != "recovery" || p.Recovery == nil || p.Recovery.Operation != "password-reset" {
		return nil
	}
	var provider model.AuthProvider
	if err := q.QueryRowContext(ctx, "SELECT auth_provider FROM users WHERE id=?", p.Recovery.UserID).Scan(&provider); err != nil {
		return err
	}
	if provider != model.AuthProviderLocal {
		return ErrLocalPasswordOnly
	}
	return nil
}

const protectedPersonSQL = `SELECT (SELECT COUNT(*) FROM user_roles r JOIN security_identity_links l ON l.user_id=r.user_id WHERE r.role IN ('security-officer','security-approver','original-reader') AND l.person_id=(SELECT person_id FROM security_identity_links WHERE user_id=?))+(SELECT COUNT(*) FROM security_nominations n JOIN security_changes c ON c.id=n.request_id WHERE (n.user_id=? OR n.person_id=(SELECT person_id FROM security_identity_links WHERE user_id=?)) AND c.state IN ('requested','partially_approved','approved','applying'))+(SELECT COUNT(*) FROM security_changes c WHERE c.state IN ('requested','partially_approved','approved','applying') AND (? IN (json_extract(c.payload,'$.change.role.user_id'),json_extract(c.payload,'$.change.person.user_id'),json_extract(c.payload,'$.change.recovery.user_id')) OR c.state='applying' AND ? IN (c.requester_id,c.applier_id)))`

func guardSecurityPrincipal(ctx context.Context, q securityQuerier, user string) error {
	var n int
	if err := q.QueryRowContext(ctx, protectedPersonSQL, user, user, user, user, user).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrProtectedChange
	}
	return nil
}
func (s *Store) securityUserWrite(user string, mfaSetup bool, fn func(context.Context, *sql.Conn) error) error {
	return s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
		if err := guardMFASetup(ctx, conn, user, mfaSetup); err != nil {
			return err
		}
		return fn(ctx, conn)
	})
}

func guardMFASetup(ctx context.Context, conn *sql.Conn, user string, mfaSetup bool, boundary ...time.Time) error {
	guard := guardSecurityPrincipal(ctx, conn, user)
	if guard != nil {
		if !errors.Is(guard, ErrProtectedChange) || !mfaSetup {
			return guard
		}
		var allowed bool
		now := time.Now()
		if len(boundary) != 0 {
			now = boundary[0]
		}
		if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users u WHERE u.id=? AND NOT u.totp_enabled AND u.disabled_at IS NULL AND (
		 EXISTS(SELECT 1 FROM security_mfa_recoveries r JOIN security_changes c ON c.id=r.request_id WHERE r.user_id=u.id AND u.token_generation=r.token_generation AND c.state='applied' AND c.result_ref!='') OR
		 EXISTS(SELECT 1 FROM local_break_glass_recoveries r JOIN audit_logs a ON a.id=r.audit_id WHERE r.user_id=u.id AND u.auth_provider='local' AND r.token_generation=u.token_generation AND r.password_hash=u.password_hash AND unixepoch(r.expires_at)>? AND a.action='user.totp_reset' AND a.outcome='success' AND a.actor_type='system' AND a.user_id=u.id AND a.target=u.id)
		))`, user, now.Unix()).Scan(&allowed); err != nil {
			return err
		}
		if !allowed {
			return guard
		}
	}
	return nil
}

// CompleteApprovedPasswordRecovery consumes only the temporary credential
// installed by an externally completed approved recovery or atomic shell reset.
// Shell authority is explicitly recorded separately from governance approvals.
// The HTTP caller must
// authenticate the principal and its current credential/MFA before this CAS.
func (s *Store) CompleteApprovedPasswordRecovery(user, currentHash string, revision int, newHash string, now time.Time) (int, error) {
	clock := advancingClock(now)
	history := s.GetAuditSettings().PasswordHistoryCount
	return s.completeApprovedPasswordRecovery(PasswordRecoverySnapshot{UserID: user, PasswordHash: currentHash, SecurityRevision: revision, TokenGeneration: -1}, newHash, clock(), history, nil)
}

func (s *Store) CompleteApprovedPasswordRecoveryAudited(snapshot PasswordRecoverySnapshot, newHash string, now time.Time, history int, entry model.AuditEntry, authority ...PasswordChangeAuthority) (int, error) {
	return s.completeApprovedPasswordRecovery(snapshot, newHash, now, history, &entry, authority...)
}

func (s *Store) completeApprovedPasswordRecovery(snapshot PasswordRecoverySnapshot, newHash string, now time.Time, history int, entry *model.AuditEntry, authority ...PasswordChangeAuthority) (int, error) {
	var generation int
	err := s.withImmediateTxClock(now, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		recheck, err := s.guardPasswordChangeAuthority(ctx, conn, snapshot.UserID, authority, clock)
		if err != nil {
			return err
		}
		now := clock()
		deadline, err := s.completeApprovedPasswordRecoveryConn(ctx, conn, snapshot, newHash, now, history, entry)
		if err != nil {
			return err
		}
		if err := conn.QueryRowContext(ctx, "SELECT token_generation FROM users WHERE id=?", snapshot.UserID).Scan(&generation); err != nil {
			return err
		}
		finalNow := clock()
		if err := deadline(finalNow); err != nil {
			return err
		}
		return recheck(finalNow)
	})
	return generation, err
}

func (s *Store) completeApprovedPasswordRecoveryConn(ctx context.Context, conn *sql.Conn, snapshot PasswordRecoverySnapshot, newHash string, now time.Time, history int, entry *model.AuditEntry) (func(time.Time) error, error) {
	user, currentHash := snapshot.UserID, snapshot.PasswordHash
	if err := validateSecurityRecoveryTarget(ctx, conn, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: user, Operation: "password-reset"}}); err != nil {
		return nil, err
	}
	deadline, err := passwordRecoveryDeadlineRecheck(ctx, conn, snapshot, now)
	if err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, "UPDATE users SET password_hash=?,must_change_password=0,temp_password_expires_at=NULL,token_generation=token_generation+1,ssh_credential_generation=ssh_credential_generation+1,updated_at=datetime('now') WHERE id=?", newHash, user); err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, "DELETE FROM security_password_recoveries WHERE user_id=?", user); err != nil {
		return nil, err
	}
	// Advance only a still-live shell grant that authorized this credential.
	// An independent approved completion must not revive revoked shell MFA.
	if _, err := conn.ExecContext(ctx, `UPDATE local_break_glass_recoveries SET password_pending=0,password_hash=?,token_generation=(SELECT token_generation FROM users WHERE id=?) WHERE user_id=? AND password_hash=? AND token_generation=(SELECT token_generation-1 FROM users WHERE id=?) AND password_pending=1 AND unixepoch(expires_at)>?`, newHash, user, user, currentHash, user, now.Unix()); err != nil {
		return nil, err
	}
	// MFA recovery can complete in the same authenticated setup flow.
	if _, err := conn.ExecContext(ctx, "UPDATE security_mfa_recoveries SET token_generation=(SELECT token_generation FROM users WHERE id=?) WHERE user_id=? AND token_generation=(SELECT token_generation-1 FROM users WHERE id=?)", user, user, user); err != nil {
		return nil, err
	}
	_, err = conn.ExecContext(ctx, "UPDATE api_tokens SET revoked_at=datetime('now') WHERE user_id=? AND revoked_at IS NULL", user)
	if err != nil {
		return nil, err
	}
	if err := appendPasswordHistoryConn(ctx, conn, user, currentHash, true, history, now); err != nil {
		return nil, err
	}
	if entry != nil {
		if err := revokePasswordAuthorityConn(ctx, conn, user, entry.UserID, now); err != nil {
			return nil, err
		}
		if err := logAuditConn(ctx, conn, *entry); err != nil {
			return nil, err
		}
	}
	return deadline, nil
}

func passwordRecoveryDeadlineRecheck(ctx context.Context, conn *sql.Conn, snapshot PasswordRecoverySnapshot, now time.Time) (func(time.Time) error, error) {
	var temporary string
	var governed bool
	var breakGlass sql.NullString
	err := conn.QueryRowContext(ctx, `SELECT u.temp_password_expires_at,
	 EXISTS(SELECT 1 FROM security_password_recoveries r JOIN security_changes c ON c.id=r.request_id WHERE r.user_id=u.id AND r.password_hash=u.password_hash AND c.state='applied' AND c.result_ref!=''),
	 (SELECT r.expires_at FROM local_break_glass_recoveries r JOIN audit_logs a ON a.id=r.audit_id WHERE r.user_id=u.id AND r.password_hash=u.password_hash AND r.token_generation=u.token_generation AND r.password_pending=1 AND a.action='user.totp_reset' AND a.outcome='success' AND a.actor_type='system' AND a.user_id=u.id AND a.target=u.id LIMIT 1)
	 FROM users u WHERE u.id=? AND u.auth_provider='local' AND u.password_hash=? AND u.security_revision=? AND (?<0 OR u.token_generation=?) AND u.must_change_password AND u.disabled_at IS NULL`, snapshot.UserID, snapshot.PasswordHash, snapshot.SecurityRevision, snapshot.TokenGeneration, snapshot.TokenGeneration).Scan(&temporary, &governed, &breakGlass)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrProtectedChange
		}
		return nil, err
	}
	temporaryExpiry := parseSQLiteTimeValue(temporary)
	breakGlassExpiry := parseSQLiteTime(breakGlass)
	recheck := func(at time.Time) error {
		if temporaryExpiry.IsZero() || !at.Before(temporaryExpiry) {
			return ErrTemporaryPasswordExpired
		}
		if !governed && (breakGlassExpiry == nil || !at.Before(*breakGlassExpiry)) {
			return ErrProtectedChange
		}
		return nil
	}
	if err := recheck(now); err != nil {
		return nil, err
	}
	return recheck, nil
}

func mfaSetupDeadlineRecheck(ctx context.Context, conn *sql.Conn, user string, now time.Time) (func(time.Time) error, error) {
	guard := guardSecurityPrincipal(ctx, conn, user)
	if guard == nil {
		return func(time.Time) error { return nil }, nil
	}
	if !errors.Is(guard, ErrProtectedChange) {
		return nil, guard
	}
	var governed bool
	var breakGlass sql.NullString
	err := conn.QueryRowContext(ctx, `SELECT
	 EXISTS(SELECT 1 FROM security_mfa_recoveries r JOIN security_changes c ON c.id=r.request_id WHERE r.user_id=u.id AND u.token_generation=r.token_generation AND c.state='applied' AND c.result_ref!=''),
	 (SELECT r.expires_at FROM local_break_glass_recoveries r JOIN audit_logs a ON a.id=r.audit_id WHERE r.user_id=u.id AND r.token_generation=u.token_generation AND r.password_hash=u.password_hash AND a.action='user.totp_reset' AND a.outcome='success' AND a.actor_type='system' AND a.user_id=u.id AND a.target=u.id LIMIT 1)
	 FROM users u WHERE u.id=? AND NOT u.totp_enabled AND u.disabled_at IS NULL`, user).Scan(&governed, &breakGlass)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrProtectedChange
		}
		return nil, err
	}
	breakGlassExpiry := parseSQLiteTime(breakGlass)
	recheck := func(at time.Time) error {
		if !governed && (breakGlassExpiry == nil || !at.Before(*breakGlassExpiry)) {
			return ErrProtectedChange
		}
		return nil
	}
	if err := recheck(now); err != nil {
		return nil, err
	}
	return recheck, nil
}

func (s *Store) ProtectedLDAPPrincipals() (bool, error) {
	return protectedLDAPPrincipals(context.Background(), s.db)
}
func protectedLDAPPrincipals(ctx context.Context, q securityQuerier) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM users u WHERE u.auth_provider='ldap' AND (EXISTS(SELECT 1 FROM user_roles r JOIN security_identity_links l ON l.user_id=r.user_id WHERE r.role IN ('security-officer','security-approver','original-reader') AND l.person_id=(SELECT person_id FROM security_identity_links WHERE user_id=u.id)) OR EXISTS(SELECT 1 FROM security_nominations n JOIN security_changes c ON c.id=n.request_id WHERE n.user_id=u.id AND c.state IN ('requested','partially_approved','approved','applying')))`).Scan(&n)
	return n > 0, err
}
func (s *Store) UpdateLegacyLDAPConfig(values map[string]string) error {
	return s.withImmediateTx(func(ctx context.Context, conn *sql.Conn) error {
		protected, err := protectedLDAPPrincipals(ctx, conn)
		if err != nil {
			return err
		}
		if protected {
			return ErrProtectedChange
		}
		for key, value := range values {
			if !strings.HasPrefix(key, "ldap.") {
				return ErrSecurityConflict
			}
			if _, err := conn.ExecContext(ctx, "INSERT INTO _config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Store) ClaimSecurityApplier(c model.SecurityChange, user, person string, revision int, session, proof string, now time.Time) error {
	return s.withImmediateTxClock(now, func(ctx context.Context, conn *sql.Conn, clock func() time.Time) error {
		principalGuard, err := checkSecurityPrincipal(ctx, conn, c, user, person, revision, "security.apply", clock)
		if err != nil {
			return err
		}
		policy, err := accountManagementPolicyStrict(ctx, conn)
		if err != nil {
			return err
		}
		loadPolicy := func() lockout.Policy {
			return policy
		}
		var expires int64
		if err := conn.QueryRowContext(ctx, "SELECT expires_at FROM security_changes WHERE id=? AND state='approved'", c.ID).Scan(&expires); err != nil {
			return err
		}
		if err := consumeStepupWithClock(ctx, conn, proof, user, session, "security.apply", c.Digest, clock, loadPolicy); err != nil {
			return err
		}
		now := clock()
		result, err := conn.ExecContext(ctx, "UPDATE security_changes SET applier_id=?,applier_person=?,applier_revision=? WHERE id=? AND expires_at>? AND state='approved' AND (applier_id='' OR (applier_id=? AND applier_person=? AND applier_revision=?))", user, person, revision, c.ID, now.Unix(), user, person, revision)
		if err != nil {
			return err
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return ErrSecurityConflict
		}
		if err := recheckStepupSession(ctx, conn, user, session, clock, loadPolicy); err != nil {
			return err
		}
		if err := recheckSecurityPrincipalGuards(clock, principalGuard); err != nil {
			return err
		}
		if expires <= clock().Unix() {
			return ErrSecurityConflict
		}
		return nil
	})
}
func (s *Store) validateSecurityQuorumConn(ctx context.Context, conn *sql.Conn, c model.SecurityChange, clock func() time.Time) ([]securityPrincipalGuard, error) {
	requesterGuard, err := checkSecurityPrincipal(ctx, conn, c, c.RequesterID, c.RequesterPersonID, c.RequesterGeneration, "security.request", clock)
	if err != nil {
		return nil, err
	}
	rows, err := conn.QueryContext(ctx, "SELECT user_id,person_id,token_generation FROM security_approvals WHERE request_id=? AND revision=? AND digest=? AND invalidated_at IS NULL", c.ID, c.Revision, c.Digest)
	if err != nil {
		return nil, err
	}
	type principal struct {
		user, person string
		revision     int
	}
	people := []principal{}
	for rows.Next() {
		var p principal
		if err := rows.Scan(&p.user, &p.person, &p.revision); err != nil {
			rows.Close()
			return nil, err
		}
		people = append(people, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(people) < 2 {
		return nil, ErrSecurityConflict
	}
	guards := []securityPrincipalGuard{requesterGuard}
	seen := map[string]bool{c.RequesterPersonID: true}
	for _, p := range people {
		if seen[p.person] || p.user == c.RequesterID {
			return nil, ErrSecurityConflict
		}
		seen[p.person] = true
		guard, err := checkSecurityPrincipal(ctx, conn, c, p.user, p.person, p.revision, "security.approve", clock)
		if err != nil {
			return nil, err
		}
		guards = append(guards, guard)
	}
	if err := recheckSecurityPrincipalGuards(clock, guards...); err != nil {
		return nil, err
	}
	return guards, nil
}
func (s *Store) ResumeSecurityApplying(id string) error {
	return s.changeInteractivePolicy(func() error { return s.resumeSecurityApplying(id) })
}
func (s *Store) resumeSecurityApplying(id string) error {
	result, err := s.db.Exec("UPDATE audit_policy_state SET state='applying' WHERE id=1 AND state='recovery_required' AND pending_change=? AND pending_version IS NOT NULL AND EXISTS(SELECT 1 FROM security_changes WHERE id=? AND state='applying')", id, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrSecurityConflict
	}
	return nil
}

// A scoped reader shares neither mutexes nor mutable observer state with its
// parent. Every continuity query uses the same short cancellation deadline.
func (s *Store) policyContext() context.Context {
	if s.policyReadContext != nil {
		return s.policyReadContext
	}
	return context.Background()
}
func (s *Store) terminalPolicyLive(ctx context.Context, db policyReader, actor, node string) bool {
	s.executionPolicyMu.RLock()
	validate := s.executionPolicyValidator
	s.executionPolicyMu.RUnlock()
	reader := &Store{db: s.credentialDB, policyReadDB: db, executionPolicyValidator: validate, policyReadContext: ctx}
	state, err := reader.GetPolicyState()
	if err != nil || state.State == "recovery_required" || reader.ValidateExecutionPolicy(state) != nil {
		return false
	}
	if state.Active.Policy.Covers(actor, node) || state.Pending != nil && state.Pending.Policy.Covers(actor, node) || state.Previous != nil && state.Previous.Policy.Covers(actor, node) {
		return false
	}
	return ctx.Err() == nil
}

// Policy readers are either the normal pool or the exact bounded connection
// reserved for an established terminal check. A scoped reader never copies a
// parent's locks and never opens more connections during continuity validation.
type policyReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (s *Store) policyDB() policyReader {
	if s.policyReadDB != nil {
		return s.policyReadDB
	}
	return s.db
}
