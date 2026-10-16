package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

var ErrApplicationConflict = errors.New("application changed or unavailable")

func (s *Store) CreateApplication(a *model.Application, now time.Time) error {
	a.ConfigVersion = 1
	a.CreatedAt = now
	a.UpdatedAt = now
	b, e := json.Marshal(a)
	if e != nil {
		return e
	}
	_, e = s.db.Exec(`INSERT INTO applications(id,slug,public_hostname,name,config_version,enabled,config_json)VALUES(?,?,?,?,1,?,?)`, a.ID, a.Slug, a.PublicHostname, a.Name, a.Enabled, string(b))
	return e
}
func (s *Store) GetApplication(id string) (*model.Application, error) {
	var b string
	if e := s.db.QueryRow(`SELECT config_json FROM applications WHERE id=?`, id).Scan(&b); e != nil {
		return nil, e
	}
	var a model.Application
	e := json.Unmarshal([]byte(b), &a)
	return &a, e
}
func (s *Store) GetApplicationByHost(host string) (*model.Application, error) {
	var id string
	if e := s.db.QueryRow(`SELECT id FROM applications WHERE public_hostname=?`, host).Scan(&id); e != nil {
		return nil, e
	}
	return s.GetApplication(id)
}
func (s *Store) ListApplications(limit, offset int) ([]model.Application, int, error) {
	var total int
	if e := s.db.QueryRow(`SELECT count(*) FROM applications`).Scan(&total); e != nil {
		return nil, 0, e
	}
	rows, e := s.db.Query(`SELECT config_json FROM applications ORDER BY name,id LIMIT ? OFFSET ?`, limit, offset)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	out := []model.Application{}
	for rows.Next() {
		var b string
		var a model.Application
		if e = rows.Scan(&b); e != nil {
			return nil, 0, e
		}
		if e = json.Unmarshal([]byte(b), &a); e != nil {
			return nil, 0, e
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}
func (s *Store) UpdateApplication(a *model.Application, expected int64, now time.Time) error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a.ConfigVersion = expected + 1
	a.UpdatedAt = now
	b, e := json.Marshal(a)
	if e != nil {
		return e
	}
	res, e := tx.Exec(`UPDATE applications SET slug=?,public_hostname=?,name=?,config_version=?,enabled=?,config_json=? WHERE id=? AND config_version=? AND deleting=0`, a.Slug, a.PublicHostname, a.Name, a.ConfigVersion, a.Enabled, string(b), a.ID, expected)
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrApplicationConflict
	}
	if _, e = tx.Exec(`UPDATE application_sessions SET ended_at=?,end_reason='configuration_changed' WHERE app_id=? AND ended_at IS NULL`, now.UnixMilli(), a.ID); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) DeleteApplication(id string) error {
	res, e := s.db.Exec(`DELETE FROM applications WHERE id=? AND deleting=1 AND NOT EXISTS(SELECT 1 FROM application_sessions WHERE app_id=applications.id AND (ended_at IS NULL OR audited_at IS NULL))`, id)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrApplicationConflict
	}
	return nil
}
func (s *Store) ApplicationGrants(id string) ([]model.ApplicationGrant, error) {
	rows, e := s.db.Query(`SELECT kind,subject_id FROM application_grants WHERE application_id=? ORDER BY kind,subject_id`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.ApplicationGrant{}
	for rows.Next() {
		var g model.ApplicationGrant
		if e = rows.Scan(&g.Kind, &g.SubjectID); e != nil {
			return nil, e
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *Store) ReplaceApplicationGrants(id string, grants []model.ApplicationGrant, expected int64, now time.Time) error {
	a, e := s.GetApplication(id)
	if e != nil {
		return e
	}
	a.ConfigVersion = expected + 1
	a.UpdatedAt = now
	b, e := json.Marshal(a)
	if e != nil {
		return e
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	res, e := tx.Exec(`UPDATE applications SET config_version=?,config_json=? WHERE id=? AND config_version=? AND deleting=0`, a.ConfigVersion, string(b), id, expected)
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrApplicationConflict
	}
	if _, e = tx.Exec(`DELETE FROM application_grants WHERE application_id=?`, id); e != nil {
		return e
	}
	for _, g := range grants {
		if _, e = tx.Exec(`INSERT INTO application_grants(application_id,kind,subject_id)VALUES(?,?,?)`, id, g.Kind, g.SubjectID); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(`UPDATE application_sessions SET ended_at=?,end_reason='grants_changed' WHERE app_id=? AND ended_at IS NULL`, now.UnixMilli(), id); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) ApplicationAccessRevision(user string) (int64, error) {
	var n int64
	e := s.db.QueryRow(`SELECT revision FROM application_access_versions WHERE user_id=?`, user).Scan(&n)
	if errors.Is(e, sql.ErrNoRows) {
		return 0, nil
	}
	return n, e
}
func (s *Store) ApplicationLocalMemberships(user string) (map[string]bool, error) {
	rows, e := s.db.Query(`SELECT group_id FROM application_group_members WHERE user_id=?`, user)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		out[id] = true
	}
	return out, rows.Err()
}
func (s *Store) EnsureApplicationAnchor(a model.ApplicationAnchor) error {
	_, e := s.db.Exec(`INSERT INTO application_login_anchors(id,user_id,completed_mfa_at,token_generation)VALUES(?,?,?,?)ON CONFLICT(id)DO NOTHING`, a.ID, a.UserID, a.CompletedMFAAt.UnixMilli(), a.TokenGeneration)
	if e != nil {
		return e
	}
	stored, e := s.GetApplicationAnchor(a.ID)
	if e != nil {
		return e
	}
	if stored.RevokedAt != nil || stored.UserID != a.UserID || stored.TokenGeneration != a.TokenGeneration || stored.CompletedMFAAt.UnixMilli() != a.CompletedMFAAt.UnixMilli() {
		return ErrApplicationConflict
	}
	return nil
}
func (s *Store) GetApplicationAnchor(id string) (*model.ApplicationAnchor, error) {
	var a model.ApplicationAnchor
	var ts int64
	var revoked sql.NullInt64
	e := s.db.QueryRow(`SELECT id,user_id,completed_mfa_at,token_generation,revoked_at FROM application_login_anchors WHERE id=?`, id).Scan(&a.ID, &a.UserID, &ts, &a.TokenGeneration, &revoked)
	a.CompletedMFAAt = time.UnixMilli(ts).UTC()
	if revoked.Valid {
		t := time.UnixMilli(revoked.Int64).UTC()
		a.RevokedAt = &t
	}
	return &a, e
}
func (s *Store) CreateApplicationTicket(t model.ApplicationLaunchTicket) error {
	res, e := s.db.Exec(`INSERT INTO application_launch_tickets(digest,app_id,user_id,anchor_id,hostname,path,config_version,access_revision,directory_fingerprint,expires_at) SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM application_login_anchors WHERE id=? AND revoked_at IS NULL) AND EXISTS(SELECT 1 FROM applications WHERE id=? AND enabled=1 AND deleting=0 AND config_version=?)`, t.Digest, t.ApplicationID, t.UserID, t.AnchorID, t.Hostname, t.Path, t.ConfigVersion, t.AccessRevision, t.DirectoryFingerprint, t.ExpiresAt.UnixMilli(), t.AnchorID, t.ApplicationID, t.ConfigVersion)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrApplicationConflict
	}
	return nil
}
func (s *Store) ConsumeApplicationTicket(digest, host string, ss model.ApplicationSession, now time.Time) (string, error) {
	tx, e := s.db.BeginTx(context.Background(), nil)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	var t model.ApplicationLaunchTicket
	e = tx.QueryRow(`DELETE FROM application_launch_tickets WHERE digest=? AND hostname=? AND expires_at>? RETURNING app_id,user_id,anchor_id,path,config_version,access_revision,directory_fingerprint`, digest, host, now.UnixMilli()).Scan(&t.ApplicationID, &t.UserID, &t.AnchorID, &t.Path, &t.ConfigVersion, &t.AccessRevision, &t.DirectoryFingerprint)
	if e != nil {
		return "", ErrApplicationConflict
	}
	res, e := tx.Exec(`INSERT INTO application_sessions(id,credential_digest,app_id,user_id,anchor_id,config_version,access_revision,directory_fingerprint,created_at,last_seen_at,expires_at) SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM application_login_anchors la JOIN users u ON u.id=la.user_id WHERE la.id=? AND la.revoked_at IS NULL AND la.token_generation=u.token_generation AND u.disabled_at IS NULL) AND EXISTS(SELECT 1 FROM applications WHERE id=? AND enabled=1 AND deleting=0 AND config_version=?) AND COALESCE((SELECT revision FROM application_access_versions WHERE user_id=?),0)=?`, ss.ID, ss.CredentialDigest, t.ApplicationID, t.UserID, t.AnchorID, t.ConfigVersion, t.AccessRevision, t.DirectoryFingerprint, now.UnixMilli(), now.UnixMilli(), ss.ExpiresAt.UnixMilli(), t.AnchorID, t.ApplicationID, t.ConfigVersion, t.UserID, t.AccessRevision)
	if e != nil {
		return "", e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return "", ErrApplicationConflict
	}
	if e = tx.Commit(); e != nil {
		return "", e
	}
	return t.Path, nil
}

const applicationSessionColumns = `id,credential_digest,app_id,user_id,anchor_id,config_version,access_revision,directory_fingerprint,created_at,last_seen_at,expires_at,ended_at,end_reason`

func scanApplicationSession(row interface{ Scan(...any) error }) (*model.ApplicationSession, error) {
	var s model.ApplicationSession
	var created, seen, expires int64
	var ended sql.NullInt64
	e := row.Scan(&s.ID, &s.CredentialDigest, &s.ApplicationID, &s.UserID, &s.AnchorID, &s.ConfigVersion, &s.AccessRevision, &s.DirectoryFingerprint, &created, &seen, &expires, &ended, &s.EndReason)
	s.CreatedAt = time.UnixMilli(created).UTC()
	s.LastSeenAt = time.UnixMilli(seen).UTC()
	s.ExpiresAt = time.UnixMilli(expires).UTC()
	if ended.Valid {
		t := time.UnixMilli(ended.Int64).UTC()
		s.EndedAt = &t
	}
	return &s, e
}
func (s *Store) GetApplicationSession(digest string) (*model.ApplicationSession, error) {
	return scanApplicationSession(s.db.QueryRow(`SELECT `+applicationSessionColumns+` FROM application_sessions WHERE credential_digest=?`, digest))
}
func (s *Store) TouchApplicationSession(id string, now time.Time) error {
	_, e := s.db.Exec(`UPDATE application_sessions SET last_seen_at=? WHERE id=? AND ended_at IS NULL AND expires_at>?`, now.UnixMilli(), id, now.UnixMilli())
	return e
}
func (s *Store) EndApplicationSession(id, reason string, now time.Time) error {
	_, e := s.db.Exec(`UPDATE application_sessions SET ended_at=?,end_reason=? WHERE id=? AND ended_at IS NULL`, now.UnixMilli(), reason, id)
	return e
}
func (s *Store) RevokeApplicationFamily(user, anchor, reason string, now time.Time) error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`UPDATE application_login_anchors SET revoked_at=?,reason=? WHERE user_id=? AND id=? AND revoked_at IS NULL`, now.UnixMilli(), reason, user, anchor); e != nil {
		return e
	}
	if _, e = tx.Exec(`UPDATE application_sessions SET ended_at=?,end_reason=? WHERE user_id=? AND anchor_id=? AND ended_at IS NULL`, now.UnixMilli(), reason, user, anchor); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) RevokeUserApplications(user, except, reason string, now time.Time) error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`UPDATE application_login_anchors SET revoked_at=?,reason=? WHERE user_id=? AND id<>? AND revoked_at IS NULL`, now.UnixMilli(), reason, user, except); e != nil {
		return e
	}
	if _, e = tx.Exec(`UPDATE application_sessions SET ended_at=?,end_reason=? WHERE user_id=? AND anchor_id<>? AND ended_at IS NULL`, now.UnixMilli(), reason, user, except); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) ListApplicationSessions(user string, limit, offset int) ([]model.ApplicationSession, error) {
	rows, e := s.db.Query(`SELECT ss.id,ss.credential_digest,ss.app_id,ss.user_id,ss.anchor_id,ss.config_version,ss.access_revision,ss.directory_fingerprint,ss.created_at,ss.last_seen_at,ss.expires_at,ss.ended_at,ss.end_reason,a.name FROM application_sessions ss JOIN applications a ON a.id=ss.app_id WHERE ss.user_id=? ORDER BY ss.created_at DESC,ss.id LIMIT ? OFFSET ?`, user, limit, offset)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.ApplicationSession{}
	for rows.Next() {
		var name string
		ss, e := scanApplicationSession(applicationNamedRow{rows, &name})
		ss.ApplicationName = name
		if e != nil {
			return nil, e
		}
		out = append(out, *ss)
	}
	return out, rows.Err()
}
func (s *Store) ListApplicationGroups(limit, offset int) ([]model.ApplicationGroup, int, error) {
	var total int
	if e := s.db.QueryRow(`SELECT count(*) FROM application_groups`).Scan(&total); e != nil {
		return nil, 0, e
	}
	rows, e := s.db.Query(`SELECT g.id,g.name,g.version,count(m.user_id) FROM application_groups g LEFT JOIN application_group_members m ON m.group_id=g.id GROUP BY g.id ORDER BY g.name,g.id LIMIT ? OFFSET ?`, limit, offset)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	out := []model.ApplicationGroup{}
	for rows.Next() {
		var g model.ApplicationGroup
		g.UserIDs = []string{}
		if e = rows.Scan(&g.ID, &g.Name, &g.Version, &g.MemberCount); e != nil {
			return nil, 0, e
		}
		out = append(out, g)
	}
	return out, total, rows.Err()
}
func (s *Store) GetApplicationGroup(id string) (*model.ApplicationGroup, error) {
	var g model.ApplicationGroup
	e := s.db.QueryRow(`SELECT id,name,version FROM application_groups WHERE id=?`, id).Scan(&g.ID, &g.Name, &g.Version)
	if e != nil {
		return nil, e
	}
	rows, e := s.db.Query(`SELECT user_id FROM application_group_members WHERE group_id=? ORDER BY user_id`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	g.UserIDs = []string{}
	for rows.Next() {
		var u string
		if e = rows.Scan(&u); e != nil {
			return nil, e
		}
		g.UserIDs = append(g.UserIDs, u)
	}
	return &g, rows.Err()
}
func (s *Store) PutApplicationGroup(g *model.ApplicationGroup, expected int64) error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if expected == 0 {
		_, e = tx.Exec(`INSERT INTO application_groups(id,name,version)VALUES(?,?,1)`, g.ID, g.Name)
		g.Version = 1
	} else {
		var res sql.Result
		res, e = tx.Exec(`UPDATE application_groups SET name=?,version=version+1 WHERE id=? AND version=?`, g.Name, g.ID, expected)
		if e == nil {
			n, _ := res.RowsAffected()
			if n != 1 {
				return ErrApplicationConflict
			}
		}
		g.Version = expected + 1
	}
	if e != nil {
		return e
	}
	if _, e = tx.Exec(`DELETE FROM application_group_members WHERE group_id=?`, g.ID); e != nil {
		return e
	}
	for _, u := range g.UserIDs {
		if _, e = tx.Exec(`INSERT INTO application_group_members(group_id,user_id)VALUES(?,?)`, g.ID, u); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) DeleteApplicationGroup(id string) error {
	_, e := s.db.Exec(`DELETE FROM application_groups WHERE id=?`, id)
	return e
}
func (s *Store) ApplicationSessionByID(id string) (*model.ApplicationSession, error) {
	return scanApplicationSession(s.db.QueryRow(`SELECT `+applicationSessionColumns+` FROM application_sessions WHERE id=?`, id))
}
func (s *Store) CompareApplicationPolicy(expected int64, value string) error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var old string
	e = tx.QueryRow(`SELECT value FROM _config WHERE key='application.policy'`).Scan(&old)
	if errors.Is(e, sql.ErrNoRows) {
		if expected != 1 {
			return ErrApplicationConflict
		}
		_, e = tx.Exec(`INSERT INTO _config(key,value)VALUES('application.policy',?)`, value)
	} else if e == nil {
		var p struct {
			Version int64 `json:"version"`
		}
		if json.Unmarshal([]byte(old), &p) != nil || p.Version != expected {
			return ErrApplicationConflict
		}
		_, e = tx.Exec(`UPDATE _config SET value=? WHERE key='application.policy'`, value)
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) ListAuthorizedApplications(claims []model.ApplicationGrant, limit, offset int) ([]model.Application, int, error) {
	b, e := json.Marshal(claims)
	if e != nil {
		return nil, 0, e
	}
	const predicate = `enabled=1 AND EXISTS(SELECT 1 FROM application_grants g JOIN json_each(?) j ON g.kind=json_extract(j.value,'$.kind') AND g.subject_id=json_extract(j.value,'$.subject_id') WHERE g.application_id=applications.id)`
	var total int
	if e = s.db.QueryRow(`SELECT count(*) FROM applications WHERE `+predicate, string(b)).Scan(&total); e != nil {
		return nil, 0, e
	}
	rows, e := s.db.Query(`SELECT config_json FROM applications WHERE `+predicate+` ORDER BY name,id LIMIT ? OFFSET ?`, string(b), limit, offset)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	out := []model.Application{}
	for rows.Next() {
		var b string
		var a model.Application
		if e = rows.Scan(&b); e != nil {
			return nil, 0, e
		}
		if e = json.Unmarshal([]byte(b), &a); e != nil {
			return nil, 0, e
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}
func (s *Store) GetApplicationTicket(digest, host string, now time.Time) (*model.ApplicationLaunchTicket, error) {
	var t model.ApplicationLaunchTicket
	var ts int64
	e := s.db.QueryRow(`SELECT digest,app_id,user_id,anchor_id,hostname,path,config_version,access_revision,directory_fingerprint,expires_at FROM application_launch_tickets WHERE digest=? AND hostname=? AND expires_at>?`, digest, host, now.UnixMilli()).Scan(&t.Digest, &t.ApplicationID, &t.UserID, &t.AnchorID, &t.Hostname, &t.Path, &t.ConfigVersion, &t.AccessRevision, &t.DirectoryFingerprint, &ts)
	t.ExpiresAt = time.UnixMilli(ts).UTC()
	return &t, e
}

type ApplicationUserSubject struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

func (s *Store) ApplicationUserSubjects(q string, limit, offset int) ([]ApplicationUserSubject, int, error) {
	var total int
	search := "%" + q + "%"
	if e := s.db.QueryRow(`SELECT count(*) FROM users WHERE username LIKE ?`, search).Scan(&total); e != nil {
		return nil, 0, e
	}
	rows, e := s.db.Query(`SELECT id,username FROM users WHERE username LIKE ? ORDER BY username,id LIMIT ? OFFSET ?`, search, limit, offset)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	out := []ApplicationUserSubject{}
	for rows.Next() {
		var u ApplicationUserSubject
		if e = rows.Scan(&u.ID, &u.Username); e != nil {
			return nil, 0, e
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

type applicationNamedRow struct {
	row  interface{ Scan(...any) error }
	name *string
}

func (r applicationNamedRow) Scan(args ...any) error { return r.row.Scan(append(args, r.name)...) }

// Cleanup is independent of the dashboard rows; anchors outlive every ticket
// and app descendant, including active apps whose source dashboard was pruned.
func (s *Store) PruneApplicationRecords(now time.Time, retention time.Duration) error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`DELETE FROM application_launch_tickets WHERE expires_at<=?`, now.UnixMilli()); e != nil {
		return e
	}
	cutoff := now.Add(-retention).UnixMilli()
	if _, e = tx.Exec(`DELETE FROM application_sessions WHERE audited_at IS NOT NULL AND (expires_at<? OR ended_at<?)`, cutoff, cutoff); e != nil {
		return e
	}
	if _, e = tx.Exec(`DELETE FROM application_login_anchors WHERE completed_mfa_at<? AND NOT EXISTS(SELECT 1 FROM application_sessions WHERE anchor_id=application_login_anchors.id) AND NOT EXISTS(SELECT 1 FROM application_launch_tickets WHERE anchor_id=application_login_anchors.id)`, cutoff); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) UnauditedApplicationSessionEnds(limit int) ([]model.ApplicationSession, error) {
	rows, e := s.db.Query(`SELECT `+applicationSessionColumns+` FROM application_sessions WHERE ended_at IS NOT NULL AND audited_at IS NULL ORDER BY ended_at,id LIMIT ?`, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.ApplicationSession{}
	for rows.Next() {
		ss, e := scanApplicationSession(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, *ss)
	}
	return out, rows.Err()
}
func (s *Store) ApplicationAuditExists(id string) (bool, error) {
	var count int
	e := s.db.QueryRow(`SELECT count(*) FROM audit_logs WHERE id=?`, id).Scan(&count)
	return count > 0, e
}
func (s *Store) MarkApplicationEndAudited(id string) error {
	_, e := s.db.Exec(`UPDATE application_sessions SET audited_at=ended_at WHERE id=? AND ended_at IS NOT NULL`, id)
	return e
}
func (s *Store) CountApplicationSessions(user string) (int, error) {
	var total int
	e := s.db.QueryRow(`SELECT count(*) FROM application_sessions WHERE user_id=?`, user).Scan(&total)
	return total, e
}
func (s *Store) ExpireApplicationSessions(now time.Time, idle, max time.Duration) error {
	_, e := s.db.Exec(`UPDATE application_sessions SET ended_at=MIN(expires_at,(SELECT completed_mfa_at+? FROM application_login_anchors WHERE id=anchor_id)),end_reason='expired_absolute' WHERE ended_at IS NULL AND MIN(expires_at,(SELECT completed_mfa_at+? FROM application_login_anchors WHERE id=anchor_id))<=?`, max.Milliseconds(), max.Milliseconds(), now.UnixMilli())
	if e != nil {
		return e
	}
	_, e = s.db.Exec(`UPDATE application_sessions SET ended_at=last_seen_at+?,end_reason='expired_idle' WHERE ended_at IS NULL AND last_seen_at+?<?`, idle.Milliseconds(), idle.Milliseconds(), now.UnixMilli())
	return e
}

// BeginApplicationDeletion takes SQLite's writer lock before reading any
// admission state. Either ticket consumption commits first and is ended here,
// or this transaction commits first and no ticket can subsequently be admitted.
func (s *Store) BeginApplicationDeletion(app string, now time.Time) error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	res, e := tx.Exec(`UPDATE applications SET enabled=0,config_version=CASE WHEN deleting=0 THEN config_version+1 ELSE config_version END,config_json=json_set(config_json,'$.enabled',json('false'),'$.config_version',CASE WHEN deleting=0 THEN config_version+1 ELSE config_version END,'$.updated_at',?),deleting=1 WHERE id=?`, now.UTC().Format(time.RFC3339Nano), app)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrApplicationConflict
	}
	if _, e = tx.Exec(`DELETE FROM application_launch_tickets WHERE app_id=?`, app); e != nil {
		return e
	}
	if _, e = tx.Exec(`UPDATE application_sessions SET ended_at=?,end_reason='application_deleted' WHERE app_id=? AND ended_at IS NULL`, now.UnixMilli(), app); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) PendingApplicationEndAudits(app string) (int, error) {
	var count int
	e := s.db.QueryRow(`SELECT count(*) FROM application_sessions WHERE app_id=? AND ended_at IS NOT NULL AND audited_at IS NULL`, app).Scan(&count)
	return count, e
}

// EndAllApplicationSessions is a fail-closed startup/overflow boundary. Pending
// launch tickets cannot survive it and create fresh descendants of old state.
func (s *Store) EndAllApplicationSessions(reason string, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE application_sessions SET ended_at=?,end_reason=? WHERE ended_at IS NULL`, now.UnixMilli(), reason); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM application_launch_tickets`); err != nil {
		return err
	}
	return tx.Commit()
}
