-- Also upgrade databases that ran the early, unreleased version of 032.
-- Discard orphaned or invalid provenance instead of granting recovery authority.
CREATE TABLE local_break_glass_recoveries_bound (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 audit_id TEXT NOT NULL REFERENCES audit_logs(id) ON DELETE CASCADE,
 password_hash TEXT NOT NULL,
 token_generation INTEGER NOT NULL,
 password_pending INTEGER NOT NULL CHECK(password_pending IN (0,1)),
 expires_at TEXT NOT NULL
);
INSERT INTO local_break_glass_recoveries_bound
 SELECT r.* FROM local_break_glass_recoveries r JOIN audit_logs a ON a.id=r.audit_id
 WHERE a.action='user.totp_reset' AND a.outcome='success' AND a.actor_type='system'
 AND a.user_id=r.user_id AND a.target=r.user_id;
DROP TABLE local_break_glass_recoveries;
ALTER TABLE local_break_glass_recoveries_bound RENAME TO local_break_glass_recoveries;
