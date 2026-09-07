CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK(kind IN ('web','cli')),
    ip            TEXT NOT NULL DEFAULT '',
    user_agent    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    expires_at    TEXT,                 -- absolute; NULL = no absolute limit (policy 0 at creation)
    ended_at      TEXT,
    end_reason    TEXT,                 -- revoked_admin | revoked_self | revoked_disable | logout | expired_idle | expired_absolute
    ended_by      TEXT,                 -- user id of the actor (admin or self); NULL for expiry/disable-by-system
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id  ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_ended_at ON sessions(ended_at);
