-- Shell-only recovery authority is separate from independently approved changes.
-- Bind it to the exact credential generation and the atomic system audit.
CREATE TABLE local_break_glass_recoveries (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 audit_id TEXT NOT NULL REFERENCES audit_logs(id) ON DELETE CASCADE,
 password_hash TEXT NOT NULL,
 token_generation INTEGER NOT NULL,
 password_pending INTEGER NOT NULL CHECK(password_pending IN (0,1)),
 expires_at TEXT NOT NULL
);
