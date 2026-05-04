-- Recreate audit_logs with ON DELETE SET NULL so user deletion doesn't fail.
-- SQLite doesn't support ALTER TABLE to change FK constraints, so we recreate.
CREATE TABLE audit_logs_new (
    id         TEXT PRIMARY KEY,
    user_id    TEXT,
    action     TEXT NOT NULL,
    target     TEXT,
    detail     TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

INSERT INTO audit_logs_new (id, user_id, action, target, detail, ip_address, created_at)
    SELECT
        audit_logs.id,
        CASE
            WHEN audit_logs.user_id IS NULL OR users.id IS NOT NULL THEN audit_logs.user_id
            ELSE NULL
        END,
        audit_logs.action,
        audit_logs.target,
        audit_logs.detail,
        audit_logs.ip_address,
        audit_logs.created_at
    FROM audit_logs
    LEFT JOIN users ON users.id = audit_logs.user_id;
DROP TABLE audit_logs;
ALTER TABLE audit_logs_new RENAME TO audit_logs;

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
