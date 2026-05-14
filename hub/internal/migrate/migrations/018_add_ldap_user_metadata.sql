ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN external_id TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN ldap_dn TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN ldap_username TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN ldap_last_sync_at TEXT;
ALTER TABLE users ADD COLUMN terminal_access INTEGER NOT NULL DEFAULT 0;

CREATE INDEX idx_users_auth_provider ON users(auth_provider);
CREATE UNIQUE INDEX idx_users_external_identity ON users(auth_provider, external_id)
    WHERE external_id != '';
