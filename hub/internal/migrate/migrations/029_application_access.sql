CREATE TABLE applications (
 id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, public_hostname TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL, config_version INTEGER NOT NULL, enabled INTEGER NOT NULL,
 config_json TEXT NOT NULL
);
CREATE TABLE application_grants (
 application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind IN ('user','role','local_group','directory_group')),
 subject_id TEXT NOT NULL, PRIMARY KEY(application_id,kind,subject_id)
);
CREATE TABLE application_groups (id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,version INTEGER NOT NULL DEFAULT 1);
CREATE TABLE application_group_members (
 group_id TEXT NOT NULL REFERENCES application_groups(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(group_id,user_id)
);
CREATE TABLE application_access_versions (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, revision INTEGER NOT NULL DEFAULT 0);
CREATE TABLE application_login_anchors (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 completed_mfa_at INTEGER NOT NULL, token_generation INTEGER NOT NULL,
 revoked_at INTEGER, reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX application_anchor_user ON application_login_anchors(user_id);
CREATE TABLE application_launch_tickets (
 digest TEXT PRIMARY KEY, app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 anchor_id TEXT NOT NULL REFERENCES application_login_anchors(id) ON DELETE CASCADE,
 hostname TEXT NOT NULL,path TEXT NOT NULL,config_version INTEGER NOT NULL,
 access_revision INTEGER NOT NULL,directory_fingerprint TEXT NOT NULL DEFAULT '',expires_at INTEGER NOT NULL
);
CREATE INDEX application_ticket_expiry ON application_launch_tickets(expires_at);
 CREATE TABLE application_sessions (
 id TEXT PRIMARY KEY, credential_digest TEXT NOT NULL UNIQUE,
 app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 anchor_id TEXT NOT NULL REFERENCES application_login_anchors(id) ON DELETE CASCADE,
 config_version INTEGER NOT NULL,access_revision INTEGER NOT NULL,
 directory_fingerprint TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,
 last_seen_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,ended_at INTEGER,audited_at INTEGER,end_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX application_session_expiry ON application_sessions(expires_at);
 CREATE INDEX application_session_audit ON application_sessions(audited_at,ended_at);
 CREATE INDEX application_session_user ON application_sessions(user_id,ended_at);
CREATE INDEX application_session_app ON application_sessions(app_id,ended_at);
CREATE INDEX application_session_anchor ON application_sessions(anchor_id,ended_at);
CREATE TRIGGER application_role_added AFTER INSERT ON user_roles BEGIN
 INSERT INTO application_access_versions(user_id,revision) VALUES (NEW.user_id,1) ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
 UPDATE application_sessions SET ended_at=CAST(unixepoch('subsec')*1000 AS INTEGER),end_reason='access_changed' WHERE user_id=NEW.user_id AND ended_at IS NULL;
END;
CREATE TRIGGER application_role_removed AFTER DELETE ON user_roles BEGIN
 INSERT INTO application_access_versions(user_id,revision) SELECT OLD.user_id,1 WHERE EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id) ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
 UPDATE application_sessions SET ended_at=CAST(unixepoch('subsec')*1000 AS INTEGER),end_reason='access_changed' WHERE user_id=OLD.user_id AND ended_at IS NULL;
END;
CREATE TRIGGER application_membership_added AFTER INSERT ON application_group_members BEGIN
 INSERT INTO application_access_versions(user_id,revision) VALUES (NEW.user_id,1) ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
 UPDATE application_sessions SET ended_at=CAST(unixepoch('subsec')*1000 AS INTEGER),end_reason='access_changed' WHERE user_id=NEW.user_id AND ended_at IS NULL;
END;
CREATE TRIGGER application_membership_removed AFTER DELETE ON application_group_members BEGIN
 INSERT INTO application_access_versions(user_id,revision) SELECT OLD.user_id,1 WHERE EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id) ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
 UPDATE application_sessions SET ended_at=CAST(unixepoch('subsec')*1000 AS INTEGER),end_reason='access_changed' WHERE user_id=OLD.user_id AND ended_at IS NULL;
END;
CREATE TRIGGER application_account_changed AFTER UPDATE OF role,token_generation,security_revision,disabled_at ON users
 WHEN OLD.role IS NOT NEW.role OR OLD.token_generation IS NOT NEW.token_generation OR OLD.security_revision IS NOT NEW.security_revision OR OLD.disabled_at IS NOT NEW.disabled_at BEGIN
 INSERT INTO application_access_versions(user_id,revision) VALUES (NEW.id,1) ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
 UPDATE application_sessions SET ended_at=CAST(unixepoch('subsec')*1000 AS INTEGER),end_reason='account_changed' WHERE user_id=NEW.id AND ended_at IS NULL;
END;
