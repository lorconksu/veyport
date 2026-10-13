-- Additive governance. Legacy roles remain compatible and Standard is explicit.
CREATE TABLE security_persons (id TEXT PRIMARY KEY, verification TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE security_identity_links (user_id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES security_persons(id), provider TEXT NOT NULL, subject TEXT NOT NULL, granting_request TEXT NOT NULL DEFAULT '', UNIQUE(provider,subject));
CREATE TABLE user_roles (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, role TEXT NOT NULL CHECK(role IN ('admin','auditor','viewer','security-officer','security-approver','original-reader')), granting_request TEXT NOT NULL DEFAULT '', granted_at TEXT NOT NULL DEFAULT (datetime('now')), PRIMARY KEY(user_id,role));
INSERT INTO security_persons(id) SELECT 'user:'||id FROM users;
INSERT INTO security_identity_links SELECT id,'user:'||id,auth_provider,CASE WHEN external_id='' THEN id ELSE external_id END,'' FROM users;
INSERT INTO user_roles(user_id,role) SELECT id,role FROM users;
CREATE TRIGGER governance_new_user AFTER INSERT ON users BEGIN
 INSERT INTO security_persons(id) VALUES ('user:'||NEW.id);
 INSERT INTO security_identity_links VALUES(NEW.id,'user:'||NEW.id,NEW.auth_provider,CASE WHEN NEW.external_id='' THEN NEW.id ELSE NEW.external_id END,'');
 INSERT INTO user_roles(user_id,role) VALUES(NEW.id,NEW.role);
END;
CREATE TRIGGER governance_legacy_role AFTER UPDATE OF role ON users WHEN OLD.role!=NEW.role BEGIN
 DELETE FROM user_roles WHERE user_id=NEW.id AND role IN ('admin','auditor','viewer');
 INSERT INTO user_roles(user_id,role) VALUES(NEW.id,NEW.role);
END;
CREATE TABLE audit_policy_versions(version INTEGER PRIMARY KEY CHECK(version>0), payload BLOB NOT NULL, digest TEXT NOT NULL, request_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')));
INSERT INTO audit_policy_versions VALUES(1,'{"profile":"standard","actors":[],"nodes":[],"runtime_seconds":3600,"retention_hours":24,"destination":"","credential_ref":"","trust_key_ids":[],"qualification_sha256":""}','','',datetime('now'));
CREATE TABLE audit_policy_state(id INTEGER PRIMARY KEY CHECK(id=1), active_version INTEGER NOT NULL REFERENCES audit_policy_versions(version), state TEXT NOT NULL CHECK(state IN ('standard','setup_pending','enhanced','applying','recovery_required')), pending_version INTEGER REFERENCES audit_policy_versions(version), pending_change TEXT NOT NULL DEFAULT '');
INSERT INTO audit_policy_state VALUES(1,1,'standard',NULL,'');
CREATE TABLE security_changes(id TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK(revision>0), requester_id TEXT NOT NULL, requester_person TEXT NOT NULL, requester_generation INTEGER NOT NULL, expected_version INTEGER NOT NULL, digest TEXT NOT NULL CHECK(length(digest)=64), reason TEXT NOT NULL CHECK(length(reason)>0), payload BLOB NOT NULL, state TEXT NOT NULL CHECK(state IN ('requested','partially_approved','approved','applying','applied','expired','superseded','failed','rejected')), created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, intent_ref TEXT NOT NULL DEFAULT '', commit_ref TEXT NOT NULL DEFAULT '', result_ref TEXT NOT NULL DEFAULT '');
CREATE INDEX security_changes_state_expiry ON security_changes(state,expires_at);
CREATE TABLE security_nominations(request_id TEXT NOT NULL REFERENCES security_changes(id), user_id TEXT NOT NULL, person_id TEXT NOT NULL, roles BLOB NOT NULL, verification TEXT NOT NULL, PRIMARY KEY(request_id,user_id));
CREATE TABLE security_approvals(request_id TEXT NOT NULL REFERENCES security_changes(id), revision INTEGER NOT NULL, digest TEXT NOT NULL, user_id TEXT NOT NULL, person_id TEXT NOT NULL, proof_sha256 TEXT NOT NULL, token_generation INTEGER NOT NULL, approved_at INTEGER NOT NULL, PRIMARY KEY(request_id,revision,person_id), UNIQUE(request_id,revision,user_id));
CREATE TABLE stepup_proofs(hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, session_id TEXT NOT NULL, action TEXT NOT NULL, digest TEXT NOT NULL CHECK(length(digest)=64), created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER);
CREATE INDEX stepup_expiry ON stepup_proofs(expires_at);
CREATE TABLE security_secrets(ref TEXT PRIMARY KEY, encrypted BLOB NOT NULL, created_by TEXT NOT NULL, created_at INTEGER NOT NULL);
ALTER TABLE users ADD COLUMN security_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE security_approvals ADD COLUMN invalidated_at INTEGER;
CREATE TRIGGER governance_credentials AFTER UPDATE OF password_hash,totp_secret,totp_enabled,role,auth_provider,external_id,disabled_at,username,ldap_dn,ldap_username,terminal_access,must_change_password ON users
WHEN OLD.password_hash IS NOT NEW.password_hash OR OLD.totp_secret IS NOT NEW.totp_secret OR OLD.totp_enabled IS NOT NEW.totp_enabled OR OLD.role IS NOT NEW.role OR OLD.auth_provider IS NOT NEW.auth_provider OR OLD.external_id IS NOT NEW.external_id OR OLD.disabled_at IS NOT NEW.disabled_at OR OLD.username IS NOT NEW.username OR OLD.ldap_dn IS NOT NEW.ldap_dn OR OLD.ldap_username IS NOT NEW.ldap_username OR OLD.terminal_access IS NOT NEW.terminal_access OR OLD.must_change_password IS NOT NEW.must_change_password BEGIN
 UPDATE users SET security_revision=security_revision+1 WHERE id=NEW.id;
 UPDATE stepup_proofs SET consumed_at=COALESCE(consumed_at,unixepoch()) WHERE user_id=NEW.id;
 UPDATE security_approvals SET invalidated_at=unixepoch() WHERE user_id=NEW.id;
END;
CREATE TRIGGER governance_security_role_grant AFTER INSERT ON user_roles WHEN NEW.role IN ('security-officer','security-approver','original-reader') BEGIN
 UPDATE users SET security_revision=security_revision+1,token_generation=token_generation+1 WHERE id=NEW.user_id;
 UPDATE stepup_proofs SET consumed_at=COALESCE(consumed_at,unixepoch()) WHERE user_id=NEW.user_id;
 UPDATE security_approvals SET invalidated_at=unixepoch() WHERE user_id=NEW.user_id;
END;
CREATE TRIGGER governance_security_role_revoke AFTER DELETE ON user_roles WHEN OLD.role IN ('security-officer','security-approver','original-reader') BEGIN
 UPDATE users SET security_revision=security_revision+1,token_generation=token_generation+1 WHERE id=OLD.user_id;
 UPDATE stepup_proofs SET consumed_at=COALESCE(consumed_at,unixepoch()) WHERE user_id=OLD.user_id;
 UPDATE security_approvals SET invalidated_at=unixepoch() WHERE user_id=OLD.user_id;
END;
CREATE TRIGGER governance_person_link AFTER UPDATE OF person_id ON security_identity_links WHEN OLD.person_id!=NEW.person_id BEGIN
 UPDATE users SET security_revision=security_revision+1,token_generation=token_generation+1 WHERE id=NEW.user_id;
 UPDATE stepup_proofs SET consumed_at=COALESCE(consumed_at,unixepoch()) WHERE user_id=NEW.user_id;
 UPDATE security_approvals SET invalidated_at=unixepoch() WHERE user_id=NEW.user_id;
END;
CREATE TABLE security_evidence(request_id TEXT NOT NULL REFERENCES security_changes(id),event_type TEXT NOT NULL,exact_record BLOB NOT NULL,reference TEXT NOT NULL DEFAULT '',PRIMARY KEY(request_id,event_type));
ALTER TABLE security_changes ADD COLUMN applier_id TEXT NOT NULL DEFAULT '';
ALTER TABLE security_changes ADD COLUMN applier_person TEXT NOT NULL DEFAULT '';
ALTER TABLE security_changes ADD COLUMN applier_revision INTEGER NOT NULL DEFAULT 0;
CREATE TABLE security_password_recoveries(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,request_id TEXT NOT NULL REFERENCES security_changes(id),password_hash TEXT NOT NULL);
CREATE TABLE security_mfa_recoveries(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,request_id TEXT NOT NULL REFERENCES security_changes(id),token_generation INTEGER NOT NULL);
