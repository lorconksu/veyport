-- Hashed, short-lived one-use permits; originals never enter the hub database.
CREATE TABLE original_access (
 id TEXT PRIMARY KEY, execution_id TEXT NOT NULL,
 user_id TEXT NOT NULL, person_id TEXT NOT NULL, session_id TEXT NOT NULL,
 security_revision INTEGER NOT NULL, policy_version INTEGER NOT NULL,
 policy_sha256 TEXT NOT NULL, digest TEXT NOT NULL, purpose TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('envelope','script')),
 object_ref BLOB NOT NULL, actor BLOB NOT NULL, intent BLOB NOT NULL,
 intent_token TEXT NOT NULL DEFAULT '', handle_sha256 TEXT NOT NULL UNIQUE,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 consumed_at INTEGER, state TEXT NOT NULL CHECK(state IN ('pending','authorized','started','completed','interrupted','unconfirmed','expired')),
 evidence_state TEXT NOT NULL DEFAULT 'pending' CHECK(evidence_state IN ('pending','confirmed','unconfirmed','permanently_incomplete')),
 bytes_written INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX original_access_expiry ON original_access(expires_at);
CREATE TABLE original_read_evidence (
 event_id TEXT PRIMARY KEY, access_id TEXT NOT NULL REFERENCES original_access(id),
 policy_version INTEGER NOT NULL, exact_record BLOB NOT NULL CHECK(length(exact_record)<=16384),
 min_retain_until TEXT NOT NULL, created_at INTEGER NOT NULL, next_attempt_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX original_read_evidence_created ON original_read_evidence(created_at);
CREATE TABLE original_read_confirmations (
 event_id TEXT PRIMARY KEY, access_id TEXT NOT NULL, record_sha256 TEXT NOT NULL,
 manifest BLOB NOT NULL, confirmed_at INTEGER NOT NULL
);
