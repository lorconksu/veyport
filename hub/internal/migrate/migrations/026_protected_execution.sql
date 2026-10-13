ALTER TABLE executions ADD COLUMN enhanced INTEGER NOT NULL DEFAULT 0;
ALTER TABLE executions ADD COLUMN actor_person_id TEXT NOT NULL DEFAULT '';
ALTER TABLE executions ADD COLUMN actor_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE executions ADD COLUMN policy_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE executions ADD COLUMN script_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE executions ADD COLUMN script_length INTEGER NOT NULL DEFAULT 0;
ALTER TABLE executions ADD COLUMN admission_event_id TEXT NOT NULL DEFAULT '';
ALTER TABLE executions ADD COLUMN admission_record_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE executions ADD COLUMN admission_receipt TEXT NOT NULL DEFAULT '';
ALTER TABLE executions ADD COLUMN admission_disposition TEXT NOT NULL DEFAULT '';
ALTER TABLE execution_dispatches ADD COLUMN receipt_sha256 TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX execution_receipt_single_use ON execution_dispatches(receipt_sha256) WHERE receipt_sha256 != '';

-- Only bounded redacted lifecycle envelopes belong here. No command, script or
-- output payload is retained. Admission is always synchronous and external.
CREATE TABLE execution_evidence_recovery (
 event_id TEXT PRIMARY KEY,
 execution_id TEXT NOT NULL REFERENCES executions(id),
 policy_version INTEGER NOT NULL,
 record_sha256 TEXT NOT NULL,
 envelope BLOB NOT NULL CHECK(length(envelope) <= 16384),
 min_retain_until TEXT NOT NULL,
 created_at TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt_at TEXT NOT NULL,
 last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX execution_recovery_due ON execution_evidence_recovery(next_attempt_at);
CREATE TABLE execution_evidence_confirmations (
 event_id TEXT PRIMARY KEY,
 execution_id TEXT NOT NULL REFERENCES executions(id),
 record_sha256 TEXT NOT NULL,
 confirmed_at TEXT NOT NULL
);
