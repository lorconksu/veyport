-- Snapshots intentionally have no user/node foreign key: deleting live fleet
-- records must never delete the record of an execution or its dispatch claim.
CREATE TABLE executions (
 id TEXT PRIMARY KEY,
 actor_id TEXT NOT NULL,
 actor_name TEXT NOT NULL,
 actor_provider TEXT NOT NULL DEFAULT '',
 node_id TEXT NOT NULL,
 node_name TEXT NOT NULL,
 requested_user TEXT NOT NULL DEFAULT '',
 command_sha256 TEXT NOT NULL CHECK(length(command_sha256)=64),
 command_length INTEGER NOT NULL CHECK(command_length BETWEEN 1 AND 32768),
 policy_version TEXT NOT NULL DEFAULT 'standard-v1',
 preparation TEXT NOT NULL DEFAULT '{}',
 state TEXT NOT NULL DEFAULT 'submitted' CHECK(state IN ('submitted','prepared','admitted','dispatching','running','exited','denied','admission_failed','launch_failed','cancelled','transport_lost','outcome_unknown')),
 evidence_state TEXT NOT NULL DEFAULT 'local' CHECK(evidence_state IN ('local','pending','confirmed','completion_unconfirmed','permanently_incomplete')),
 exit_code INTEGER,
 signal TEXT NOT NULL DEFAULT '',
 reason TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 finished_at TEXT
);
CREATE INDEX executions_actor_time ON executions(actor_id,created_at DESC);
CREATE INDEX executions_node_time ON executions(node_id,created_at DESC);
CREATE INDEX executions_state_time ON executions(state,updated_at);
CREATE TABLE execution_events (
 id TEXT PRIMARY KEY,
 execution_id TEXT NOT NULL REFERENCES executions(id),
 sequence INTEGER NOT NULL CHECK(sequence>=0),
 event_type TEXT NOT NULL,
 created_at TEXT NOT NULL,
 UNIQUE(execution_id,sequence)
);
CREATE TABLE execution_dispatches (
 execution_id TEXT PRIMARY KEY REFERENCES executions(id),
 preparation_id TEXT NOT NULL,
 claimed_at TEXT NOT NULL
);
