CREATE TABLE agent_updates (
 id TEXT PRIMARY KEY,
 node_id TEXT NOT NULL,
 actor_id TEXT NOT NULL,
 session_id TEXT NOT NULL,
 state TEXT NOT NULL,
 ticket_hash TEXT NOT NULL DEFAULT '',
 expires_at INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 metadata TEXT NOT NULL
);
CREATE UNIQUE INDEX agent_updates_active_node ON agent_updates(node_id)
 WHERE state NOT IN ('succeeded','failed','rolled_back','expired','recovery_acknowledged');
CREATE INDEX agent_updates_node_created ON agent_updates(node_id,created_at DESC);
CREATE UNIQUE INDEX agent_updates_ticket ON agent_updates(ticket_hash) WHERE ticket_hash<>'';
