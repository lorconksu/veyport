ALTER TABLE servers ADD COLUMN node_pubkey TEXT;
ALTER TABLE servers ADD COLUMN node_kek_enc TEXT;
ALTER TABLE servers ADD COLUMN enroll_fingerprint TEXT;

CREATE TABLE IF NOT EXISTS reenroll_requests (
    id           TEXT PRIMARY KEY,
    server_id    TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    ip_address   TEXT,
    fingerprint  TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    anomaly_flags TEXT DEFAULT '{}',
    decided_by   TEXT
);
