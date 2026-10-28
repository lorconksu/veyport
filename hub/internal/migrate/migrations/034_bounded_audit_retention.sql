-- Upgrade databases that have already applied recovery migrations 032/033.
-- Keep the original timestamp for exact subsecond comparisons; index its UTC
-- second for bounded candidate selection, including historical offset formats.
ALTER TABLE audit_logs ADD COLUMN created_at_epoch INTEGER
    GENERATED ALWAYS AS (unixepoch(created_at)) VIRTUAL;
CREATE INDEX idx_audit_logs_retention ON audit_logs(created_at_epoch, id);
CREATE INDEX idx_local_break_glass_recoveries_audit_id ON local_break_glass_recoveries(audit_id);
