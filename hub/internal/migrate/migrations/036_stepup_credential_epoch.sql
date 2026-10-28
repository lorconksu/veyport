-- Existing proofs lack an authenticated credential epoch and require a fresh
-- action-bound MFA challenge after upgrade.
ALTER TABLE stepup_proofs ADD COLUMN token_generation INTEGER NOT NULL DEFAULT -1;
