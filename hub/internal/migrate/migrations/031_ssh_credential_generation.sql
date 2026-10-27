-- Keep SSH certificate revocation independent of browser token refresh. Legacy
-- certificates belong to generation zero and remain valid until credentials
-- change; password recovery permanently advances this durable epoch.
ALTER TABLE users ADD COLUMN ssh_credential_generation INTEGER NOT NULL DEFAULT 0
    CHECK (ssh_credential_generation >= 0);
