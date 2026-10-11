-- Private one-use refresh authority. An empty digest marks a session created
-- before this migration; its first current, signed refresh may adopt a digest
-- exactly once. No token or digest is returned by session listing APIs.
ALTER TABLE sessions ADD COLUMN refresh_token_sha256 TEXT NOT NULL DEFAULT ''
    CHECK (refresh_token_sha256 = '' OR
           (length(refresh_token_sha256) = 64 AND refresh_token_sha256 NOT GLOB '*[^0-9a-f]*'));
