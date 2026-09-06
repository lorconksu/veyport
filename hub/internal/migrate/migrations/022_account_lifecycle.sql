ALTER TABLE users ADD COLUMN disabled_at      TEXT;
ALTER TABLE users ADD COLUMN disabled_by      TEXT;
ALTER TABLE users ADD COLUMN reactivated_at   TEXT;
ALTER TABLE users ADD COLUMN dormancy_exempt  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN last_activity_at TEXT;

-- backfill activity = later of last_login_at and the user's latest token use
UPDATE users SET last_activity_at = (
  SELECT CASE
    WHEN u.last_login_at IS NULL THEN t.max_used
    WHEN t.max_used IS NULL THEN u.last_login_at
    WHEN t.max_used > u.last_login_at THEN t.max_used
    ELSE u.last_login_at END
  FROM users u LEFT JOIN (SELECT user_id, MAX(last_used_at) AS max_used FROM api_tokens GROUP BY user_id) t
    ON t.user_id = u.id
  WHERE u.id = users.id)
WHERE last_activity_at IS NULL;

-- the earliest-created admin is the default recovery admin
UPDATE users SET dormancy_exempt = 1
 WHERE id = (SELECT id FROM users WHERE role = 'admin' ORDER BY created_at, id LIMIT 1);
