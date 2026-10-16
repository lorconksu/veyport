-- A deletion phase persists across audit failures/retries and excludes admission
-- and concurrent edits until every ended session has a durable local audit.
ALTER TABLE applications ADD COLUMN deleting INTEGER NOT NULL DEFAULT 0 CHECK(deleting IN (0,1));
