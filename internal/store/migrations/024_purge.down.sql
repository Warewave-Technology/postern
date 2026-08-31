DROP INDEX IF EXISTS users_purged_idx;
ALTER TABLE users DROP COLUMN IF EXISTS former_username;
ALTER TABLE users DROP COLUMN IF EXISTS purged_at;
