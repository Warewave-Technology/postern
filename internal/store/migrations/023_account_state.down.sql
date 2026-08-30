DROP INDEX IF EXISTS users_state_confirmed_idx;
ALTER TABLE users DROP COLUMN IF EXISTS last_confirmed_at;
ALTER TABLE users DROP COLUMN IF EXISTS state;
