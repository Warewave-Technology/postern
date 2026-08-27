DROP INDEX IF EXISTS user_roles_source_idx;
ALTER TABLE user_roles DROP COLUMN expires_at;
ALTER TABLE user_roles DROP COLUMN source;
