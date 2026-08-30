DELETE FROM admin_log WHERE via = 'dir';
ALTER TABLE admin_log DROP CONSTRAINT admin_log_via_check;
ALTER TABLE admin_log ADD CONSTRAINT admin_log_via_check
  CHECK (via IN ('web', 'cli', 'sync', 'sso', 'probe', 'local'));

DROP INDEX IF EXISTS users_dir_identity_idx;
ALTER TABLE users DROP COLUMN IF EXISTS dir_subject;
