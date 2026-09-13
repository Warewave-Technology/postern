DELETE FROM admin_log WHERE via = 'system';
ALTER TABLE admin_log DROP CONSTRAINT admin_log_via_check;
ALTER TABLE admin_log ADD CONSTRAINT admin_log_via_check
  CHECK (via IN ('web', 'cli', 'sync', 'sso', 'probe', 'local', 'dir'));
