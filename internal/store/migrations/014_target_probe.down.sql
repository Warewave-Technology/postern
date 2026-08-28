DELETE FROM admin_log WHERE via = 'probe';
ALTER TABLE admin_log DROP CONSTRAINT admin_log_via_check;
ALTER TABLE admin_log ADD CONSTRAINT admin_log_via_check
  CHECK (via IN ('web', 'cli', 'sync', 'sso'));

ALTER TABLE target_facts DROP COLUMN IF EXISTS kernel;
ALTER TABLE target_facts DROP COLUMN IF EXISTS os_name;
ALTER TABLE target_facts DROP COLUMN IF EXISTS probed_at;
