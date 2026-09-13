-- Let the bastion itself write to the admin log.
--
-- The via column's check listed every door a person or a directory can come
-- through, but not the bastion acting on its own: 'system'. The recording
-- pruner has been writing its rows with that value since it started, and
-- every one of them was refused by this constraint — the retention deletions
-- the panel says "the admin log explains" were never explained. The JIT
-- sweeper, which revokes expired accounts unattended, hit the same wall.
ALTER TABLE admin_log DROP CONSTRAINT admin_log_via_check;
ALTER TABLE admin_log ADD CONSTRAINT admin_log_via_check
  CHECK (via IN ('web', 'cli', 'sync', 'sso', 'probe', 'local', 'dir', 'system'));
