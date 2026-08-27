-- 010 geri alma.
--
-- ⚠️ SIRA ÖNEMLİ: via='sync' satırları ÖNCE silinmeli. Dar kısıtı
-- onlar dururken geri koymak, geri almanın KENDİSİNİ düşürür.
DELETE FROM admin_log WHERE via = 'sync';

ALTER TABLE admin_log DROP CONSTRAINT admin_log_via_check;
ALTER TABLE admin_log ADD CONSTRAINT admin_log_via_check
  CHECK (via IN ('web', 'cli'));

DROP INDEX IF EXISTS sync_runs_started_idx;
DROP TABLE IF EXISTS sync_runs;

ALTER TABLE users DROP COLUMN dir_missing_since;
ALTER TABLE users DROP COLUMN dir_last_seen_at;
