-- ⚠️ SIRA ÖNEMLİ: via='sso' satırları ÖNCE silinmeli, yoksa dar kısıtı
-- geri koymak geri almanın KENDİSİNİ düşürür.
DELETE FROM admin_log WHERE via = 'sso';

ALTER TABLE admin_log DROP CONSTRAINT admin_log_via_check;
ALTER TABLE admin_log ADD CONSTRAINT admin_log_via_check
  CHECK (via IN ('web', 'cli', 'sync'));

DROP INDEX IF EXISTS users_idp_identity_idx;
ALTER TABLE users DROP COLUMN idp_subject;
ALTER TABLE users DROP COLUMN idp_issuer;
