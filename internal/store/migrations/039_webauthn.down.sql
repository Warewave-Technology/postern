-- Geri alma, kayıtlı güvenlik anahtarlarını siler: aynı anahtarlar
-- yeniden kaydedilebilir, ama kimlik avına dayanıklı ikinci faktör
-- ortadan kalkar ve hesaplar koda geri döner.
DROP INDEX IF EXISTS webauthn_credentials_user_idx;
DROP TABLE IF EXISTS webauthn_credentials;
ALTER TABLE users DROP COLUMN webauthn_only;
