-- Geri dönüş: aktif kaynak dizinse eski bayrağı geri koy.
INSERT INTO settings (key, value, encrypted, updated_by, updated_at)
SELECT 'ldap.auth_enabled', 'true', FALSE, 'migration-018-down', EXTRACT(EPOCH FROM now())::BIGINT
FROM settings
WHERE key = 'auth.source' AND value = 'ldap'
ON CONFLICT (key) DO NOTHING;

DELETE FROM settings WHERE key = 'auth.source';
