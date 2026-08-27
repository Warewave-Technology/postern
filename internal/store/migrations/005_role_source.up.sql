-- 005_role_source: rol atamasının KAYNAĞI ve ÖMRÜ.
--
-- Neden gerekli: aynı kullanıcı hem IdP grubundan hem yöneticinin elinden
-- rol alabiliyor. Kaynağı saklamayan bir tablo iki kötü seçenekten birine
-- mahkûm eder — ya her senkronizasyon elle verilen yetkiyi siler, ya da
-- elle verilen yetki sonsuza dek birikir. Kaynağı bilirsek ikisi de
-- olmaz: SSO satırları her girişte yenilenir, manual satırlara dokunulmaz.
--
-- expires_at, "geçici proje için yetki verdim" senaryosunun cevabı.
-- Süresi dolan satır SİLİNMEZ: denetim izi olarak kalır ("bu yetki vardı,
-- doldu") ve sorgular tembel filtreyle görmezden gelir.

ALTER TABLE user_roles ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'
  CHECK (source IN ('sso', 'manual'));

-- NULL = süresiz. Unix saniyesi (şemanın geri kalanıyla aynı biçim).
ALTER TABLE user_roles ADD COLUMN expires_at BIGINT;

-- "Bu kullanıcının SSO rollerini yenile" en sık çalışacak sorgu.
CREATE INDEX user_roles_source_idx ON user_roles(user_id, source);
