-- 011_idp_subject: kimlik sağlayıcı kimliğinin KALICI anahtarı.
--
-- ⚠️ KAPATILAN AÇIK: kullanıcı kaydı yalnızca username ile
-- eşleştiriliyordu ve username, OIDC'de preferred_username claim'inden
-- geliyordu. O claim BİRÇOK SAĞLAYICIDA DEĞİŞTİRİLEBİLİR (Keycloak'ta
-- "Edit username", self-servis kayıt, federasyon). Yani IdP'de adını
-- "yigit.basalma" yapabilen herkes, postern'deki o hesabı — rolleriyle,
-- os_user'ıyla ve is_admin bayrağıyla — devralıyordu. Panelin
-- "admin yalnızca CLI'dan verilir" kuralı bu yoldan tamamen atlanıyordu.
--
-- Saldırgan olmadan da olurdu: ayrılan bir çalışanın kullanıcı adının
-- yeni birine verilmesi (username geri dönüşümü) aynı devralmayı
-- sessizce yapardı.
--
-- Çözüm: (issuer, subject). OIDC'de "sub" sağlayıcı içinde KALICI ve
-- YENİDEN ATANMAZ; spesifikasyonun kimlik için kullanılmasını söylediği
-- alan tam olarak budur.

ALTER TABLE users ADD COLUMN idp_issuer  TEXT;
ALTER TABLE users ADD COLUMN idp_subject TEXT;

-- Bir IdP kimliği EN FAZLA BİR postern hesabına bağlanabilir.
-- Kısıt olmadan iki hesap aynı kimliği iddia edebilir ve hangisine
-- girildiği sıralamaya kalırdı.
CREATE UNIQUE INDEX users_idp_identity_idx
  ON users (idp_issuer, idp_subject)
  WHERE idp_issuer IS NOT NULL AND idp_subject IS NOT NULL;

-- admin_log.via'ya 'sso' ekleniyor.
--
-- İlk bağlama (TOFU) denetim satırı GİRİŞ sırasında yazılıyor: ne web
-- panelinden bir yönetici işlemi, ne CLI, ne de zamanlayıcı. Var olan
-- üç değerden birini "yakın" diye seçmek, denetim kaydını okuyan kişiye
-- yanlış bilgi vermek olurdu.
ALTER TABLE admin_log DROP CONSTRAINT admin_log_via_check;
ALTER TABLE admin_log ADD CONSTRAINT admin_log_via_check
  CHECK (via IN ('web', 'cli', 'sync', 'sso'));
