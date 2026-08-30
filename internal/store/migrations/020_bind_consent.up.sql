-- 020_bind_consent: bir YÖNETİCİ hesabının ilk kez bir kimliğe
-- bağlanmasına, operatörün AÇIKÇA izin vermesi.
--
-- ⚠️ NEDEN GEREKLİ — ölçülen saldırı (demo ortamında uçtan uca):
-- "developers" grubundaki sıradan bir çalışan, IdP'de kendi
-- preferred_username'ini "ops" yaptı ve OOB girişini çalıştırdı.
-- postern'in CLI yönetici hesabı — is_admin=true, admin_via='cli' —
-- saldırganın kimliğine geçti:
--
--   önce:  ops | admin=true | via=cli | idp_subject=YOK
--   sonra: ops | admin=true | via=cli | idp_subject=f4b15fbf-…
--
-- Rol eşlemesi bunu durdurmuyor ve durdurması da beklenmemeli:
-- saldırgan kendi rollerini alıyor, ama hesabın is_admin bayrağı
-- hiçbir eşlemeden gelmiyor.
--
-- ⚠️ NEDEN ONAY, DÜZ RED DEĞİL: bağlama ANINDA saldırganla meşru
-- yönetici ayırt EDİLEMEZ — elde tek kanıt kullanıcı adı ve o da
-- birçok sağlayıcıda kullanıcının kendi değiştirebildiği bir alan
-- (011'in notu). Ayrım ancak dışarıdan, host'taki operatörden
-- gelebilir. Düz red ise CLI ile açılmış bir yöneticinin IdP'den ilk
-- girişini tamamen kapatıyordu (beş entegrasyon testi bunu gösterdi).
--
-- Sıradan hesaplar bundan ETKİLENMİYOR: onboarding'in dayandığı ilk
-- bağlama serbest kalıyor. Kapatılan tek şey, YETKİ TAŞIYAN hesapların
-- yalnızca adla devralınması.

ALTER TABLE users ADD COLUMN bind_consent_at BIGINT;

COMMENT ON COLUMN users.bind_consent_at IS
  'Operator consent for the next identity bind of an administrator account. '
  'Set by `postern user allow-bind`, consumed on use.';
