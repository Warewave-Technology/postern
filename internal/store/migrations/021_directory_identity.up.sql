-- 021_directory_identity: dizin kimliğinin KALICI anahtarı.
--
-- 011, OIDC için (issuer, subject) çiftini getirmişti; bu, aynı kararın
-- dizin tarafındaki karşılığı. Dizinlerde o değer AD'de objectGUID,
-- RFC 4530 sunucularında entryUUID.
--
-- ⚠️ GERÇEK DİZİNDE ÖLÇÜLDÜ (OpenLDAP, dc=warewave,dc=io):
--
--   yeniden adlandırma (modrdn)   DN değişti, kimlik AYNI
--   başka OU'ya taşıma            DN değişti, kimlik AYNI
--   sil + aynı adla yeniden aç    DN aynı, kimlik FARKLI
--
-- Son satır güvenlik tarafı: ayrılan çalışanın kullanıcı adını devralan
-- kişi, onun postern hesabını devralamaz.
--
-- ⚠️ NEDEN idp_issuer/idp_subject'e YAZMIYORUZ.
--
-- Aynı sütunları paylaşsalardı, kaynak değiştirmek herkesi kilitlerdi:
-- bir yıl OIDC kullanmış bir kurumun her satırında idp_subject dolu
-- olurdu ve LDAP'a geçişte BindIdPSubject'in "yalnızca boşsa bağla"
-- kuralı her kullanıcıyı reddederdi. Ayrı sütunlarla eski bağ yerinde
-- kalıyor — geri dönerlerse çalışmaya devam ediyor.
--
-- ⚠️ NEDEN "REALM" YOK. entryUUID/objectGUID zaten UUID; iki ayrı
-- dizinde çakışma olasılığı yok sayılır. Geriye kalan tek senaryo,
-- panel yöneticisinin postern'i KENDİ kontrolündeki bir dizine
-- yöneltmesi — ve o, zaten güven zincirinin tepesi (bind parolası da
-- adres değişince bu yüzden düşürülüyor). Bir realm sütunu o saldırıyı
-- kapatmıyor, yalnızca bir ayar daha ekliyordu.

ALTER TABLE users ADD COLUMN dir_subject TEXT;

-- Bir dizin kimliği EN FAZLA BİR postern hesabına bağlanabilir.
-- Kısıt olmadan iki hesap aynı kimliği iddia edebilir ve hangisine
-- girildiği sıralamaya kalırdı (011'deki aynı gerekçe).
CREATE UNIQUE INDEX users_dir_identity_idx
  ON users (dir_subject)
  WHERE dir_subject IS NOT NULL;

-- Denetim kaydına dizin bağlaması için ayrı bir kaynak: 'sso' demek,
-- kaydı okuyan kişiye yanlış kapıyı gösterirdi.
--
-- ⚠️ MEVCUT DEĞERLERİN HEPSİ KORUNUYOR. 'probe' ve 'local' 014 ve
-- 015'te eklendi; onları düşüren bir CHECK, panel girişi görmüş her
-- veritabanında doğrulamada patlardı.
ALTER TABLE admin_log DROP CONSTRAINT admin_log_via_check;
ALTER TABLE admin_log ADD CONSTRAINT admin_log_via_check
  CHECK (via IN ('web', 'cli', 'sync', 'sso', 'probe', 'local', 'dir'));
