-- 023_account_state: hesabın YAŞAM DÖNGÜSÜ ve kaynağın onu en son ne
-- zaman doğruladığı.
--
-- ⚠️ ÇÖZÜLEN BOŞLUK, OIDC'DE HİÇBİR İPTAL YOLU OLMAMASI.
--
-- Dizin (LDAP) için iki mekanizma var: oturum açılışındaki tazeleme ve
-- periyodik senkronizasyon. İkisi de dizine "bu kişi hâlâ var mı" diye
-- SORABİLDİĞİ için çalışıyor.
--
-- OIDC'de böyle bir soru YOK. groupsync.Directory'nin yorumu bunu
-- açıkça söylüyor: "bir claim ancak kullanıcı giriş yaparken gelir".
-- Yani IdP'de kapatılmış bir hesabın postern'deki karşılığı, kişi bir
-- daha hiç giriş yapmazsa SÜRESİZ ayakta kalıyor — rolleriyle,
-- anahtarlarıyla ve (grup üzerinden geldiyse) yöneticiliğiyle.
--
-- Elimizdeki tek ölçüt zaman: kaynak bu kişiyi EN SON ne zaman
-- doğruladı. Doğrulama, kaynağın kapısından geçmiş bir giriştir.
--
-- ⚠️ FİZİKİ SİLME YOK. Denetim kaydı ve oturum kayıtları kullanıcıya
-- bağlı; satırı silmek geçmişi okunamaz yapardı. Hesap önce pasifleşir,
-- sonra 'deleted' işaretlenir — ikisi de geri alınabilir.

-- ⚠️ TEK SÜTUN, İKİ BAYRAK DEĞİL.
--
-- is_active + deleted ikilisi "aktif ama silinmiş" gibi anlamı olmayan
-- bir durumu TEMSİL EDİLEBİLİR yapardı ve kural, her yazma yolunda
-- tekrarlanan bir kontrole dönüşürdü. auth.source'ta (göç 018) verilen
-- kararın aynısı: geçersiz durum hiç var olmasın.
ALTER TABLE users ADD COLUMN state TEXT NOT NULL DEFAULT 'active'
  CHECK (state IN ('active', 'inactive', 'deleted'));

-- Kaynağın bu kişiyi en son doğruladığı an (başarılı giriş ya da
-- senkronizasyonda görülme). NULL = hiç doğrulanmamış; mevcut hesaplar
-- için aşağıda dolduruluyor.
ALTER TABLE users ADD COLUMN last_confirmed_at BIGINT;

-- ⚠️ MEVCUT HESAPLAR "ŞİMDİ DOĞRULANMIŞ" SAYILIYOR.
--
-- created_at yazsaydık, yükseltmenin ertesi günü yıllardır duran
-- hesapların hepsi bir anda pasifleşirdi — bir güvenlik iyileştirmesi
-- toplu erişim kaybına dönerdi. Sayaç yükseltmeden itibaren işliyor.
UPDATE users SET last_confirmed_at = EXTRACT(EPOCH FROM now())::BIGINT;

CREATE INDEX users_state_confirmed_idx ON users (state, last_confirmed_at);
