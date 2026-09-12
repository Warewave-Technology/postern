-- Donanım güvenlik anahtarları (WebAuthn).
--
-- NEDEN VAR: panel postern'in kontrol düzlemi. Oradaki bir oturum,
-- hedeflerin tamamına erişimi yöneten şeyi eline veriyor. Bugünkü tek
-- ikinci faktör TOTP ve TOTP'nin tek gerçek zayıflığı burada ısırıyor:
-- kod, sahte bir sayfaya yazılıp otuz saniye içinde gerçek sunucuya
-- aktarılabiliyor. WebAuthn imzası KAYNAĞA bağlı olduğu için
-- aktarılamıyor — kimlik avına dayanıklı olmasının tek sebebi bu.
--
-- ⚠️ SUNUCU YALNIZCA AÇIK ANAHTAR TUTUYOR. TOTP sırrı PAYLAŞILAN bir
-- sır: onu okuyabilen sonsuza dek kod üretir (bu yüzden mühürlü
-- saklanıyor, bkz. totp_credentials). Buradaki public_key ise çalınsa
-- bile bir şey üretmiyor. Mühürlemeye de gerek yok, ve gerek yokken
-- mühürlemek "bu değer gizli" diye yanlış bir şey öğretirdi.
CREATE TABLE webauthn_credentials (
  -- WebAuthn kimlik bilgisi kimliği (ham bayt, base64url saklanıyor).
  id TEXT PRIMARY KEY CHECK (id <> ''),

  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- COSE biçiminde açık anahtar.
  public_key BYTEA NOT NULL,

  -- ⚠️ AAGUID KİMLİK BİLGİSİ DEĞİL, ÜRETİCİ MODELİ. Denetçinin
  -- "bu hesapta hangi tür anahtar var" sorusunu cevaplıyor; kişiyi
  -- değil cihaz modelini gösteriyor.
  aaguid BYTEA NOT NULL DEFAULT ''::BYTEA,

  /*
   * ⚠️ SIGN_COUNT KLONLAMA SEZGİSİ, BİR SAYAÇ DEĞİL.
   *
   * Doğrulayıcı her kullanımda artırıyor; gelen sayı saklanandan
   * KÜÇÜK ya da EŞİTSE aynı anahtarın bir kopyası dolaşıyor olabilir.
   * Sıfır özel bir değer: bazı doğrulayıcılar (özellikle platform
   * anahtarları) sayacı hiç artırmıyor ve hep 0 gönderiyor — o hâlde
   * kontrol YAPILMIYOR, çünkü yapılsaydı her girişi klon sanardık.
   */
  sign_count BIGINT NOT NULL DEFAULT 0,

  -- Kişinin verdiği ad ("iş dizüstü", "yedek anahtar"). Birden çok
  -- anahtarı ayırt etmenin tek yolu; kayıp anahtarı silecek kişi buna
  -- bakıyor.
  name TEXT NOT NULL DEFAULT '',

  created_at BIGINT NOT NULL,
  -- NULL: kaydedildi ama hiç kullanılmadı.
  last_used_at BIGINT
);

-- "Bu kullanıcının anahtarları" her girişte sorulan soru.
CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials(user_id);

-- ⚠️ KOD ZORUNLULUĞUNU KAPATMAK HESABIN KENDİ KARARI.
--
-- Anahtar ve kod BİRLİKTE açıkken hesabın kimlik avına dayanıklılığı
-- KODUNKİ kadardır: saldırgan anahtarı atlayıp kodu ister. Bunu
-- kapatabilmek gerekiyor. Ama varsayılan olarak kapatmak, anahtarını
-- tek bir tarayıcıya kaydeden herkesi başka bir makineden kilitlerdi —
-- ve bu projede kurtarma kodu bilerek yok. Karar kişinin, çıkış yolu
-- yöneticinin sıfırlaması.
ALTER TABLE users ADD COLUMN webauthn_only BOOLEAN NOT NULL DEFAULT FALSE;
