-- TOTP (RFC 6238) ikinci faktör.
--
-- NEDEN VAR: ikinci bir SSH anahtarı eklemek, postern'in kendi sırrıyla
-- YENİDEN DOĞRULAMA istiyor (mykeys.go) — çünkü ikinci anahtar eklemek,
-- hesabı ele geçiren birinin kalıcılık kurma hamlesinin ta kendisi.
-- Ama dizinden ya da kimlik sağlayıcıdan gelen hesapların postern'de bir
-- sırrı YOK; onlara verilen cevap "yöneticine sor" idi. Yani en yaygın
-- kurulumda kimse kendi anahtarını yönetemiyordu.
--
-- ⚠️ SIR AÇIK SAKLANIYOR VE BAŞKA TÜRLÜSÜ MÜMKÜN DEĞİL. TOTP doğrulaması
-- sırrın kendisiyle kod ÜRETMEYİ gerektiriyor; parolalar gibi tek yönlü
-- özetlenemez. Bu tabloyu okuyabilen biri kod üretebilir — yani buranın
-- koruması veritabanı erişiminin kendisidir, satırın biçimi değil.
CREATE TABLE totp_credentials (
  user_id      TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret       TEXT NOT NULL CHECK (secret <> ''),

  -- NULL = kayıt BAŞLADI ama kullanıcı henüz bir kodla doğrulamadı.
  --
  -- ⚠️ Ayrım şart: doğrulanmamış bir kayıt hiçbir şeyi yetkilendirmemeli.
  -- Aksi hâlde QR'ı hiç okutmamış bir kullanıcı, telefonunda karşılığı
  -- olmayan bir "ikinci faktör" taşıyor sanılır ve gerçekte kimse
  -- doğrulanamaz hâle gelirdi.
  confirmed_at BIGINT,
  created_at   BIGINT NOT NULL,

  /*
   * last_step, TEKRAR KORUMASI.
   *
   * ⚠️ Aynı TOTP kodu 30 saniye boyunca geçerli. Omuz üstünden okuyan,
   * araya giren ya da kodu yeniden gönderen biri onu İKİNCİ kez
   * kullanabilir — ve bu bağlamda ikinci kullanım "bir anahtar daha
   * ekle" demek. Kullanılan adım burada tutuluyor ve daha eski ya da
   * aynı adım bir daha kabul edilmiyor.
   *
   * -1 başlangıç: adım 0 (1 Ocak 1970) bile bir kez kullanılabilsin
   * diye. 0 olsaydı ilk adım sessizce yutulurdu.
   */
  last_step    BIGINT NOT NULL DEFAULT -1,
  last_used_at BIGINT
);
