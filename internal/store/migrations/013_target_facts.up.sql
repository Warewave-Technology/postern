-- 013_target_facts: hedef hakkında BAĞLANIRKEN öğrenilenler.
--
-- ⚠️ AYRI TABLO, çünkü bunlar YAPILANDIRMA DEĞİL GÖZLEM. targets tablosu
-- operatörün yazdığı gerçeği tutuyor (adres, pinlenmiş anahtar); burası
-- makinenin söylediğini. İkisini aynı satıra koymak, bir sonraki okuyanın
-- "server_version'ı ben mi girdim" diye sormasına yol açardı.
--
-- ⚠️ İÇERİĞİ YALNIZCA EL SIKIŞMADAN GELİR. Hedefte komut çalıştırıp
-- uname/os-release okumak daha fazlasını verirdi ama güven modelini
-- bozar: postern, kullanıcının oturumu dışında hedefte iş çalıştırmaz.
CREATE TABLE target_facts (
  target_id       TEXT PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,

  -- Sunucunun kendi tanıttığı afiş: "SSH-2.0-OpenSSH_9.6p1 Debian-3".
  -- Dağıtım ve yama seviyesi için en güvenilir tek ipucu.
  server_version  TEXT NOT NULL DEFAULT '',

  -- Pinlenmiş anahtarın türü (ssh-ed25519, rsa-sha2-512 …).
  host_key_type   TEXT NOT NULL DEFAULT '',

  -- Son BAŞARILI bağlantı ve o bağlantının el sıkışma süresi.
  last_seen_at    BIGINT,
  connect_ms      INTEGER,

  -- Son BAŞARISIZ denemenin zamanı ve sebebi. Başarıyı silmiyor:
  -- "en son ne zaman çalıştı" ile "en son neden çalışmadı" ayrı
  -- sorular ve operatörün ikisine de ihtiyacı var.
  last_error_at   BIGINT,
  last_error      TEXT NOT NULL DEFAULT ''
);
