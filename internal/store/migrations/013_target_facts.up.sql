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

  -- Pinlenmiş anahtarın TEL TÜRÜ: ssh-ed25519, ssh-rsa,
  -- ecdsa-sha2-nistp256 …
  --
  -- ⚠️ MÜZAKERE EDİLEN İMZA ALGORİTMASI DEĞİL. Burada eskiden örnek
  -- olarak "rsa-sha2-512" yazıyordu ve o değer buraya HİÇ yazılamaz:
  -- tek yazan yer upstream/dial.go ve pinlenmiş anahtarın pub.Type()'ını
  -- koyuyor. RSA bir anahtar rsa-sha2-512 ile imzalansa da tel üzerinde
  -- "ssh-rsa" olarak duruyor (RFC 8332 imzayı değiştirdi, formatı
  -- değil). Yanlış örnek, "RSA host key'i olan hedefleri bul" diye
  -- sorgu yazan kişiye boş sonuç döndürürdü.
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
