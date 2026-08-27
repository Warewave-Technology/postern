-- 006_settings: çalışma zamanı yapılandırması.
--
-- LDAP/OIDC bağlantı ayarları config dosyasında DEĞİL burada yaşar. Üç
-- sebep: panelden düzenlenip test edilebilmesi, sırrın düz metin olarak
-- config'te gezmemesi, ve S4.2'de bağladığımız "yönetim CLI/API'den"
-- kuralıyla tutarlılık.
--
-- ⚠️ DÜRÜSTLÜK NOTU: bu tablo config dosyasından daha güvenli bir yer
-- DEĞİLDİR. Sırları koruyan şey tablonun kendisi değil, encrypted sütunu
-- ve ayrı dosyada duran ana anahtardır (internal/secret). Bu bile
-- sunucuyu ele geçirene karşı koruma sağlamaz (o hem DB'ye hem anahtara
-- ulaşır); koruduğu senaryo veritabanı KOPYASININ sızmasıdır — yedek,
-- hata ayıklama dökümü, yanlışlıkla paylaşılan dosya.
--
-- PostgreSQL'e geçince bu senaryo GENİŞLEDİ: veritabanı artık ayrı bir
-- sunucuda ve ağ üzerinden konuşuluyor. Yani "kopyası sızar" ihtimaline
-- "yetkisiz biri DB'ye bağlanır" da eklendi — encrypted sütununun değeri
-- arttı, sslmode ve DB kullanıcı yetkileri de artık güvenlik konusu.
CREATE TABLE settings (
  -- Noktalı ad alanı: "ldap.url", "ldap.bind_password", "oidc.client_id".
  key TEXT PRIMARY KEY CHECK (key <> ''),

  -- encrypted FALSE ise düz metin, TRUE ise internal/secret'ın
  -- mühürlediği hâli.
  value TEXT NOT NULL,

  encrypted BOOLEAN NOT NULL DEFAULT FALSE,

  updated_at BIGINT NOT NULL,
  -- Kim değiştirdi: admin_log ile aynı aktör kavramı.
  updated_by TEXT NOT NULL DEFAULT ''
);
