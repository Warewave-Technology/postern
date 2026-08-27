-- 006_settings: çalışma zamanı yapılandırması.
--
-- LDAP/OIDC bağlantı ayarları config dosyasında DEĞİL burada yaşar. Üç
-- sebep: panelden düzenlenip test edilebilmesi, sırrın düz metin olarak
-- config'te gezmemesi, ve S4.2'de bağladığımız "yönetim CLI/API'den"
-- kuralıyla tutarlılık.
--
-- ⚠️ DÜRÜSTLÜK NOTU: bu tablo config dosyasından daha güvenli bir yer
-- DEĞİLDİR — aynı disk, aynı izinler, şifresiz SQLite. Sırları koruyan
-- şey tablonun kendisi değil, encrypted sütunu ve ayrı dosyada duran ana
-- anahtardır (internal/secret). Bu bile sunucuyu ele geçirene karşı
-- koruma sağlamaz (o hem DB'yi hem anahtarı alır); koruduğu senaryo
-- veritabanı KOPYASININ sızmasıdır — yedek, hata ayıklama dökümü,
-- yanlışlıkla paylaşılan dosya.
CREATE TABLE settings (
  -- Noktalı ad alanı: "ldap.url", "ldap.bind_password", "oidc.client_id".
  key TEXT PRIMARY KEY CHECK (key <> ''),

  -- encrypted=0 ise düz metin, 1 ise internal/secret'ın mühürlediği hâli.
  value TEXT NOT NULL,

  encrypted INTEGER NOT NULL DEFAULT 0,

  updated_at INTEGER NOT NULL,
  -- Kim değiştirdi: admin_log ile aynı aktör kavramı.
  updated_by TEXT NOT NULL DEFAULT ''
);
