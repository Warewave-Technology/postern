-- 018_auth_source: aynı anda TEK bir giriş kaynağı.
--
-- ÜRÜN KURALI: panelin kapısı aynı anda yalnızca bir kaynağa açık olur —
-- yerel kimlik bilgisi, OIDC ya da dizin. Biri açıkken diğerleri kapalı;
-- yerel kapı, hiçbir dizin kaynağı seçilmediğinde geçerli olan geri
-- dönüş yolu.
--
-- ⚠️ NEDEN İKİ BOOLEAN DEĞİL, TEK DEĞER: "OIDC etkin" ve "LDAP etkin"
-- diye iki bayrak olsaydı, ikisinin birden açık olduğu bir durum
-- TEMSİL EDİLEBİLİR olurdu ve kural ancak her yazma yolunda tekrarlanan
-- bir kontrolle korunurdu — CLI'dan doğrudan yazan biri, bir yarış, ya
-- da kontrolü eklemeyi unutan yeni bir uç onu bozardı. Tek değerli bir
-- ayarda o durum yoktur.
--
-- Bu göç ayrı bir tablo AÇMIYOR: settings zaten anahtar/değer ve bu bir
-- ayar. Yaptığı tek şey, eskiden aynı işi yapan `ldap.auth_enabled`
-- bayrağını yeni tek değere TAŞIMAK.

-- Dizin parolasıyla giriş açıksa, aktif kaynak dizindir.
INSERT INTO settings (key, value, encrypted, updated_by, updated_at)
SELECT 'auth.source', 'ldap', FALSE, 'migration-018', EXTRACT(EPOCH FROM now())::BIGINT
FROM settings
WHERE key = 'ldap.auth_enabled' AND lower(value) IN ('true', '1', 't', 'yes')
ON CONFLICT (key) DO NOTHING;

-- ⚠️ ESKİ BAYRAK SİLİNİYOR. Bırakılsaydı iki ayar aynı soruya cevap
-- veriyor olurdu ve "auth_enabled=false ama source=ldap" gibi anlamı
-- tanımsız bir durum, ikisini de okuyan kodda sessizce farklı
-- yorumlanırdı.
DELETE FROM settings WHERE key = 'ldap.auth_enabled';
