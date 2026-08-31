-- 025_autocreate_default: JIT'i ZATEN kullanan kurulumlarda açık bırak.
--
-- auth.auto_create ayarı geldiğinde varsayılanı KAPALI seçildi ve o karar
-- doğru: "IdP'de hesabın olması postern'de hesabın olması demek değil"
-- kuralı ürünün başından beri yazılı, ve açık bir varsayılan onu
-- sessizce tersine çevirirdi.
--
-- ⚠️ AMA YÜKSELTME SESSİZCE DAVRANIŞ DEĞİŞTİREMEZ. Bugüne kadar OIDC
-- kapısı hesapları kendiliğinden açıyordu (rol eşlemesi kapıda olmak
-- kaydıyla). Kapalı varsayılanla yükselten bir kurum, işe yeni
-- başlayanların erişemediğini ancak biri şikâyet edince fark ederdi —
-- ve o gecikme, güvenlik iyileştirmesi diye satılan bir kesinti olurdu.
--
-- Bu yüzden: JIT'in GERÇEKTEN kullanıldığı kurulumlarda ayar açık
-- başlıyor. Ölçüt sso_only kullanıcıların varlığı — onlar yalnızca JIT
-- yoluyla oluşuyor (bkz. ProvisionUser). Yeni kurulumda hiç yok, yani
-- güvenli varsayılan orada geçerli kalıyor.

INSERT INTO settings (key, value, encrypted, updated_by, updated_at)
SELECT 'auth.auto_create', 'true', FALSE, 'migration-025',
       EXTRACT(EPOCH FROM now())::BIGINT
WHERE EXISTS (SELECT 1 FROM users WHERE sso_only = TRUE)
ON CONFLICT (key) DO NOTHING;
