-- 015_local_credential: postern'in KENDİ kimlik bilgisi.
--
-- NEDEN VAR: postern'e girmenin iki yolu vardı ve ikisi de dışarıya
-- bağımlıydı — SSH açık anahtarı ya da bir OIDC sağlayıcısı. Dizini olan
-- ama kimlik sağlayıcısı OLMAYAN bir kurum paneli hiç açamıyordu; yani
-- ürünün yönetilebilir hâli bir Keycloak kurmaya bağlıydı. İlk
-- yöneticiyi postern'in kendisi verebilmeli.
--
-- ⚠️ BU BİR PAROLA DEĞİL, MAKİNE ÜRETİMİ BİR SIR. Değerini operatör
-- SEÇEMİYOR; `postern admin bootstrap` üretiyor, bir kez basıyor ve bir
-- daha göstermiyor. Bu bir kolaylık tercihi değil: "yerel parolanı AD
-- parolan yapma" demek bir rica, postern'i o değeri alamayacak hâle
-- getirmek bir özelliktir. Kurumsal parolanın buraya sızmasını
-- engelleyen tek uygulanabilir yol bu.
--
-- SAKLANAN ŞEY DOĞRULAYICI (verifier), sırrın kendisi değil: geri
-- okunamaz. Şifrelenmiyor da — bir hash'i ayrıca mühürlemek, kurtarma
-- yolunu anahtar dosyasının sağlığına bağlardı ve bu kapının var olma
-- sebebi tam olarak "başka her şey bozulduğunda içeri girebilmek".

CREATE TABLE local_credentials (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,

  -- Kendini tanımlayan biçim: "argon2id$v=..$m=..,t=..,p=..$salt$hash".
  -- Parametreler değerin İÇİNDE, böylece ileride sertleştirilebilirler
  -- ve eski satırlar okunmaya devam eder.
  verifier TEXT NOT NULL CHECK (verifier <> ''),

  created_at BIGINT NOT NULL,
  -- Kimin bastığı: bu kapı bir yönetici hesabı yaratıyor ve denetim
  -- kaydının "system" demesi yeterli değil.
  created_by TEXT NOT NULL CHECK (created_by <> ''),

  -- Son kullanım: operatör bu hesabın hâlâ kullanılıp kullanılmadığını
  -- görebilmeli. Kullanılmayan bir acil durum kapısı, unutulmuş bir
  -- kapıdır.
  last_used_at BIGINT
);

-- admin_log.via'ya 'local' ekleniyor: yerel kapıdan yapılan girişler ve
-- bootstrap, SSO'dan gelenlerle AYNI satıra karışmamalı. "Bu işi kim,
-- hangi kapıdan yaptı" sorusunun cevabı denetim kaydının kendisi.
ALTER TABLE admin_log DROP CONSTRAINT admin_log_via_check;
ALTER TABLE admin_log ADD CONSTRAINT admin_log_via_check
  CHECK (via IN ('web', 'cli', 'sync', 'sso', 'probe', 'local'));
