-- 002_user_public_keys: SSH açık anahtarları da veritabanına.
--
-- Neden 001'e ek olarak: kimlik doğrulama (auth.go) ile yetkilendirme
-- (policy) AYNI kaynağa bakmak zorunda. Kullanıcılar DB'de, anahtarları
-- config'de kalsaydı, DB'den bir kullanıcıyı silmek onun GİRİŞİNİ
-- engellemezdi — iptal edilemeyen erişim.

CREATE TABLE user_public_keys (
  -- key_blob, ssh.PublicKey.Marshal()'ın base64'ü. authorized_keys
  -- SATIRI değil: o satır yorum ve seçenek taşır, aynı anahtar iki farklı
  -- metin olarak yazılabilir. Marshal çıktısı anahtarın kanonik hâli.
  --
  -- PRIMARY KEY olması bilinçli ve GÜVENLİK amaçlı: bir anahtar
  -- yalnızca TEK bir kullanıcıya ait olabilir. Aksi halde iki hesap aynı
  -- kimliği paylaşır ve denetim kaydı "kim girdi" sorusunu cevaplayamaz.
  key_blob TEXT PRIMARY KEY CHECK (key_blob <> ''),

  user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- authorized_keys satırının sonundaki yorum ("yigit@laptop"). Yalnızca
  -- insan için: hangi cihazın anahtarı olduğunu söyler.
  comment  TEXT NOT NULL DEFAULT '',

  added_at BIGINT NOT NULL
);

-- "Bu kullanıcının anahtarlarını listele" için. Doğrulama yönündeki arama
-- (blob → kullanıcı) zaten PRIMARY KEY üzerinden gidiyor: her bağlantıda
-- bütün kullanıcıları taramak yerine tek indeksli okuma.
CREATE INDEX user_public_keys_user_idx ON user_public_keys(user_id);
