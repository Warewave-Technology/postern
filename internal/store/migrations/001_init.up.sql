-- 001_init: postern'in kalıcı şeması.
--
-- Zaman alanları INTEGER: Unix saniyesi (UTC). SQLite'ın DATETIME'ı
-- aslında metin saklar ve karşılaştırmalarda sürprize açıktır; sayı
-- saklamak hem sıralamayı hem aritmetiği tartışmasız kılar.
--
-- ⚠️ FOREIGN KEY kısıtları burada TANIMLI ama SQLite bunları bağlantı
-- başına PRAGMA foreign_keys = ON denmedikçe UYGULAMAZ (sessizce yok
-- sayar). O pragma'yı store.Open kuruyor — bkz. store.go.

-- ⚠️ CHECK (x <> '') satırları NOT NULL'ın bıraktığı boşluğu kapatıyor:
-- boş string NULL değildir, yani NOT NULL onu kabul eder. Kimlik taşıyan
-- bir sütunda boş string, "değeri yok"un sessiz halidir ve okuyan kodu
-- "bulunamadı" gibi yanlış bir kola sokar.
CREATE TABLE users (
  id         TEXT PRIMARY KEY,
  username   TEXT UNIQUE NOT NULL CHECK (username <> ''),
  -- Boş string yerine NULL yazılması bir sözleşme (bkz. CreateUser);
  -- CHECK onu şema seviyesinde zorunlu kılıyor.
  email      TEXT UNIQUE CHECK (email IS NULL OR email <> ''),
  -- Driver 1'in özü: herkes hedefe KENDİ hesabıyla düşer. Paylaşılan
  -- hesap yok, o yüzden NOT NULL.
  os_user    TEXT NOT NULL CHECK (os_user <> ''),
  created_at INTEGER NOT NULL
);

CREATE TABLE roles (
  id   TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL CHECK (name <> '')
);

CREATE TABLE targets (
  id       TEXT PRIMARY KEY,
  -- COLLATE NOCASE sütunun VARSAYILAN karşılaştırması olur; ORDER BY,
  -- WHERE ve UNIQUE üçü birden büyük/küçük harf ayrımını bırakır.
  -- Sorgulara tek tek COLLATE serpiştirmekten farkı: unutulabilecek bir
  -- yer kalmıyor. (SQLite'ın NOCASE'i yalnızca ASCII A-Z'yi katlar;
  -- makine adları için yeterli.)
  name     TEXT UNIQUE NOT NULL COLLATE NOCASE CHECK (name <> ''),
  host     TEXT NOT NULL CHECK (host <> ''),
  port     INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  -- Hedefin beklenen host key'i. Boş bırakılamaz: InsecureIgnoreHostKey
  -- yok, "host key'i olmayan hedef" diye bir şey de yok.
  host_key TEXT NOT NULL CHECK (host_key <> '')
);

-- ON DELETE CASCADE: kullanıcı silinince yetkisi de gider. Yetim satır
-- bırakmak, silinmiş bir kullanıcının rolünün ortalıkta durması demek.
CREATE TABLE user_roles (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE role_targets (
  role_id   TEXT NOT NULL REFERENCES roles(id)   ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, target_id)
);

-- Denetim kaydı. Buradaki satırlar SİLİNMEZ: kullanıcı ya da hedef
-- sonradan yok olsa bile "kim, nereye, ne zaman girdi" sorusunun cevabı
-- durmalı. Bu yüzden CASCADE değil RESTRICT.
CREATE TABLE sessions (
  id             TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL REFERENCES users(id)   ON DELETE RESTRICT,
  target_id      TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
  -- Oturumun AÇILDIĞI hesap. users.os_user'ın kopyası değil: policy o an
  -- başka bir hesaba karar vermiş olabilir ve denetim, bugünkü değeri
  -- değil o günkü kararı görmek ister.
  os_user        TEXT NOT NULL CHECK (os_user <> ''),
  -- Boş olabilirler ama NULL olamazlar: taranırken sürpriz çıkarmasınlar
  -- diye. Bu tabloda NULL'a izin verilen TEK alan ended_at.
  src_ip         TEXT NOT NULL DEFAULT '',
  recording_path TEXT NOT NULL DEFAULT '',
  started_at     INTEGER NOT NULL,
  -- NULL = oturum hâlâ açık.
  ended_at       INTEGER
);

-- "Bu kullanıcı ne zaman nereye girdi" en sık sorulan denetim sorusu.
CREATE INDEX sessions_user_started_idx   ON sessions(user_id, started_at);
CREATE INDEX sessions_target_started_idx ON sessions(target_id, started_at);
