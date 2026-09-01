-- SFTP dosya olayları.
--
-- NEDEN VAR: `subsystem sftp` bu tablo yazılana kadar REDDEDİLİYORDU.
-- Gerekçe ölçülmüştü: transfer terminal kaydına ham ikili protokol olarak
-- düşüyor, oynatınca anlamsız çıkıyor ve "kim hangi dosyayı aldı" sorusu
-- cevapsız kalıyordu. Kanalın açılabilmesi dosya seviyesinde denetime
-- bağlıydı; burası o denetimin durduğu yer.
--
-- Satırlar SİLİNMEZ (sessions ile aynı gerekçe): kullanıcı sonradan yok
-- olsa bile hangi dosyanın kimin eline geçtiği durmalı.
CREATE TABLE session_files (
  id          TEXT PRIMARY KEY,
  session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
  at          BIGINT NOT NULL,
  -- open, transfer, remove, rename, mkdir, rmdir, setstat, symlink, opendir
  op          TEXT NOT NULL CHECK (op <> ''),
  path        TEXT NOT NULL,
  -- rename ve symlink'te ikinci yol; diğerlerinde boş.
  new_path    TEXT NOT NULL DEFAULT '',
  flags       TEXT NOT NULL DEFAULT '',
  -- GERÇEKTEN taşınan bayt: istenen değil, karşı tarafın verdiği/kabul
  -- ettiği. İstenen sayılsaydı kayıt, hiç okunmamış baytları okunmuş
  -- gösterirdi.
  bytes_read  BIGINT NOT NULL DEFAULT 0 CHECK (bytes_read  >= 0),
  bytes_wrote BIGINT NOT NULL DEFAULT 0 CHECK (bytes_wrote >= 0),
  -- ⚠️ ok=false satırlar da tutuluyor: izinsizlikten dönen bir silme
  -- denemesi, engelin çalıştığının kanıtıdır ve denetimin işi tam da
  -- bunu göstermektir. Yalnızca başarılıları saklayan bir tablo,
  -- "kimse denemedi" ile "herkes denedi ama giremedi"yi aynı gösterirdi.
  ok          BOOLEAN NOT NULL,
  detail      TEXT NOT NULL DEFAULT ''
);

-- "Bu oturumda hangi dosyalara dokunuldu" — oturum detayının sorusu.
CREATE INDEX session_files_session_idx ON session_files(session_id, at);

-- "Bu dosyaya kim dokundu" — soruşturmanın sorusu. Yol üzerinden arama
-- indekssiz kalsaydı, tablo büyüdükçe cevaplanamaz hâle gelirdi.
CREATE INDEX session_files_path_idx ON session_files(path);
