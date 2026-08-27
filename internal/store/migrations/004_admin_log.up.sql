-- 004_admin_log: yönetici işlemlerinin denetim kaydı.
--
-- Oturumlar için sessions neyse, yönetim için bu: "ops rolüne db01'i kim,
-- ne zaman ekledi?" sorusunun cevabı. S3 sözleşmesine "gelecek" diye
-- yazılmıştı; değiştiren API geldiğine göre vadesi doldu.
--
-- actor TEXT ve KASITLI olarak FK DEĞİL: log, işleri yapan kullanıcıdan
-- uzun yaşamalı. Silinen bir yöneticinin geçmiş işlemleri "bilinmeyen
-- satır"a dönüşmemeli. (sessions'taki RESTRICT kararıyla aynı aile,
-- farklı araç: orada satırı adlarla JOIN'liyorduk, burada adı doğrudan
-- yazıyoruz çünkü aktör dış dünyadan da gelebilir: "cli".)
CREATE TABLE admin_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  at      INTEGER NOT NULL,
  -- Kim: web'de oturum sahibi kullanıcı adı; CLI'da işletim sistemi
  -- kullanıcısı (dosya erişimi = yetki modeli, aktör de o).
  actor   TEXT NOT NULL CHECK (actor <> ''),
  -- Hangi kapıdan: 'web' | 'cli'.
  via     TEXT NOT NULL CHECK (via IN ('web', 'cli')),
  -- Ne: makine-okur eylem adı ('user.create', 'role.grant' ...).
  action  TEXT NOT NULL CHECK (action <> ''),
  -- Neye: etkilenen varlığın adı ('yigit', 'ops', 'web01').
  entity  TEXT NOT NULL,
  -- İnsan-okur ayrıntı ('granted target web01').
  details TEXT NOT NULL DEFAULT ''
);

CREATE INDEX admin_log_at_idx ON admin_log(at);
