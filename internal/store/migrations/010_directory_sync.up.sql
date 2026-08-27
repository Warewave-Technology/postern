-- 010_directory_sync: dizin senkronizasyonunun durumu ve geçmişi.
--
-- Kapatılan boşluk: grup üyeliği YALNIZCA girişte çözülüyordu. Dizinde
-- silinen bir kullanıcı, bir daha giriş denemedikçe rollerini sonsuza
-- kadar tutuyordu — sso_only (008) bu deliğin yarısını kapatıyor
-- (anahtar kapısını kesiyor), yetkinin TAZELENMESİNİ değil.

-- dir_last_seen_at: dizinde en son ne zaman görüldü.
-- dir_missing_since: İLK kez ne zaman bulunamadı (NULL = bulunuyor).
--
-- Ayrı bir tabloda değil kullanıcı satırında, çünkü grace penceresi için
-- gereken tek durum bu ve mevcut kullanıcı sorgularında bedavaya geliyor.
ALTER TABLE users ADD COLUMN dir_last_seen_at  BIGINT;
ALTER TABLE users ADD COLUMN dir_missing_since BIGINT;

-- Senkronizasyon koşularının geçmişi.
--
-- Ayrı tablo çünkü bu KİMLİK değil işletim geçmişi — ve çünkü "son
-- başarılı senkronizasyon ne zamandı" bir iptal yanlış göründüğünde
-- operatörün soracağı İLK soru. Görülmeyen bir iptal, hiç
-- senkronizasyon olmamasıyla aynı arıza: operatör iptallerin
-- işlediğini sanırken dizin bir haftadır ulaşılamaz olabilir.
CREATE TABLE sync_runs (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

  started_at  BIGINT NOT NULL,
  finished_at BIGINT,

  -- Hangi kaynak ('ldap') ve neyin tetiklediği ('timer' | 'cli').
  source  TEXT NOT NULL DEFAULT '',
  trigger TEXT NOT NULL CHECK (trigger <> ''),

  -- ok       : uygulandı
  -- skipped  : yapılandırılmamış ya da başka bir koşu sürüyor
  -- aborted  : güvenlik tavanı devreye girdi, HİÇBİR ŞEY uygulanmadı
  -- failed   : beklenmeyen hata
  outcome TEXT NOT NULL CHECK (outcome IN ('ok', 'aborted', 'failed', 'skipped')),
  reason  TEXT NOT NULL DEFAULT '',

  users_considered INTEGER NOT NULL DEFAULT 0,
  users_present    INTEGER NOT NULL DEFAULT 0,
  users_absent     INTEGER NOT NULL DEFAULT 0,
  users_unknown    INTEGER NOT NULL DEFAULT 0,
  users_revoked    INTEGER NOT NULL DEFAULT 0,
  roles_changed    INTEGER NOT NULL DEFAULT 0,

  dry_run BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX sync_runs_started_idx ON sync_runs(started_at DESC);

-- admin_log.via'ya 'sync' eklenmeli: koşunun yazdığı denetim satırları
-- aksi hâlde CHECK kısıtına takılır — ve bu, gözden geçirmede değil
-- VERİTABANINDA patlar.
ALTER TABLE admin_log DROP CONSTRAINT admin_log_via_check;
ALTER TABLE admin_log ADD CONSTRAINT admin_log_via_check
  CHECK (via IN ('web', 'cli', 'sync'));
