-- Kayıtların nesne deposuna kopyalanması.
--
-- NEDEN VAR: denetim izi bugüne kadar YALNIZCA denetlenen makinede
-- duruyordu. Bastion'ı ele geçiren kayıtları da ele geçiriyor; diskten
-- uzun bir saklama yükümlülüğünün cevabı yok; yedek tamamen operatörde.
-- "Kayıt açılamazsa oturum reddedilir" diyen bir tasarımın o kaydı
-- saldırganın erişebildiği tek diskte bırakması tutarsızdı.
--
-- ⚠️ AYRI TABLO, sessions'a SÜTUN DEĞİL. 001_init sessions için kuralı
-- yazıyor: "Bu tabloda NULL'a izin verilen TEK alan ended_at." Yükleme
-- durumu doğası gereği NULL'lu (henüz yüklenmedi) ve bir yeniden deneme
-- döngüsünün denetim tablosuna sürekli UPDATE atması da yanlış olurdu.
-- sessions kanıt; burası o kanıtın nerede olduğunun defteri.
--
-- ⚠️ ON DELETE RESTRICT: oturum satırı silinemiyor (sessions ile aynı
-- gerekçe), dolayısıyla arşiv satırı da sahipsiz kalamıyor.
CREATE TABLE session_archives (
  session_id     TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE RESTRICT,

  -- Yükleme BAŞARIYLA doğrulandığında dolar. NULL = henüz güvende değil.
  --
  -- ⚠️ BUDAYICININ TEK SORDUĞU ŞEY BU. Dolu değilse dosya silinmiyor;
  -- yani "yüklendi sandık ama olmadı" ile "yüklendi ve doğrulandı"
  -- arasındaki farkı bu sütun taşıyor.
  archived_at    BIGINT,

  -- Nesnenin yeri. Panel bunu gösteriyor: arşivlenmiş bir kaydı
  -- denetçi kendi kimliğiyle oradan alıyor.
  bucket         TEXT NOT NULL DEFAULT '',
  object_key     TEXT NOT NULL DEFAULT '',

  -- Gönderilen içeriğin özeti. Bütünlük MÜHRÜ değil (bastion'ı ele
  -- geçiren ikisini de üretir); bozulmayı yakalayan bir kontrol.
  sha256         TEXT NOT NULL DEFAULT '',
  size_bytes     BIGINT NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),

  -- Kaç kez denendi ve en son ne oldu. Operatörün "neden yüklenmiyor"
  -- sorusunun cevabı log'da kaybolmasın diye tabloda.
  attempts       INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  last_error     TEXT NOT NULL DEFAULT '',
  last_attempt_at BIGINT,

  -- Bir işçinin satırı üstlendiği an. Yeniden başlatmada süresi geçmiş
  -- talepler serbest kalıyor; temizliğe değil ZAMAN AŞIMINA güveniyoruz,
  -- çünkü öldürülen süreç hiçbir temizlik yapamaz.
  claimed_at     BIGINT
);

-- Bekleyenleri bulmak için: yüklenmemiş satırlar.
CREATE INDEX session_archives_pending_idx
  ON session_archives (claimed_at, last_attempt_at)
  WHERE archived_at IS NULL;

/*
 * ⚠️ ÖZELLİK AÇILDIĞINDA VAR OLAN KAYITLAR NE OLACAK.
 *
 * Üç küme var ve hiçbiri sessiz bir varsayılana bırakılamaz:
 *
 *  1. Dosyası duran, bitmiş oturumlar — bunlara satır AÇIYORUZ, yani
 *     ilk koşuda yüklenecekler. Muaf tutsaydık, geçmiş kayıtlar
 *     korumasız kalır ve operatör "artık arşivleniyor" derken yarısı
 *     dışarıda kalırdı.
 *  2. Dosyası budayıcı tarafından çoktan silinmiş oturumlar — bunlara
 *     da satır açılıyor; yükleyici dosyayı bulamayınca satırı KALICI
 *     hata ile işaretleyecek. "Kayıp" ile "bekliyor" farklı şeyler ve
 *     ikisini de görmek gerekiyor.
 *  3. Hâlâ açık oturumlar — satır AÇMIYORUZ: dosyaları henüz
 *     bitmedi. Kapandıklarında normal yolla açılacaklar.
 */
INSERT INTO session_archives (session_id)
SELECT id FROM sessions
WHERE recording_path <> '' AND ended_at IS NOT NULL;
