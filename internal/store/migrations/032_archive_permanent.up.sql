-- 032_archive_permanent: yüklenemeyen kaydı KUYRUKTAN ÇIKARAN durum.
--
-- ⚠️ ÖLÇÜLEN ARIZA: bir arşiv satırının kaydı diskte YOKSA (özellik
-- açılmadan önce budanmış, ya da elle silinmiş), yükleyici onu her turda
-- "kalıcı hata" diye işaretliyor ama satırı candidate kümesinden ÇIKARAN
-- hiçbir durum yoktu. attempts sonsuza kadar artıyor, satır sonsuza
-- kadar yeniden claim ediliyor, ArchiveBacklog onu "bekliyor" sayıyor ve
-- bir gün sonra "disk dolacak" alarmı KALICI olarak yanıyordu — oysa o
-- kayıt için yapılabilecek hiçbir şey yok.
--
-- archive.go'daki fail() geçici/kalıcı ayrımını ZATEN hesaplıyordu ama
-- sonucu yalnızca Warn/Error seçmek için kullanıyordu; satıra hiç
-- yazılmıyordu. Bu sütun o kararı kalıcı kılıyor.
--
-- ⚠️ archived_at İLE AYRI: archived_at "başarıyla yüklendi", permanent
-- "hiç yüklenemeyecek". İkisi de satırı candidate kümesinden çıkarır ama
-- operatöre bambaşka şey söyler — biri "güvende", diğeri "kayıp".
ALTER TABLE session_archives
  ADD COLUMN permanent BOOLEAN NOT NULL DEFAULT FALSE;
