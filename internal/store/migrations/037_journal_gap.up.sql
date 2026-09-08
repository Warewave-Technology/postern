-- Denetim defterinin EKSİK OLABİLECEĞİNİ söyleyen üç sütun.
--
-- NEDEN VAR: kayıt (.cast) ile defter (session_files) aynı olayı iki
-- ayrı yere yazıyor ve İKİSİ HİÇ KARŞILAŞTIRILMIYORDU. Ölçülen yol:
-- proxy/sftpjournal.go tampon dolduğunda olayı atıyor, ama olay o ana
-- kadar kayda ÇOKTAN yazılmış oluyor (emitSFTP önce kayda, sonra
-- deftere). Yani düşen her olay, kaydın mühür satırında sayılıp
-- defterde HİÇ görünmeyen bir olay. Atma hiçbir yere yazılmıyordu:
-- kanıt sessizce kayboluyor, ekran ise dosya listesini eksiksiz
-- gösteriyordu.
--
-- Üç sütun üç ayrı soruyu cevaplıyor ve hiçbiri diğerinden türetilemez.

-- sftp_events: kaydın mühür satırındaki olay sayısı (sftpcast.go,
-- castEvents). Karşılaştırmanın BEKLENEN tarafı.
--
-- ⚠️ NULL KASITLI VE "SIFIR" DEĞİL. Bu göçten önce kapanmış oturumlarda
-- ve kaydı hiç tutulmamış oturumlarda mühür YOK; sıfır yazmak, satırı
-- olan her eski oturumu "defterde fazlalık var" diye suçlardı. NULL,
-- kontrolün ÇALIŞMADIĞINI söylüyor — "geçti" değil. Zincir başındaki
-- (034) boş baş kararının aynısı.
ALTER TABLE sessions
  ADD COLUMN sftp_events BIGINT;

-- sftp_digest: mühür satırındaki özet — kayda giren satırların
-- XOR'lanmış SHA-256'sı, onaltılık.
--
-- ⚠️ SAYIYLA AYNI ŞEYİ SORMUYOR. sftp_events "kaç satır", bu "hangi
-- satırlar" diyor. İkisi ayrı müdahaleyi yakalıyor: sayı tutmuyorsa
-- satır silinmiş, sayı tutup özet tutmuyorsa satır DEĞİŞTİRİLMİŞ. Silinen
-- satır hiç değilse bir boşluk bırakıyor; değiştirilen satır tam bir
-- denetim kaydı gibi duruyor ve bugüne kadar onu hiçbir şey görmüyordu.
--
-- ⚠️ BOŞ, "SIFIR ÖZET" DEĞİL. Dosya olayı olmayan oturumda kayda mühür
-- satırı hiç yazılmıyor; buraya sıfırların onaltılığını yazmak, dosyada
-- karşılığı olmayan bir değeri "kayıt böyle diyor" diye saklamak olurdu.
ALTER TABLE sessions
  ADD COLUMN sftp_digest TEXT NOT NULL DEFAULT '';

-- sftp_lost: postern'in KENDİ kaybettiğini bildiği olay sayısı.
--
-- ⚠️ AYRI BİR SÜTUN, ÇÜNKÜ AYRI BİR BULGU. "postern tamponu taştığı
-- için üç olayı yazamadı" ile "üç satır sonradan silindi" aynı
-- aritmetiği verir (satır sayısı mühürden üç eksik) ama bambaşka iki
-- olaydır. Bu sütun olmadan ikisini ayırmanın yolu yok ve ayırt
-- edemeyen bir kontrol, her arızayı kurcalama diye okur.
ALTER TABLE sessions
  ADD COLUMN sftp_lost BIGINT NOT NULL DEFAULT 0;

-- in_recording: bu satırın kayıtta bir karşılığı var ve mühür onu
-- sayıyor.
--
-- ⚠️ NEDEN SÜTUN, NEDEN op'TAN ÇIKARIM DEĞİL. session_files'a iki ayrı
-- yazıcı yazıyor: SFTP günlükçüsü (kayda da giren olaylar) ve kanal
-- düzeyindeki ret defteri (proxy/lifecycle.go, `denied.<istek türü>` —
-- kayda GİRMİYOR). İkisi de `denied.` önekini kullanabiliyor, çünkü yol
-- düzeyindeki retler de öyle işaretleniyor. Hangi satırın mühürde
-- sayıldığını op dizgesinden tahmin eden bir sorgu, x11 isteği
-- reddedilmiş her SFTP oturumunu "defter tutmuyor" diye raporlardı —
-- yani kontrolün kendisi yanlış alarm üretirdi.
--
-- ⚠️ VARSAYILAN FALSE, VE YÖNÜ BİLİNÇLİ. Eski satırlar false kalıyor;
-- onların oturumlarında sftp_events NULL olduğu için kontrol zaten
-- çalışmıyor. İleride bu bayrağı koymayı unutan yeni bir yazıcı olursa
-- sonuç "satır eksik" alarmı olur — sessizce "tamam" değil. Denetimde
-- yanlış yön budur.
ALTER TABLE session_files
  ADD COLUMN in_recording BOOLEAN NOT NULL DEFAULT FALSE;

-- ⚠️ AYRI BİR İNDEKS AÇILMIYOR. Kontrolün sorduğu şey "bu oturumun
-- mühürde sayılan kaç satırı duruyor"; 027'deki session_files_session_idx
-- session_id ile başlıyor, yani bir oturumun satırlarını zaten bir arada
-- tutuyor. Sayım oturum başına birkaç yüz satırda dönüyor ve yalnızca
-- `session verify` ile oturum ayrıntısında koşuyor — veri yolunda değil.
