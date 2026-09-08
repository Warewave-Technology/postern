-- Geri alma, defterin eksik olabileceği bilgisini SİLER.
--
-- Kaybedilen şey somut: hangi oturumda kaç olayın kayda girip deftere
-- girmediği. Kayıt dosyalarındaki mühür satırı yerinde kalıyor, ama onu
-- karşılaştıracak sayı gidiyor ve `postern session verify` o oturumlar
-- için bir daha "defter tam mı" sorusunu cevaplayamıyor.
ALTER TABLE session_files DROP COLUMN in_recording;
ALTER TABLE sessions DROP COLUMN sftp_lost;
ALTER TABLE sessions DROP COLUMN sftp_digest;
ALTER TABLE sessions DROP COLUMN sftp_events;
