-- ⚠️ BU GERİ ALMA KAYIPLI VE SIRADAN BİR DROP DEĞİL.
--
-- Tablo gittiğinde budayıcı "bu yüklendi mi" sorusunu soramaz hale
-- gelir; yapılandırma da kapatılmadıysa eski davranışa döner ve
-- HENÜZ YÜKLENMEMİŞ kayıtları silmeye başlar. Geri alan operatör,
-- önce recording.archive yapılandırmasını kapatmalı.
DROP INDEX IF EXISTS session_archives_pending_idx;
DROP TABLE IF EXISTS session_archives;
