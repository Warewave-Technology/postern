-- Geri alma zincir başlarını siler; kayıt dosyalarına dokunmaz.
--
-- Kaybedilen şey, o kayıtların doğrulanabilirliği: dosyalar yerinde
-- kalır ama "yazıldığı gibi mi" sorusu bir daha cevaplanamaz. Sütunu
-- düşürmek yerine boşaltmak diye bir seçenek yok — sütunun kendisi
-- gidiyor.
ALTER TABLE sessions DROP COLUMN recording_links;
ALTER TABLE sessions DROP COLUMN recording_chain;
