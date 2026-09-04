-- ⚠️ GERİ ALMAK MÜHÜRLÜ SATIRLARI OKUNAMAZ BIRAKIR.
--
-- Sütunu düşürmek, mühürlü değerin düz metin sanılmasına yol açar: 033
-- öncesi kod her satırı düz metin okur ve mühürlü bir sırla üretilen kod
-- hiçbir zaman tutmaz. Sonuç sessiz değil — kullanıcı kodunu girer, reddedilir
-- ve neden reddedildiğini gösteren hiçbir şey yoktur.
--
-- O yüzden geri alma, mühürlü satırları SİLİYOR. Kaybedilen şey ikinci
-- faktörün kaydı; kazanılan şey, ikinci faktörü VAR SANILAN bir hesabın
-- kalmaması. Etkilenen kullanıcılar TOTP'yi yeniden kurar (yönetici
-- sıfırlamasına gerek yok: kayıt satırı yoksa akış baştan açılır).
--
-- Mühürsüz satırlara dokunulmuyor; onlar 033 öncesi kodda da doğru okunur.
DELETE FROM totp_credentials WHERE sealed;

ALTER TABLE totp_credentials
  DROP COLUMN sealed;
