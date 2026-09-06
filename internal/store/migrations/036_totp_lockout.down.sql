-- Geri alma KİLİTLERİ KALDIRIYOR.
--
-- ⚠️ SESSİZ DEĞİL, GÖRÜNÜR OLMALI: o an kilitli olan hesaplar geri alma ile
-- birlikte açılıyor. Sayaç da sıfırlanıyor — sütun gidince tutulacak yer
-- kalmıyor. Geri almayı yapan kişi bunu bilerek yapıyor olmalı.
ALTER TABLE totp_credentials
  DROP COLUMN failures,
  DROP COLUMN locked_until;
