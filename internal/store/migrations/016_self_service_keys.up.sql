-- 016_self_service_keys: ilk anahtarın kendi kendine eklenebilmesi.
--
-- NEDEN: SSH tarafı anahtarla çalışıyor ama anahtar ekleyen tek uç
-- yöneticideydi. Yani her kullanıcı için yöneticinin tek tek anahtar
-- girmesi gerekiyordu — dizini olan bir kurumda bu, dizinden kaçınmak
-- için kurulan sistemin geri getirdiği elle iş.
--
-- KURAL: ilk anahtar serbest, sonrakiler yeniden kimlik doğrulama ister.
-- Gerekçe, oturumu ele geçiren birinin KALICILIK kurmasını zorlaştırmak:
-- anahtarı olmayan kullanıcı zaten SSH'a giremiyor, yani ilk anahtar
-- normal akış. Anahtarı OLAN birinin hesabına ikinci bir anahtar
-- eklenmesi ise tam olarak saldırganın yapacağı hamle.
--
-- ⚠️ NEDEN SAYIYA DEĞİL TARİHE BAKIYORUZ: kural "şu an anahtarın var mı"
-- olsaydı, sil-ve-ekle onu tamamen atlardı. Oturumu ele geçiren kişi
-- mevcut anahtarı siler, sayaç sıfıra döner ve yeni anahtarı serbestçe
-- ekler. Damga bir kez konuyor ve bir daha kalkmıyor.

ALTER TABLE users ADD COLUMN first_key_added_at BIGINT;

-- Zaten anahtarı olan mevcut kullanıcılar "ilk anahtarını kullanmış"
-- sayılır: yükseltmeden sonra kimse bedava ikinci bir anahtar
-- ekleyemesin. Değer olarak hesabın oluşturulma anı yazılıyor; kesin
-- tarih bilinmiyor ve önemli olan damganın VARLIĞI.
UPDATE users SET first_key_added_at = created_at
WHERE id IN (SELECT DISTINCT user_id FROM user_public_keys);
