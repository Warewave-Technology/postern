-- Kayıt zincirinin başı: "bu .cast dosyası yazıldığı gibi mi" sorusunun
-- cevabı.
--
-- NEDEN VAR: bu ürünün en büyük iddiası oturumların kaydedildiği, ama
-- "kayıt olan bitendir" cümlesi bugüne kadar KANITSIZDI — dosyayı
-- düzenleyen hiçbir iz bırakmıyordu. Rakiplerin durumu da aynı ve bunu
-- kendi belgeleri yazıyor; burada iddia kanıta çevriliyor.
--
-- Zincirin tanımı internal/record/chain.go'da ve doğrulayıcı orada:
--   H(0) = SHA-256("postern-recording-chain-v1")
--   H(n) = SHA-256(H(n-1) ‖ satır_n)
--
-- ⚠️ İKİ SÜTUN, ÇÜNKÜ İKİ AYRI SORU VAR. Baş "değişti mi" sorusunu
-- cevaplıyor; halka sayısı ise baş tutmadığında "nereye kadar tuttu"
-- sorusunu. Olay müdahalesinde ikincisi çoğu zaman daha kıymetli:
-- kaydın bozuk olduğunu bilmek yetmiyor, nerede kesildiğini bilmek
-- gerekiyor.
--
-- ⚠️ VARSAYILAN BOŞ, VE BU BİR EKSİKLİK DEĞİL. Bu göçten önce kapanmış
-- oturumların zinciri yok ve geriye dönük üretilemez — üretmeye
-- çalışmak, o dosyaların o tarihte böyle olduğunu iddia etmek olurdu ki
-- bilmiyoruz. Boş baş "doğrulanamaz" demek, "doğrulandı" değil; panel ve
-- `postern session verify` bu ikisini ayrı göstermek zorunda.
ALTER TABLE sessions
  ADD COLUMN recording_chain TEXT NOT NULL DEFAULT '';

ALTER TABLE sessions
  ADD COLUMN recording_links BIGINT NOT NULL DEFAULT 0;
