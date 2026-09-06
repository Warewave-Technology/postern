-- TOTP deneme sayacı ve kilit.
--
-- ⚠️ NEDEN BURADA, users'TA DEĞİL: sayaç kimlik DOĞRULAYICIYA ait. Kullanıcı
-- doğrulayıcısını sıfırlattığında (admin reset-totp) satır gidiyor ve sayaç
-- onunla birlikte gidiyor — istenen de bu: yeni doğrulayıcı, temiz sayfa.
--
-- ⚠️ PAROLA KAPISINDA KİLİT YOK, BURADA VAR — VE FARK GERÇEK.
-- locallogin.go'nun "kilitleme yok" gerekçesi 128 bitlik, MAKİNE ÜRETİMİ bir
-- sır içindi: kilitleme 2^128'i denemeyen kimseye bir şey kazandırmaz ama
-- kimliği doğrulanmamış birine "tek yöneticiyi dışarıda bırak" düğmesi
-- verirdi. TOTP kodu ise ALTI HANE (10^6) ve buraya ulaşan taraf parolayı
-- ZATEN kanıtlamış durumda. Yani kilit gerçek bir tahmin saldırısını
-- kesiyor ve düğme kimliği doğrulanmamış birinin elinde değil.
--
-- ⚠️ KİLİT SÜRELİ, KALICI DEĞİL. Kalıcı kilit, parolası sızmış bir hesap
-- üzerinden tek yöneticiyi süresiz dışarıda bırakabilirdi. Süre dolunca
-- kendiliğinden açılıyor; yönetici `postern admin unlock` ile erken de
-- açabiliyor.
ALTER TABLE totp_credentials
  ADD COLUMN failures INTEGER NOT NULL DEFAULT 0,

  -- locked_until, kilidin bittiği an (unix saniye). 0 = kilit yok.
  --
  -- NULL yerine 0: "kilitli değil" ile "hiç kilitlenmemiş" arasında bir
  -- ayrım yok ve NULL, her okuyan yere bir dal daha eklerdi.
  ADD COLUMN locked_until BIGINT NOT NULL DEFAULT 0;
