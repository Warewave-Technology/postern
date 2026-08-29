-- 017_admin_source: yönetici yetkisinin NEREDEN geldiği.
--
-- ÜRÜN KARARI DEĞİŞTİ: is_admin artık yalnızca host CLI'ından değil, bir
-- dizin/IdP GRUBUNDAN da gelebiliyor. Gerekçe, kurumun postern'in
-- çalıştığı sunucuya kurulumdan sonra hiç girmek zorunda kalmaması —
-- her yönetici ataması için SSH gerekmesi mükerrer iş yükü üretiyordu.
-- Tutarlılık argümanı da aynı yöne bakıyor: dizin zaten kimin
-- production'a erişeceğine karar veriyor, roller ondan geliyor; admin
-- bayrağını kutsal saymak tutarsızdı.
--
-- ⚠️ PANELDEN ATAMA HÂLÂ YOK. Değişen şey, CLI'ın tek kaynak olmaktan
-- çıkıp İKİ kaynaktan biri olması: CLI ve grup.
--
-- ⚠️ NEDEN AYRI SÜTUN: rol modelindeki source='sso' / 'manual' ayrımının
-- aynısı. Onsuz, dizin grubuna bakan kod CLI'ın verdiği yöneticiliği de
-- kaldırabilirdi — acil durum için elle açılmış bir hesabın yetkisini,
-- dizinde o grubu görmediği için silmek. Kaynağı yazmak, her mekanizmanın
-- yalnızca KENDİ verdiğini geri alabilmesini sağlıyor.

ALTER TABLE users ADD COLUMN admin_via TEXT
  CHECK (admin_via IS NULL OR admin_via IN ('cli', 'group'));

-- Mevcut yöneticiler CLI'dan verilmiş sayılır: tek yol oydu. Böylece
-- yükseltmeden sonra dizin grubuna bakan kod onların yetkisine
-- dokunamıyor.
UPDATE users SET admin_via = 'cli' WHERE is_admin = TRUE;
