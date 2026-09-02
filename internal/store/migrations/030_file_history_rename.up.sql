-- Yeniden adlandırmanın HEDEF yolu üzerinden arama.
--
-- NEDEN VAR: soruşturma "/tmp/exfil buraya nereden geldi" diye sorar ve
-- dosya oraya bir rename ile gelmişse, satırın `path`i KAYNAK yoldur —
-- hedef yalnızca `new_path`te durur. 027'deki indeks yalnızca `path`i
-- kapsıyordu, yani hedef yol üzerinden arama tabloyu baştan sona
-- taramak zorunda kalırdı; büyüyen bir denetim tablosunda bu, sorunun
-- pratikte cevapsız kalması demek.
--
-- KISMİ İNDEKS: satırların ezici çoğunluğunda new_path boş (yalnızca
-- rename ve symlink dolduruyor). Boş dizeleri indekslemek, hiç
-- aranmayacak milyonlarca anahtar tutmak olurdu. Sorgu da aynı koşulu
-- açıkça yazıyor (new_path <> '' AND new_path = $1) — planlayıcının
-- kısmi indeksi kullanabilmesi için koşulun sorguda GÖRÜNMESİ gerekiyor.
--
-- ÖLÇÜLDÜ (5000 satır + ANALYZE, PostgreSQL EXPLAIN): planlayıcı iki
-- indeksi BitmapOr ile birleştiriyor, yani hem kaynak hem hedef yol
-- üzerinden arama indeksten gidiyor:
--
--   Bitmap Heap Scan on session_files f
--     -> BitmapOr
--          -> Bitmap Index Scan on session_files_path_idx
--          -> Bitmap Index Scan on session_files_new_path_idx
CREATE INDEX session_files_new_path_idx
  ON session_files(new_path)
  WHERE new_path <> '';
