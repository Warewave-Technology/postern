-- "Bu dizinin altında ne oldu" — önek üzerinden arama.
--
-- NEDEN VAR: soruşturmanın en sık sorduğu soru tek bir dosya değil bir
-- ağaç: "/etc altında ne oldu". Tam eşleşmeyle sormak, oradaki her
-- dosyanın adını önceden bilmeyi gerektirirdi.
--
-- NEDEN AYRI BİR İNDEKS: 027'deki `session_files(path)` indeksi
-- VARSAYILAN opclass ile kurulu ve bu veritabanının collation'ı
-- en_US.utf8. PostgreSQL, C dışı bir collation'da düz btree indeksini
-- `LIKE 'önek%'` için KULLANAMIYOR — karşılaştırma sırası ile bayt
-- sırası aynı olmadığı için önek aralığını indekste ifade edemiyor.
-- text_pattern_ops tam da bu boşluk için var: bayt sırasına göre
-- karşılaştırır, dolayısıyla önek aralığı indekste bir aralıktır.
--
-- ÖLÇÜLDÜ (200.000 satır + ANALYZE):
--
--   LIKE '/data/dir42/%' , yalnızca 027 indeksi   → Parallel Seq Scan, 6.1 ms
--   LIKE '/data/dir42/%' , text_pattern_ops ile   → Index Scan,        0.33 ms
--
-- Fark tablo boyutuyla doğrusal büyüyor ve `session_files` hızlı
-- büyüyen bir tablo (tek bir rsync binlerce satır yazıyor).
--
-- PARAMETRELİ SORGUYLA DA ÇALIŞIYOR — ayrıca ölçüldü. Sabit metinle
-- çalışıp yer tutucuyla çalışmamak, tam da sessizce tam taramaya
-- düşülecek durum olurdu:
--
--   Index Cond: (path ~>=~ '/data/dir42/' AND path ~<~ '/data/dir420')
--
-- ⚠️ 027'DEKİ İNDEKS DURUYOR AMA ARTIK GEREKMİYOR OLABİLİR. İlk hâlde
-- buraya "text_pattern_ops tam eşitlik için kullanılamaz" yazmıştım;
-- ÖLÇÜM BUNU ÇÜRÜTTÜ. 027'deki indeksi düşürüp denedik:
--
--   path = $1              → Index Scan on ..._path_pattern_idx, 0.014 ms
--   path LIKE 'önek%'      → Index Scan on ..._path_pattern_idx, 0.279 ms
--
-- Yani bugün kodun çalıştırdığı her sorguyu bu indeks tek başına
-- karşılıyor. 027'ninki yine de DÜŞÜRÜLMEDİ: `session_files` sistemin
-- en hızlı yazılan tablosu ve oradan bir indeks silmek ayrı bir karar
-- — collation sırasına göre bir aralık ya da ORDER BY gerektiren bir
-- sorgu eklenirse geri istenecek olan o.
CREATE INDEX session_files_path_pattern_idx
  ON session_files(path text_pattern_ops);

-- Hedef yol için aynısı, 030'daki kısmi indeksle aynı gerekçeyle:
-- satırların ezici çoğunluğunda new_path boş.
CREATE INDEX session_files_new_path_pattern_idx
  ON session_files(new_path text_pattern_ops)
  WHERE new_path <> '';
