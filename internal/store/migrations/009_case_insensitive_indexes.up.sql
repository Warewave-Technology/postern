-- 009_case_insensitive_indexes: COLLATE NOCASE yerine lower() ifade indeksi.
--
-- Neden: COLLATE NOCASE SQLite'a özgü. PostgreSQL'de karşılığı yok —
-- oradaki seçenekler CITEXT eklentisi ya da lower() ifade indeksi.
-- lower() İKİ MOTORDA DA çalışan tek seçenek olduğu için o seçildi;
-- böylece "hangi motorda hangi karşılaştırma" diye bir soru kalmıyor.
--
-- Bu göç EKLEMELİ: SQLite'taki NOCASE sütun tanımları yerinde duruyor
-- (kaldırmak tablo yeniden inşası ister ve SQLite zaten gidiyor). İki
-- kısıt aynı anda geçerli ve aynı şeyi söylüyor. PostgreSQL şeması
-- NOCASE'siz yazılacak ve YALNIZCA aşağıdaki indeksler taşınacak.
--
-- Uyarı: lower() SQLite'ta yalnız ASCII A-Z'yi katlar, PostgreSQL'de ise
-- yerel ayara duyarlıdır. Makine adları ve grup adları ASCII olduğu için
-- fark pratikte ortaya çıkmıyor; Türkçe I/ı bu sütunlara girmiyor.

CREATE UNIQUE INDEX targets_name_lower_idx ON targets (lower(name));

CREATE UNIQUE INDEX group_mappings_group_role_lower_idx
  ON group_mappings (lower(external_group), role_id);

CREATE UNIQUE INDEX unmapped_groups_name_lower_idx
  ON unmapped_groups (lower(name));

-- Eski arama indeksi artık ölü: sorgular lower(external_group) üzerinden
-- gidiyor ve yukarıdaki UNIQUE indeksin ilk sütunu tam olarak o.
DROP INDEX group_mappings_group_idx;
