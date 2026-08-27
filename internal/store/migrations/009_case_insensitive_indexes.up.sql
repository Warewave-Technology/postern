-- 009_case_insensitive_indexes: harf duyarsız kısıtlar ve aramalar.
--
-- Harf duyarsızlık sütun tanımına gömülü DEĞİL, ifade indeksinde.
-- PostgreSQL'de sütuna gömülü seçenek CITEXT eklentisidir; eklenti
-- gerektirmemesi ve karşılaştırmanın sorguda GÖRÜNÜR olması için
-- lower() seçildi. Go tarafındaki karşılığı dialect.go'daki ciEq/
-- ciOrder ve ciColumns listesi.
--
-- Uyarı: lower() PostgreSQL'de veritabanının yerel ayarına duyarlıdır.
-- Makine adları ve grup adları ASCII olduğu için pratikte fark
-- çıkmıyor; Türkçe I/ı bu sütunlara girmiyor.

-- targets.name: asıl benzersizlik kısıtı bu. 001'deki düz UNIQUE yalnız
-- birebir aynı yazımı engeller, "Web01" ile "web01"i ayırmaz.
CREATE UNIQUE INDEX targets_name_lower_idx ON targets (lower(name));

-- Aynı grubun iki yazımı iki ayrı eşleme olmasın.
CREATE UNIQUE INDEX group_mappings_group_role_lower_idx
  ON group_mappings (lower(external_group), role_id);

-- RecordUnmappedGroups'un ON CONFLICT hedefi. Bu indeks olmadan upsert
-- "no unique or exclusion constraint matching the ON CONFLICT
-- specification" der.
CREATE UNIQUE INDEX unmapped_groups_name_lower_idx
  ON unmapped_groups (lower(name));

-- Eski arama indeksi artık ölü: sorgular lower(external_group) üzerinden
-- gidiyor ve yukarıdaki UNIQUE indeksin ilk sütunu tam olarak o.
DROP INDEX group_mappings_group_idx;
