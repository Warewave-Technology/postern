-- 009 geri alma: eski arama indeksini geri koy, ifade indekslerini kaldır.
CREATE INDEX group_mappings_group_idx ON group_mappings(external_group);

DROP INDEX unmapped_groups_name_lower_idx;
DROP INDEX group_mappings_group_role_lower_idx;
DROP INDEX targets_name_lower_idx;
