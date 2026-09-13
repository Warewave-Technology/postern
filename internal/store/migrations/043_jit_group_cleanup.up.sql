-- Hakla açılan gruplar ve geri almada temizlenip temizlenmeyecekleri.
-- created_groups: postern'in BU hak için açtığı gruplar (JSON liste);
-- cleanup_groups: geri almada boş kalanları silme izni (varsayılan evet).
ALTER TABLE jit_grants ADD COLUMN created_groups TEXT NOT NULL DEFAULT '[]';
ALTER TABLE jit_grants ADD COLUMN cleanup_groups BOOLEAN NOT NULL DEFAULT TRUE;
