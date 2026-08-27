-- 007_group_mappings: dış grup → yerel rol eşlemesi ve JIT sağlama.

-- Hangi IdP/LDAP grubu hangi role karşılık geliyor.
--
-- Çoktan-çoğa: bir grup birden fazla rol verebilir, bir role birden fazla
-- gruptan hak kazanılabilir. Kurumsal gerçek bu — "sysadmins" hem ops hem
-- network rolü verebilir.
CREATE TABLE group_mappings (
  id TEXT PRIMARY KEY,

  -- IdP'nin gönderdiği grup adı ya da LDAP DN'i. Büyük/küçük harf
  -- duyarsız: AD grupları "Domain Admins" gibi karışık gelir ve aynı
  -- grubun iki yazımı iki ayrı eşleme olmamalı (targets.name'deki
  -- COLLATE NOCASE kararının aynısı).
  external_group TEXT NOT NULL COLLATE NOCASE CHECK (external_group <> ''),

  role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,

  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',

  UNIQUE (external_group, role_id)
);

CREATE INDEX group_mappings_group_idx ON group_mappings(external_group);

-- Teşhis: IdP'nin gönderdiği ama eşlenmemiş gruplar.
--
-- Varlık sebebi Warpgate'in issue #1283'ü: claim geliyor, eşleşme yok,
-- hiçbir yerde iz yok ve kimse neyin yanlış olduğunu anlayamıyor. Bu
-- tablo yöneticiye "IdP bana şunları söylüyor, hangisini eşlemek
-- istersin" listesini verir — eşleme kurmayı tahmin işi olmaktan çıkarır.
CREATE TABLE unmapped_groups (
  name TEXT PRIMARY KEY COLLATE NOCASE,
  last_seen INTEGER NOT NULL,
  seen_count INTEGER NOT NULL DEFAULT 1
);
