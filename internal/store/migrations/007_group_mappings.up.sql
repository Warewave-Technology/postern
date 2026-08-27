-- 007_group_mappings: dış grup → yerel rol eşlemesi ve JIT sağlama.

-- Hangi IdP/LDAP grubu hangi role karşılık geliyor.
--
-- Çoktan-çoğa: bir grup birden fazla rol verebilir, bir role birden fazla
-- gruptan hak kazanılabilir. Kurumsal gerçek bu — "sysadmins" hem ops hem
-- network rolü verebilir.
CREATE TABLE group_mappings (
  id TEXT PRIMARY KEY,

  -- IdP'nin gönderdiği grup adı ya da LDAP DN'i. Harf duyarsız
  -- karşılaştırılır (AD grupları "Domain Admins" gibi karışık gelir ve
  -- aynı grubun iki yazımı iki ayrı eşleme olmamalı) — ama kısıt burada
  -- değil, 009'daki lower() ifade indeksinde. targets.name ile aynı
  -- karar.
  external_group TEXT NOT NULL CHECK (external_group <> ''),

  role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,

  created_at BIGINT NOT NULL,
  created_by TEXT NOT NULL DEFAULT ''
);

CREATE INDEX group_mappings_group_idx ON group_mappings(external_group);

-- Teşhis: IdP'nin gönderdiği ama eşlenmemiş gruplar.
--
-- Varlık sebebi Warpgate'in issue #1283'ü: claim geliyor, eşleşme yok,
-- hiçbir yerde iz yok ve kimse neyin yanlış olduğunu anlayamıyor. Bu
-- tablo yöneticiye "IdP bana şunları söylüyor, hangisini eşlemek
-- istersin" listesini verir — eşleme kurmayı tahmin işi olmaktan çıkarır.
CREATE TABLE unmapped_groups (
  name TEXT PRIMARY KEY,
  last_seen BIGINT NOT NULL,
  seen_count INTEGER NOT NULL DEFAULT 1
);
