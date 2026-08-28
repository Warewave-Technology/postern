-- 012_target_labels: hedeflere key=value etiketleri.
--
-- NEDEN AYRI TABLO, JSON SÜTUNU DEĞİL: etiketler aranacak ve
-- süzülecek. Ayrı satırlar bunu düz bir indeksle veriyor; JSON sütunu
-- ise ya her sorguda tam tarama ya da ifade indeksi ister — ikisi de
-- bu boyuttaki bir veri için gereksiz karmaşıklık.
--
-- ⚠️ ON DELETE CASCADE: hedef silinince etiketleri de gider. RESTRICT
-- olsaydı, etiketlenmiş bir hedef silinemez hâle gelir ve operatör
-- silmek için önce etiketleri tek tek kaldırmak zorunda kalırdı —
-- etiket bir yetki değil, yalnızca not.
CREATE TABLE target_labels (
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  key       TEXT NOT NULL CHECK (key <> ''),
  value     TEXT NOT NULL,
  PRIMARY KEY (target_id, key)
);

-- Etikete göre arama: "env=prod olan hedefler".
CREATE INDEX target_labels_kv_idx ON target_labels(key, value);
