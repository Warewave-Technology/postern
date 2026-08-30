-- 022_pending_users: hesap açılışı otomatik değilse, ONAY KUYRUĞU.
--
-- Ürün kararı: "IdP'de hesabın olması postern'de hesabın olması demek
-- değil" kuralı korunuyor, ama bunun bedeli kullanıcı için kapalı bir
-- kapı olmamalı. Kimliği doğrulanan kişi "hesabınız onay bekliyor"
-- görüyor, yönetici de kimin beklediğini.
--
-- ⚠️ SATIR KARARLI KİMLİKLE ANAHTARLANIYOR, kullanıcı adıyla DEĞİL.
--
-- Adla anahtarlansaydı, reddedilen kişi dizinde adını değiştirip
-- yeniden başvurabilirdi — yani "tekrar tekrar kaydı engelleme"
-- ihtiyacının kendisi karşılanamazdı. Kararlı kimlik (objectGUID /
-- entryUUID / OIDC sub) dizinde adını değiştirse de aynı kalıyor
-- (ölçüldü), dolayısıyla RED YAPIŞKAN olabiliyor.
--
-- ⚠️ Aynı sebep, kuyruğun bir yazma yükselticisine dönüşmesini de
-- engelliyor: kimliği doğrulanmış biri kaç kez denerse denesin TEK
-- satır oluşuyor, her deneme yalnızca last_seen'i güncelliyor.

CREATE TABLE pending_users (
  id TEXT PRIMARY KEY,

  -- Kaynağın verdiği DEĞİŞMEZ kimlik. Benzersiz: bir kişi, bir satır.
  subject TEXT NOT NULL UNIQUE CHECK (subject <> ''),

  -- 'dir' (LDAP) ya da 'oidc'. Hangi kapıdan geldiğini denetim ve
  -- onay ekranı için saklıyoruz.
  source TEXT NOT NULL CHECK (source IN ('dir', 'oidc')),

  -- Kaynağın o anki adı ve e-postası. ⚠️ YALNIZCA GÖSTERİM İÇİN:
  -- hiçbir karar bunlara bakmıyor, çünkü ikisi de değişebilir.
  username TEXT NOT NULL,
  email    TEXT NOT NULL DEFAULT '',

  -- Görüldüğü andaki gruplar, virgülle. Yine yalnızca gösterim:
  -- onaydan sonra roller, kişinin BİR SONRAKİ girişinde canlı
  -- kaynaktan çözülüyor. Bayat bir grup listesine göre rol yazmak,
  -- yetkiyi geçmişteki bir fotoğrafa bağlamak olurdu.
  seen_groups TEXT NOT NULL DEFAULT '',

  -- 'waiting' ya da 'rejected'. Onaylanan satır SİLİNİYOR: hesap
  -- artık users tablosunda ve kuyrukta bir kopyası durursa iki ayrı
  -- doğruluk kaynağı olur.
  state TEXT NOT NULL DEFAULT 'waiting' CHECK (state IN ('waiting', 'rejected')),

  first_seen BIGINT NOT NULL,
  last_seen  BIGINT NOT NULL,

  -- Reddin kim tarafından, ne zaman ve NEDEN verildiği.
  decided_by TEXT NOT NULL DEFAULT '',
  decided_at BIGINT,
  reason     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX pending_users_state_idx ON pending_users (state, last_seen DESC);
