# postern — S6: LDAP kimlik sağlayıcı (parolasız mod)

> Karar kaydı ve uygulama planı. `postern-PLAN.md`'deki S1–S5 dizisinin
> devamı: S6 parolasız LDAP, S7 LDAP bind, S8 TOTP.

**Hedef.** Mevcut dizini olan bir kurum, önce bir OIDC sağlayıcı (Keycloak)
dikmek zorunda kalmadan postern'i kurabilsin. Kullanıcının parolası hiçbir
aşamada postern'e uğramaz.

---

## 0. Bu planın dayandığı ölçümler

Aşağıdakiler varsayım değil; bu ağaçta çalıştırılarak doğrulandı.

| # | Ölçüm | Nerede |
|---|---|---|
| M1 | `underBase("cn=x,ou=evil\,ou=groups,dc=corp", "ou=groups,dc=corp")` → **true** | düzeltildi, `4235ab9` |
| M2 | `normalize("cn=sysadmins,ou=teams,ou=groups,dc=corp")` → `"sysadmins"` | açık, S6.0 |
| M3 | `DeleteUser` oturum kaydı olanı reddediyor; `sso_only` hiç temizlenmiyor | `store.go:550` |
| M4 | `BuildPlan` sıfır SSO rolü olan Absent kullanıcıyı da `zeroing`'e sayıyor | `plan.go:117-127` |
| M5 | Girişte `Groups()` `nil,nil` dönünce `SyncRoles(user, [])` tüm SSO rollerini siliyor | `store.go:1019` |
| M6 | `ldap.connect` her sorguda taze TCP+TLS+bind açıyor, havuz yok | `ldap.go:187` |
| M7 | `max_conns`=256, `max_conns_per_ip`=8, `max_auth_tries`=4, `max_channels_per_conn`=10 | `config.go:271-274` |
| M8 | Demo dizininde `ldapPublicKey`/`sshPublicKey` şeması zaten etkin | `openssh-lpk` |

---

## 1. Karar: dizini aynalıyoruz — ama yalnızca bir dizin olarak

İki seçenek ciddi biçimde karşılaştırıldı. **Canlı sorgu** (postern hiçbir
şey saklamaz, her soruyu dizine sorar) iki nedenle eleniyor:

**1. Ön-kimlik yolunun sorduğu soruyu LDAP cevaplayamaz.** `publicKeyCallback`
eline bir anahtar bloğu alır ve "bu kimin?" diye sorar. Dizinde bunun ters
indeksi yoktur: `sshPublicKey` OpenLDAP'ta varsayılan olarak eşitlik indeksli
değildir, AD'de hiç yoktur. Eşitlik zaten tutmaz — istemci
`ssh.PublicKey.Marshal()` sunar, dizinde ise yorumlu bir `authorized_keys`
satırı durur. Eşleştirmek için **saldırgandan gelen baytlardan kurulan bir
substring filtresi** gerekirdi: indekssiz, imza doğrulanmadan önce, postern'in
servis hesabıyla. Tek başına diskalifiye.

Dolayısıyla canlı tasarım anahtarla değil `conn.User()` ile arama yapmak
zorunda kalır — yani istemcinin yazdığı adla. Bu, **invariant 6**'nın (kimlik
kararlı ve opak bir çiftle bağlanır, asla kullanıcı adıyla) geri alınamaz
biçimde ihlalidir.

**2. Ölçülen yükseltici.** M6 + M7: her sorgu taze TLS+bind demek. 256 bağlantı
× 4 deneme, `curl` seviyesinde bir çabayla kurumun kendi servis hesabını
kullanarak dizine karşı ~1000 eşzamanlı bind üretir. postern dizin için bir
DoS yükselticisine dönüşür — üstelik artık her giriş o dizine bağımlıdır.

**Karar.** Ayna kalıyor, ama **rütbesi düşürülüyor**:

> `directory_keys`, "bu anahtar kimin?" sorusunu **ağ trafiği olmadan**
> cevaplayan bir **indekstir**. Hiçbir şeyin otoritesi değildir. Her yetki
> gerçeği — kişi hâlâ orada mı, grupları ne, anahtar hâlâ girişinde mi —
> oturum açılışında **canlı** okunur ve ayna o okumadan düzeltilir.

Bundan türeyen üç kural:

1. Ayna, canlı okumanın verdiğinden **fazlasını asla vermez**.
2. Aynayı **tek bir okuma yok edemez**; silme, nüfus bağlamı olan periyodik
   koşuya aittir (replika gecikmesi kilitlenmeye dönüşmesin).
3. Ayna **sonsuza kadar bayatlayamaz**: `ldap.confirm_grace` sert durak.

---

## 2. Kimlik modeli

OIDC'deki `(issuer, subject)` çiftinin LDAP karşılığı:

- **issuer** = postern'in ürettiği, dizin sunucusuna ait kararlı bir kimlik
  (`ldap:<realm-uuid>`). URL **değil** — adres değişince kimlik kopmamalı.
- **subject** = dizin girişinin kararlı benzersiz kimliği: `entryUUID`
  (OpenLDAP/389ds), `objectGUID` (AD), `nsuniqueid`. Öznitelik adı **beyaz
  listeden** seçilir; serbest metin değil.

Kullanıcı adı hiçbir aşamada eşleştirme anahtarı değildir. Yeniden
adlandırma bağı koparmaz.

**TOFU ve JIT yok.** LDAP kimliği yalnızca açık, denetlenen bir operatör
eylemiyle bağlanır (`postern ldap enroll`). Gerekçe: parolasız modda hesap,
anahtar, grup ve rol aynı alt ağaçta duruyor; otomatik bağlama, dizine giriş
açabilen herkese hesap devralma imkânı verirdi. `is_admin` hesaplar panelden
hiç bağlanamaz (CLI + açık bayrak).

---

## 3. Dilimler

Her dilim tek başına gönderilebilir ve ağacı yeşil bırakır. Sıra, en riskli
yüzeyin en sona kalması için seçildi.

### S6.0 — Bugün kırık olanı düzelt (yeni özellik yok)

> **Durum:** S6.0 tamamlandı (`4235ab9`, `569f56b`, `1ba63e3`, `bf7eec0`, `a5e4a83`).
> S6.1 tamamlandı (`5ce17a9` P0, `3f0b0fb` yerel kapı).
> S6.2 tamamlandı: anahtarla dizin girişi (`13b8a64`), dizin parolasıyla
> panel girişi (`b70903d`), grup üzerinden yöneticilik (`3b7d216`) ve onay
> ekranı (`933392f`).
>
> ⚠️ Aşağıdaki S6.2/S6.3 başlıkları planın İLK hâlinden kalma ve
> uygulanan tasarımı anlatmıyor. Sohbette şu yönde revize edildi:
> LDAP artık grup kaynağı değil **kimlik sağlayıcı**; SSH yalnızca
> anahtar, kurumsal parola yalnızca panelde; yöneticilik panelden
> atanamıyor ama bir dizin grubu taşıyabiliyor; ve o grubu ayarlamak,
> kime yetki verildiğini gösteren bir onay ekranından geçiyor.
>
> S6.3 tamamlandı (`790ee10`): tek aktif giriş kaynağı ve `unknown` grubu.
>
> ⚠️ **Plandan sapma, bilinçli.** İstenen "OIDC ve LDAP için birer
> `enabled` bayrağı, aynı anda yalnızca biri açık" idi. Bunun yerine tek
> değerli `auth.source` (`local` | `oidc` | `ldap`) yazıldı: iki bayrak,
> "ikisi birden açık" durumunu TEMSİL EDİLEBİLİR yapıyor ve kuralı her
> yazma yolunda tekrarlanan bir kontrole bağlıyor — CLI'dan doğrudan
> yazan biri, bir yarış ya da kontrolü eklemeyi unutan yeni bir uç onu
> bozar. Tek değerde o durum hiç yok.
>
> Kaynak değiştirmek panelde KANIT istiyor (geçilecek kapının gerçekten
> birini içeri alabildiği); CLI'da istemiyor ve uyarıyor — acil çıkışı
> bir dizinin ulaşılabilirliğine bağlamak onu acil çıkış olmaktan
> çıkarırdı.
>
> **Sırada:** kararlı dizin kimliği (entryUUID/objectGUID) ile bağlama.
> Bugün dizin kapısı JIT hesap AÇMIYOR, çünkü kararlı bir subject
> olmadan hesap açmak kullanıcı adına dayalı bir bağ kurmak olurdu
> (011'de kapatılan açık). S8'de TOTP, `mykeys.go`'daki yeniden
> doğrulamaya bağlanacak.

Bunlar LDAP dönüşümünden bağımsız olarak değerli; sonrasını de-riske ediyor.

| # | İş | Ölçüm |
|---|---|---|
| 0.1 | DN'leri metin değil DN olarak karşılaştır | M1 — **bitti**, `4235ab9` |
| 0.2 | `ldap.group_scope` = `direct` (**karar: varsayılan**) \| `subtree`; `subtree` yalnızca `group_name_from=dn` ile geçerli | M2 |
| 0.3 | `zeroing`/`revoking` yalnızca **gerçekten rol kaybedecek** kullanıcıyı saysın | M3, M4 |
| 0.4 | `SyncRoles`'a açık değiştirme semantiği; `PresenceAbsent`/`Unknown` asla rol silmesin | M5 |
| 0.5 | `GET /api/admin/sync/runs` + panelde kalıcı uyarı şeridi | 0.3'ün arızası görünmez dönmesin |
| 0.6 | **P0 — HTTP yüzeyini OIDC'den ayır** | Ölçüldü: `OOBEnabled()` düpedüz `IssuerURL != ""` ve `serve.go:127` bütün paneli onun içine alıyor. Tezimizin hedeflediği kurulum bugün AÇILAMIYOR. |

0.2 mevcut kurulumlar için **kırıcı**: grupları bir OU daha derinde duran bir
kurum, `direct`'e geçince rol kaybeder. Bu yüzden 0.2 şunlarla birlikte
gider: `postern doctor ldap-groups` (hangi eşlemenin kapsam dışı kalacağını
listeler), senkron raporunda ayrı bir satır, ve sürüm notlarında en üstte.

### S6.1 — Kendi kullanıcı veritabanı ve yerel kapı ✅

P0 tek başına gönderilemez: kapısı olmayan bir panel açmak olurdu. Bu yüzden
ayırma işi yerel kapıyla birlikte gidiyor.

- **Kimlik bilgisi: yalnızca makine üretimi sır.** `postern admin bootstrap`
  120 bitlik bir sır üretir, **bir kez** basar, bir daha göstermez. Operatör
  parola SEÇEMEZ.

  ⚠️ Gerekçe, kolaylık değil: "yerel parolanı AD parolan yapma" demek bunu
  engellemez; postern'i o değeri **alamayacak** hâle getirmek engeller. Yan
  etkileri zincirleme — kimlik bilgisi doldurma yapısal olarak imkânsız, kaba
  kuvvet güvenlik sorunu olmaktan çıkıp erişilebilirlik sorununa iner, ve
  kilitleme mekanizmasına hiç gerek kalmaz (kilitleme, tek admini kilitleyen
  silahtır).
- İkinci kapı olarak SSH anahtarı: `--key` ile açılan admin, panel oturumunu
  kimliği doğrulanmış SSH kanalından alır; ağa yeni kimlik bilgisi eklenmez.
- Giriş ekranı ne olduğunu DOĞRU söylemeli: yapılandırılmış kapılar
  (`local` / `oidc` / `ldap`) uca sorulur, buton uydurulmaz.

⚠️ Dürüst not: bu sır **panel-only değildir.** Admin panelden kendine rol
atayabiliyor (`admin.go:306`), dolayısıyla bir yerel giriş yönetilen her
makinede oturuma dönüşebilir.

### S6.2 — SSH kapısında LDAP kimliği ← SIRADAKİ

- **Migration 015**: `user_identities` (OIDC ve LDAP'ı tek tabloda toplayan
  `kind` + `issuer` + `subject`), `directory_keys` (`key_blob` **tek sütun
  PRIMARY KEY**, `user_id`, `absent_since`, `first_seen`).
- **`postern ldap enroll`** — önizleme + o önizlemenin üstüne HMAC'li onay
  jetonu; operatör *gördüğü şeyi* onaylar, bir adı değil. Aynı işlemde:
  kimlik satırı, anahtarların aynalanması, `SyncRoles`, denetim satırı.
- **`publicKeyCallback`**: yerel anahtar **koşulsuz kazanır**; dizin indeksi
  ikinci sırada. **Ağ trafiği yok.** Çakışan blob hiç aynalanmaz (aynı
  anahtarı kendi girişine kopyalayarak birini kilitleme saldırısı, `key_blob`
  PK'si sayesinde temsil edilemez hâle gelir).
- **`internal/dirconfirm` kapısı**: oturum açılışında **tek arama** ile
  varlık + subject + gruplar + anahtarlar; `SyncRoles` yeniden koşar. Satır
  **silmez**, `absent_since` işaretler. `confirm_ttl` (5dk) / `confirm_grace`
  (12s) ile sınırlı, tek-uçuşlu ve eşzamanlılığı tavanlı.
- Periyodik koşuda anahtar aynalaması; **silme yarısı bir sürüm boyunca
  yalnızca dry-run**.

### S6.3 — Dizin kullanıcıları için panel kapısı

- Panel oturumu **kimliği doğrulanmış SSH kanalından** açılır
  (`ssh kullanıcı:postern@bastion` → terminale URL + kod). **Kimliksiz bir
  HTTP ucu yok** — bu seçim, "kimliksiz `/auth/ssh/begin` selleyerek paneli
  kapalı tutma" ve "istemci `User-Agent`'ını kurbanın terminaline ham basma"
  bulgularını yapısal olarak ortadan kaldırır.
- Terminale basılan her şey **sunucu tarafından yazılır**; istemciden gelen
  hiçbir dize doğrudan basılmaz.
- `requireSession`, `ldap` kullanıcılarını aynı kapıdan tazeler (panel
  oturumu dizin hesabından uzun yaşamasın).

---

## 4. Ayarlar

| Anahtar | Varsayılan | Yazan | Gerekçe |
|---|---|---|---|
| `ldap.identity_enabled` | `false` | CLI | Güvenlik anahtarı unutulunca **kapalı** olmalı |
| `ldap.uid_attribute` | — | panel (beyaz liste) | Serbest metin, subject'i değiştirilebilir bir alana çevirip invariant 6'yı çökertirdi |
| `ldap.key_attribute` | `sshPublicKey` | panel | Şema standart |
| `ldap.group_scope` | `direct` | panel | M2; güvenli taraf varsayılan |
| `ldap.confirm_ttl` | `5m` | panel | Rol/anahtar iptalinin üst sınırı |
| `ldap.confirm_grace` | `12h` | CLI | Bayat aynanın sert durağı |
| `sync.dry_run` | mevcut | panel | Açmak güvenli eylem; tehlike **görünmezlik**, o yüzden şerit + saatlik uyarı |
| `sync.max_*` tavanları | mevcut | **CLI** | Panelden gevşetilebilir bir patlama yarıçapı tavanı, tavan değildir |

---

## 5. Test planı

Mevcut LDAP testlerinin tamamı gerçek bir OpenLDAP konteynerine karşı koşuyor;
bu yüzden **düşmanca dizin cevapları üretilemiyor**. S6.1 ile birlikte
`internal/ldap/ldaptest` altında **betiklenebilir sahte bir LDAP sunucusu**
geliyor. Zorunlu vakalar:

- Kaçışlı virgüllü DN, çok değerli RDN, tırnaklı değer *(M1 regresyonu — var)*
- Aynı CN'in farklı alt-OU'da olması *(M2)*
- `objectGUID` ikili biçimi; `entryUUID` metin biçimi
- Referral dönen ve **sıfır giriş** dönen arama → `Absent` **değil** `Unknown`
- AD aralıklı getirme (`memberOf;range=0-1499`), öznitelik seçenekleri
- Yinelenen `sshPublicKey` değeri; bozuk satır; `authorized_keys` seçenekli
  satır (reddedilmeli); aşırı büyük öznitelik
- Servis hesabının okuyamadığı giriş
- Aynı blob'un iki girişte olması → aynalanmaz, denetime düşer
- Dizin yavaş / kapalı → `confirm_grace` içinde degrade, sonrasında ret

Ayrıca: her düzeltme için **mutasyon kontrolü** (düzeltmeyi geri al, testin
düştüğünü gör, geri koy) — bu repoda uygulanan kural.

---

## 6. Kapsam dışı (S6)

Alt ağaç sayımıyla otomatik kullanıcı keşfi · çoklu dizin sunucusu · nested
group çözümleme · LDAP bind ile parola doğrulama (S7) · TOTP (S8) · panel
üzerinden `is_admin` (hiçbir zaman).

---

## 7. S7 / S8 payı

`user_identities` tablosu `kind` taşıdığı için bind kimliği üçüncü bir tür
olarak eklenir; kimlik modeli değişmez. `dirconfirm` kapısı S7'de de aynı
kapıdır. TOTP, kimlikten bağımsız bir ikinci faktör tablosu olarak gelir ve
`secret` paketinin mevcut şifrelemesini kullanır.

**S7'nin devraldığı yük** (şimdiden biliniyor): hesap durumu kontrolü
(`userAccountControl`, `pwdAccountLockedTime`, süresi dolmuş parola), kilitleme
ve hız sınırlama, parola süresi sinyali, ve "postern parolayı görmez"
iddiasının kaybı — panelde açıkça yazılacak.
