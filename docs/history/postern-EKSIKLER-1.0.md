# 1.0 için eksikler

*1–2 Eylül 2026 gecesi yapılan elden geçirme. Ölçülen her şeyin kanıtı
yanında; ölçülmeyen hiçbir şey "sorun yok" diye yazılmadı.*

Ölçüt iki cümleydi: **güvenlikte hassasız, ama overengineering
istemiyoruz.** Rapor buna göre bölündü:

1. **Sağlam bulduklarım** — listeye güvenmen için önce neye baktığımı gör.
2. **Bulunan ve düzeltilenler** — dördü de testli ve mutasyon testinden geçti.
3. **Kapatılmayan eksikler** — bilerek bırakıldı, gerekçesiyle.
4. **1.0'da yapılmaması gerekenler** — bu liste ötekiler kadar önemli.

---

## Önce: sağlam bulduklarım

Bunları tek tek açıp baktım, çünkü aşağıdaki listeye güvenmen için önce
neye baktığımı bilmen lazım.

| Alan | Durum |
|---|---|
| OIDC akışı | `state` + `nonce` + PKCE (S256) — üçü de var, üçü de doğru yerde |
| ID token | `provider.Verifier` ile imza + `aud` doğrulaması |
| Oturum çerezi | `HttpOnly`, `SameSite=Lax`, `Secure` (external_url https ise) |
| Parola tahmini | argon2id + artan gecikme + eşzamanlılık kotası |
| Kanal politikası | yalnızca `session`; `direct-tcpip` dahil her şey `UnknownChannelType` ile ret |
| Sertifika | 5 dk ömür, tek principal, yalnızca `permit-pty` uzantısı |
| Host key | kayıt için **zorunlu**; panelde parmak izi operatöre onaylatılıyor |
| Kayıt dosyaları | dizin `0700`, dosya `0600`, `O_EXCL` |
| Kayıt budama | `serve` içine bağlı, çalışıyor |
| Ayarların şifrelenmesi | AES-256-GCM, anahtar ayrı dosyada |
| DB TLS | `sslmode` yazılmamışsa `verify-full` (libpq'nun sessiz düz metne düşmesi engelleniyor) |
| Şema | `serve`, göç geride kalmışsa **başlamıyor** |
| Göçler | 28 up / 28 down — geri dönüş yolu tam |
| Kapanış | `SIGTERM` yakalanıyor, 5 sn son çare süresi |
| Yönetici eylemleri | `admin_log` tablosuna aktörüyle yazılıyor |
| Loglar | kimlik bilgisinden bahseden her `logger.*` çağrısı tek tek okundu: hepsi OLAYI adlandırıyor, hiçbiri DEĞERİ geçirmiyor. DSN maskeli basılıyor (`postgres://postern:xxxxx@...`) |

---

## Bulunan ve DÜZELTİLEN on dört şey

İlk üçü aynı sınıftan: **kural yazılmıştı, bağlanmamıştı.** Dördüncüsü
bir adım daha ince: iki ayrı doğru karar, birleşince yanlış davranıyordu.

Bu desen oturum boyunca tekrar tekrar çıktı ve raporun asıl konusu bu.

Her biri önce ölçüldü, sonra düzeltildi, sonra mutasyon testinden
geçirildi: düzeltmeyi kaldır → testin düştüğünü gör → geri koy.

### B1 — Silinen hesabın açık paneli çalışmaya devam ediyordu

**Ciddiyet: bloklayıcı.**

`internal/sshd/auth.go:70` hesabın durumunu okuyor ve kendi yorumu bunu
"OIDC kurulumlarındaki tek iptal yolu" diye tanımlıyor. Panel tarafında
`requireSession` ise oturumu **bellekten** çözüyor ve veritabanına hiç
bakmıyordu. `store.ActiveUser` — tam bu kontrol için yazılmış yardımcı —
**hiç çağrılmıyordu.**

Ölçüm (entegrasyon koşumu, gerçek hedefe karşı):

```
silmeden ÖNCE: /api/me = 200, hedefler = [web01]
DB'deki durum artık: deleted
silmeden SONRA: /api/me = 200, hedefler = [web01]
SONUÇ: SİLİNMİŞ HESAP KABUK AÇTI — ilk çerçeve: "Welcome to Alpine!..."
```

Yani yönetici "sil"e basıyor, SSH kapısının gürültüyle kapandığını
görüyor ve erişimin bittiğini sanıyor — oysa açık sekmesi olan kişi
kabuk açmaya devam ediyor. Sınır, web oturumunun 12 saatlik ömrü; her
sabah giren biri için o sınır her sabah yenileniyor.

**Düzeltme:** `requireSession` her istekte `RefuseIfDeleted` çağırıyor.
Kural GİRİŞTEKİYLE AYNI — `inactive` burada da reddedilmiyor, çünkü
reddetseydik kişi çıkıp yeniden girerek aynı yere gelirdi. Veritabanı
susuyorsa 401 değil **503**: "çözemedim" ile "yetkin yok" ayrı şeyler ve
geçerli kullanıcıyı parolasını sıfırlamaya göndermek yanlış teşhis olurdu.

Testler: `TestWebSessionStopsWhenAccountIsDeleted` (silme durduruyor mu)
ve `TestWebSessionSurvivesInactive` (birinin ileride fazla sıkıştırıp
tatilden dönenleri kapıda bırakmasını engelliyor).

### B2 — `os_user` yalnızca oturum anında denetleniyordu

**Ciddiyet: önemli. En yaygın kurumsal IdP'de her kurulumu bozuyor.**

`policy.Authorize` `os_user`'ı `^[a-z_][a-z0-9_.-]{0,31}$` desenine göre
eliyor. Hiçbir **yazma** yolu aynı kuralı uygulamıyordu: JIT sağlama
`os_user`'ı IdP kullanıcı adından birebir alıyor
(`CreateUser(..., req.Username)`), panel yalnızca boş mu diye bakıyor,
CLI hiç bakmıyor, şemada da yalnızca `<> ''` var.

Entra ID / Azure AD `preferred_username`'e **UPN** koyuyor:
`yigit@corp.com`. Desene uymuyor. Sonuç: hesap açılıyor, roller
veriliyor, yönetici listesinde görünüyor, panelde hedef kartları
çıkıyor — ve **her bağlantı** "access denied" ile düşüyor. Sebebi
açıklayan tek cümle bastion'ın log'unda.

Aynı şey `Yigit` (büyük harf) ve `şüheda.celik` (Türkçe harf) için de
geçerli.

**Düzeltme:** kural tek yere taşındı (`model.ValidOSUserName`) ve
**yazan yerin kendisine** bağlandı — `CreateUser` ve `SetUserOSUser`.
Böylece yeni bir çağıran eklendiğinde kuralı hatırlaması gerekmiyor.
Politika kapısındaki kontrol yine duruyor: veritabanına elle
dokunulmuş bir satıra karşı son savunma.

Panel artık **400 ve okunabilir bir cümle** dönüyor, 500 "internal
error" değil — bu hatanın metni operatörün az önce yazdığı değere dair,
sır taşımıyor ve tam olarak eksik olan şey oydu.

**Normalleştirmedik.** `yigit@corp.com` → `yigit` cazip ama
`a@x.com` ile `a@y.com`'u aynı hesaba çarpardı; iki insanı tek
principal'da birleştirmek, kimliği `(iss,sub)` ile bağlama kararının
tam tersi olurdu.

### B3 — SFTP yeniden adlandırmaları denetim defterine hiç düşmüyordu

**Ciddiyet: önemli — ve bunu ancak GERÇEKTEN DENEYEREK bulduk.**

Çözücü `SSH_FXP_RENAME` (18) paketini işliyordu. OpenSSH'in kendi sftp
istemcisi ise, sunucu eklentiyi ilan ettiğinde **`SSH_FXP_EXTENDED`
(200) / `posix-rename@openssh.com`** gönderiyor. O dal hiç yoktu.

Demoda ölçüldü: `rename yukle.txt yeni-ad.txt` hedefte başarıyla
çalıştı, `session_files` tablosunda karşılığı **yoktu**. Yani pratikte
her yeniden adlandırma görünmez geçiyordu — dosyaların taşınması,
denetim defterinde hiç iz bırakmadan.

`hardlink@openssh.com` de aynı durumdaydı ve daha kötüsü: sert bağ bir
dosyaya ikinci bir ad veriyor, yani silinmiş görünen bir içerik başka
bir yerde yaşamaya devam edebiliyor.

**Düzeltme:** `SSH_FXP_EXTENDED` çözülüyor; `posix-rename` → `rename`,
`hardlink` → `hardlink`, `lsetstat` → `setstat`. Zararsız üstveri
eklentileri (`fsync`, `statvfs`...) `stat`/`readdir` gibi satır
üretmiyor. **Tanımadığımız her eklenti adıyla birlikte yazılıyor** —
arızanın asıl dersi buydu: yarın eklenen bir eklenti önceden onaylanmış
olmamalı.

Düzeltme sonrası aynı istemciyle ölçüm:

```
 rename   | /home/sidinak/taze.txt   | /home/sidinak/tasindi.txt | t
 hardlink | /home/sidinak/kaynak.txt | /home/sidinak/sertbag.txt | t
 symlink  | kaynak.txt               | /home/sidinak/yumusakbag  | t
```

### B4 — Ters vekil arkasında yönetici panelden kilitlenebiliyordu

**Ciddiyet: yüksek. Kimliği doğrulanmamış bir saldırganın uzaktan
kullanabileceği tek bulgu buydu.**

İki ayrı doğru karar, birleşince yanlış davranıyordu.

`clientKey` bilerek yalnızca `RemoteAddr` okuyor ve gerekçesi doğru:
`X-Forwarded-For`'u koşulsuz okumak, istemcinin kendi hız sınırı
anahtarını seçmesine izin vermek olurdu. `backoffKey` ise (hesap, adres)
çiftiyle anahtarlıyor ve *onun* gerekçesi de doğru: yalnızca hesaba göre
saymak, yabancıya "yöneticiyi dışarıda tut" düğmesi verirdi.

Ama TLS için ters vekil **şart koştuğumuz** topolojide `RemoteAddr`
herkes için vekilin adresine çöküyor, çift tekile iniyor ve backoff.go'nun
engellemek için yazıldığı senaryo aynı kapıdan geri geliyordu.

Ölçüm:

```
saldırgan anahtarı = fc0e8e7498064614
yönetici  anahtarı = fc0e8e7498064614
SONUÇ: anahtarlar AYNI — vekil arkasında izolasyon yok
YÖNETİCİNİN beklemesi = 4m59.999999958s
```

Ret sayacı artırmadığı için saldırganın maliyeti **beş dakikada bir
istek**, karşılığı süresiz kilit. Hedefin adını tahmin etmek de
gerekmiyor: `postern admin bootstrap` varsayılan olarak `admin` açıyor.

CLI break-glass durduğu için yıkıcı değildi — kilit paneli kapatıyordu,
kurulumu değil. Ki bu tam olarak o tasarımın var olma sebebi.

**Düzeltme:** `http.trusted_proxies`. `RemoteAddr` listedeyse
`X-Forwarded-For` okunuyor, değilse eski davranış aynen sürüyor.
**Liste boşken — varsayılan — hiçbir şey değişmiyor.**

Zincir **sağdan sola** yürünüyor: soldaki girdileri istemci uydurabilir,
güvenilen vekiller sağdan elenince kalan ilk adres doğrulayabildiğimiz en
uzak atlamadır. Bozuk bir CIDR **başlamayı kesiyor** — yok saymak,
operatörün vekilini tanıttığını sandığı ama tanıtmadığı bir kurulum
üretirdi, yani kilidin sessizce geri geldiği hâl.

Yedi test, iki mutasyonla doğrulandı.

### B5 — Yönetici canlı bir oturumu sonlandıramıyordu ✅ 2 Eylül'de kapatıldı

Panel canlı oturumları listeliyor ama kesecek bir düğmesi yoktu; kartın
kendi alt satırı bunu yazıyordu: *"Closing one is not possible from here
yet."* Bir bastion için "şu an kes" çekirdek işlem — kayıt tutup
kesememek, olaydan sonra ne olduğunu izleyip o sırada seyretmek demek.

**Mekanizma yeni değil.** Boşta kalma ve ömür sınırı zaten bağlamı
iptal ederek çalışıyordu ve o yol `TestIdleSessionIsClosedAndRecorded`
ile kanıtlıydı. Kesme, dördüncü bir kapanış sebebi olarak aynı yola
girdi: `Broker.Run` `ctx.Done()`'da uyanıyor, yarım SFTP transferlerini
yazıyor, kanalları kapatıyor; `Close` kaydı kapatıp `ended_at` yazıyor.

Üzerine eklenenler:

- **`POST /api/admin/sessions/{id}/terminate`** — `DELETE` değil: bu
  API'de DELETE satır siliyor ve oturum satırı denetim izi, asla
  silinmiyor.
- **Denetim satırı ÖNCE.** Yazamıyorsak kesmiyoruz. Sonra yazsaydık,
  veritabanı o an düşen bir kurulumda yöneticinin izsiz iş yapabildiği
  bir yol açılırdı.
- **Dört ayrı cevap, tek "başarısız" değil:** kesildi / zaten bitmişti /
  bu süreçte akmıyor / böyle bir oturum yok.
- **Kullanıcı sebebini görüyor** ve aynı cümle kayda işleniyor — yoksa
  oynatılan `.cast` ortasından kesilmiş görünür ve olayı inceleyen
  "burada ne oldu" sorusunu kayıttan cevaplayamazdı.
- **Yıkım sırası ters çevrildi:** önce hedef, sonra istemci. `down.Close()`
  kovulan tarafa yazıyor; tıkalı bir istemci onu geciktirdiğinde hedefteki
  kabuk yaşamaya devam ediyordu — yani düğmenin verdiği tek garanti
  sıranın sonundaydı.

**Ekranın yalan söylemediği yer:** kesmek erişimi ALMIYOR. Kart artık
bunu yazıyor. Onay kutusunda bir çare adı da **vermiyoruz**: ilk metin
"hesabı pasifleştir" diyordu, sonra ölçüldü ki dört giriş yolunun dördü
de `ConfirmAccount` çağırıyor ve o `inactive`'i `active`'e geri
çeviriyor. Operatörden güvenmesini istediğimiz kutuya yarı doğru bir
vaat koymak, hiçbir şey dememekten kötüydü.

**Bu iş üç önceden var olan sorunu da açığa çıkardı** ve üçü de aynı
commit setinde kapandı, çünkü hepsi düğmeyi yalancı çıkarıyordu:

1. **Açılışta sahipsiz satırlar uzlaştırılmıyordu.** SIGKILL sonrası
   `ended_at` sonsuza dek NULL kalıyordu (ölçüldü). Panel onları süresiz
   "çalışıyor" gösteriyordu; düğme var olmayan bir oturuma basardı.
   Artık açılışta kapanıyor ve kaç satır olduğu loglanıyor.
2. **`SessionEnded` olayı `ended_at` yazılmadan ÖNCE yayınlanıyordu.**
   Paneli olayla tazeleyen yönetici oturumu hâlâ "running" görüyordu —
   yani çalışan bir kesme "bastım, bir şey olmadı" diye okunurdu. Yayın
   `Close`'a taşındı.
3. **Aktif liste en yeni 200 satır üzerinde istemci süzgeciydi.**
   Sabahtan beri açık bir oturumun üstüne 200 yeni oturum bindiğinde o
   oturum karttan düşüyordu; görünmeyen oturum kesilemez de. Açık
   oturumlar artık kendi sorgusundan geliyor.

**Kanıt:** `TestTerminateClosesALiveSession` gerçek bir `sleep 300`
oturumu açıp API'den kesiyor ve oturumun GERÇEKTEN öldüğünü ölçüyor —
durum kodu testi, çalışan bir kesmeyi hiçbir şey yapmayan bir 200'den
ayırt edemezdi. Mutasyon: `Terminate` iptal etmeden `true` dönünce test
"KESME İŞE YARAMADI: `sleep 300` hâlâ akıyor" diyerek düşüyor.

**Yapılmayanlar** (tek düğüm 1.0 için fazlalık): `sessions` tablosuna
`closed_by` sütunu, kullanıcının kendi oturumunu kesmesi, "kes ve
pasifleştir" birleşik diyaloğu, zorunlu gerekçe alanı, süreçler arası
kesme. Sonuncusunun tek yükümlülüğü ucun "bu süreçte akmıyor" diye ayrı
bir cevap vermesi ve veriyor.

### B6 — CLI, var olan bir kullanıcıya rol veremiyordu ✅ 2 Eylül'de kapatıldı

`user add --role` yalnızca hesabı AÇARKEN rol verebiliyordu; `user
modify` e-posta, os-user, admin ve sso-only ile sınırlıydı. Panelde
vardı, CLI'da yoktu — yani tam olarak **panelin çalışmadığı an** için var
olan yolda yoktu. Demo kurulurken de aynı duvara toslandı.

**Eklenen dört komut:**

| Komut | Neden |
|---|---|
| `user grant-role --name X --role Y` | Asıl eksik |
| `user revoke-role --name X --role Y` | Aynısının tersi |
| `role list` | `store.Roles` yazılmıştı, CLI'dan çağıran yoktu: host'a girmiş operatör hangi roller var göremiyordu |
| `role revoke-target --name X --target Y` | `store.RevokeTarget` da öyle: rol bir makineye bağlanıyordu ama geri alınamıyordu |

Adlandırma `grant-role` / `revoke-role`, `grant` / `revoke` değil: bu
CLI'da `add` satır yaratan komutların sözü ve atama satır yaratmıyor.

**Yol boyunca çıkan üç şey — üçü de aynı sette kapandı:**

1. ⚠️ **En ciddisi, sessiz bir yetki kalıcılaşması.** `AssignRole`'un
   `ON CONFLICT` dalı `source`'u koşulsuz `manual` yapıyor; `SyncRoles`
   ise yalnızca `source='sso'` satırlarını siliyor. Yani dizinden gelen
   bir rolü elle "yeniden vermek", o rolü senkronizasyonun
   erişemeyeceği yere taşıyor: kişi gruptan çıkarıldığında **rol
   üzerinde kalıyor ve hiçbir otomatik yol geri alamıyor.** Komut artık
   yazmadan önce kaynağı okuyup bunu söylüyor. Engellemiyor — acil çıkış
   yolu kimseyi kilitlemez — ama sessiz de kalmıyor.
2. **Denetim adı ikiye ayrılmıştı.** CLI `user.role_assign`, panel
   `user.grant_role` yazıyordu; `action=user.grant_role` diye süzen bir
   denetçi, break-glass yoluyla verilmiş **her** rolü kaçırırdı. İkisi
   birleştirildi.
3. **İki komut olmayan bir komuta yönlendiriyordu.** `user purge` ve
   `user allow-bind` çıktıları "`postern log`"u işaret ediyordu; öyle bir
   komut yok. Metinler panelin Admin log'unu gösterecek şekilde
   düzeltildi. (`postern log` eklemek ayrı bir iş — aşağıda S7.)

**Dürüstlük kararları:** verilmemiş bir rolü almak "revoked" değil
"held no active grant" diyor; dizinden gelen bir rolü almak, bir sonraki
girişte geri geleceğini söylüyor; silinmiş hesaba rol vermek
**reddedilmiyor** ("önce rolleri ver, sonra hesabı aç" meşru bir sıra) ama
hesabın giremediği yazılıyor.

**Süreli atama (`--until`) YAPILMADI.** `expires_at` şemada var ve erişim
kararı veren iki sorgu da onu uyguluyor — ama hiçbir yerden okunamıyor
(`model.Role` süre taşımıyor, `user list` gösteremiyor) ve `AssignRole`'un
`ON CONFLICT` dalı bayraksız ikinci bir atamada süreyi **sessizce
siliyor**. Yazması olup okuması olmayan bir alan, erişimin kimsenin
bakamayacağı bir saatte kaybolması demek. Eklenecekse okuma yoluyla
birlikte eklenmeli.

### B7 — Kayıtlar yalnızca bastion'ın diskindeydi ✅ 2 Eylül'de kapatıldı

Denetim izi, denetlenen makinede duruyordu. Bastion'ı ele geçiren
kayıtları da ele geçiriyordu; diskten uzun bir saklama yükümlülüğünün
cevabı yoktu; yedek tamamen operatördeydi.

**Aktarım kararı: elle yazılmış SigV4 + `net/http`.** Gerekçeyi ölçerek
verdim:

- AWS'nin kendi `aws4_testsuite` vektörleri (`get-vanilla`,
  `get-vanilla-query-order-key-case`) standart kütüphaneyle geçiyor —
  yani "doğru sanıyorum" değil, **bağımsız olarak doğrulanabilir**.
  Depo TOTP'yi RFC vektörlerine, QR'ı referans kodlayıcıya, SFTP
  çözücüsünü protokol belgesine karşı zaten böyle yazıyor.
- Tek PUT yetiyor: **ölçüldü**, 140 KB ham terminal çıktısı 155 KB
  `.cast` üretiyor. 5 GB sınırına ulaşmak için bir oturumun 5 GB
  basması gerek. Multipart yazmak, kullanılmayan bir kod yolunu bakım
  yüküne çevirmek olurdu — ama sınır aşıldığında dosya yerel kalıyor ve
  sebebi yazılıyor.
- SDK ~18 modül getiriyordu; depoda 12 doğrudan bağımlılık var.
- Yan fayda: MinIO, Ceph, R2, Backblaze — hepsi çalışıyor, satıcı
  bağımlılığı yok.

**Yapısal güvence: ağ, oturum yoluna hiç dokunmuyor.** Yükleyici
`proxy.Deps`'in üyesi DEĞİL — `proxy.Open` ona ulaşamıyor, dolayısıyla
ondan zarar da göremiyor. Oturum yolunun yükleme ile tek teması,
kapanışta yazılan bir veritabanı satırı.

**Sıra: yükle → deponun kendisine sor → damgala → silmeye izin ver.**
PUT'un 200 dönmesi kanıt değil; `archived_at` ancak HEAD ile
doğrulandıktan sonra yazılıyor ve budayıcıya silme iznini yalnızca o
damga veriyor.

**Budayıcının kapısı varsayılan reddetme.** Sorgu hata verirse koşu
hiçbir şey silmeden iptal ediliyor — bu dosyadaki diğer hata
davranışlarının tersi ve fark bilinçli: orada bedel bir oturumun
reddedilmemesi, burada bedel kanıtın yok olması.

**Dürüst bedel:** arşivlenmemiş kayıt asla budanmıyor, yani uzun bir
kesinti diski dolduruyor ve `min_free` oturumları reddetmeye başlıyor.
Doğru davranış bu; budayıcı her koşuda kaç dosyanın tutulduğunu ve kaç
bayt biriktiğini yazıyor, arşivleyici de bekleyenin **yaşını** —
ölmüş bir yükleyicinin belirtisi sayının artması değil, en eskisinin
yaşlanması.

**1.0'da yazma-yalnız.** Panel arşivlenmiş kaydın kova ve anahtarını
gösteriyor, indirmiyor: bastion'a bir okuma kimliği koymak, tek bir ele
geçirmeyi bütün arşivin dışarı çıkarılmasına çevirirdi.

⚠️ **`PutObject`, `DeleteObject` olmadan "append-only" DEĞİL** — var
olan bir anahtara PUT üzerine yazıyor. Gerçek koruma kovadan geliyor:
sürümleme, compliance kipinde Object Lock ve varsayılan saklama süresi.
postern **Object Lock başlığı göndermiyor**, çünkü kimliği ele geçiren
saklama süresini sıfır da yapabilirdi. Ve bunların hiçbirini
doğrulayamıyor — doğrulayamadığı bir korumayı da iddia etmiyor.

**Çalıştırarak bulunan iki şey:**

1. **Koşulsuz SSE, KMS'siz MinIO'da 501 veriyor.** İlk hâli
   `x-amz-server-side-encryption: AES256`'yı her istekte gönderiyordu;
   şirket içi kurulumların çoğunda hiçbir kayıt yüklenemezdi. Üstelik
   bastion'ı ele geçiren yükleme kimliğini de aldığı için o başlığın o
   saldırgana karşı faydası yok. Artık ayarlanabilir, varsayılan kapalı.
2. **S3 hata gövdesi sır taşıyabiliyor.** İlk hâli gövdeden 512 bayt
   alıp hataya koyuyordu ve yorumu "sır taşımıyor" diyordu — yanlış:
   AWS'nin `SignatureDoesNotMatch` cevabı `<AWSAccessKeyId>`,
   `<StringToSign>` ve `<CanonicalRequest>` içeriyor ve o metin log'a
   gidiyordu. Artık yalnızca `<Code>` alınıyor; çözülemezse "kod
   okunamadı" deniyor, "kod yok" değil.

**Yan çıkan iki eski sorun** (aynı sette kapandı, çünkü kapıyı güvensiz
kılıyorlardı):

- **`proxy.Open` yetim `.cast` bırakıyordu.** `NewWriter` ya da
  `StartSession` başarısız olduğunda diskte yalnızca başlık içeren ve
  hiçbir oturuma ait olmayan bir dosya kalıyordu. Budayıcının yeni
  kapısı varsayılan reddettiği için bunlar sonsuza dek tutulup diski
  doldururdu.
- **Budama denetim defterine hiç yazmıyordu**, oysa panel kayıp bir
  kayıt için "admin log hangisi olduğunu söyler" diyordu. Artık
  `recording.prune` satırı yazılıyor.

**Kanıt:** `TestArchivedRecordingSurvivesLocalDeletion` gerçek bir
MinIO'ya yüklüyor, **yerel kayıt dizinini tamamen siliyor** ve aynı
baytların depodan geri geldiğini gösteriyor. Bir veritabanı bayrağını
kontrol eden test, hiçbir şey yüklemeyen bir uygulamayı da geçirirdi.

Mutasyonlar: budayıcı kapısını kaldırınca "arşivlenmemiş kayıt silindi"
diye düşüyor; kapı cevap veremezken hiçbir şey silinmiyor. Ve bir
mutasyon **test yazdırdı**: HEAD doğrulamasını kaldırdım, hiçbir test
düşmedi — çünkü hepsinde PUT gerçekten başarılıydı. Doğrulama adımı
korumasızdı; PUT'a 200, HEAD'e 404 diyen bir depoyla o boşluk kapatıldı.

### B8 — Arşiv görünürlüğü ve panelden kimlik ✅ 2 Eylül'de kapatıldı

İki iş, sırayla.

**1. Görünürlük.** `record.Usage` yazılmıştı, testi vardı ve hiçbir
yerden çağrılmıyordu. Arşivleme onu taşıyıcı hâle getirdi: yüklenemeyen
kayıt budanmıyor, yani sıkışma yalnızca log'da görünüyorsa disk sessizce
doluyor ve operatör bir gün "oturumlar reddediliyor" diye uyanıyor.

`GET /api/admin/storage` ve Overview'da iki kart: diskteki kayıtların
boyutu ve **bekleyen arşiv işinin en eskisinin yaşı**. Yaş, sayıdan
önemli — ölmüş bir yükleyicinin belirtisi sayının artması değil; sabit
bir sayı da hiçbir şeyin ilerlemediği anlamına gelebilir.

⚠️ **Ölçülemeyen değer sıfır diye gösterilmiyor.** Dizini okuyamayan bir
kurulumu "0 dosya" diye göstermek, her şeyin yolunda olduğunu söylemek
olurdu; kart sebebi yazıyor.

**2. Panelden kimlik — ama hedef değil.**

Kapsamı bilerek dar tuttuk. `federation.go`'daki yorum kapatılan
saldırıyı zaten adıyla anıyor: panel admini `ldap.url`'i kendi
sunucusuna çevirip saklanan parolayı alıyordu. S3'te aynı yol var, üstüne
bir fazlası daha: saldırgan kendi kovasını gösterip **taze** bir kimlik
girdiğinde postern bundan sonraki her oturum kaydını ona yükler. Bu,
"hedef değişirse sırrı düşür" ile kapanmıyor — hedefi seçebilmenin
kendisinden geliyor. Panelden `is_admin` verilmemesiyle aynı raf.

Yani: **anahtar panelden, hedef config'ten.** Anahtar döndürmek rutin
bir iş; hedefi taşımak bir kurulum kararı.

- **Kendi ucu var, genel ayarlar yolu değil.** Oradaki sınıflandırma
  fail-open: haritada olmayan anahtar sessizce "sır değil" sayılıp düz
  metin saklanıyor. Bir test artık arşiv anahtarlarının o yola
  eklenmesini engelliyor.
- **Host'tan geliyorsa panel reddediyor**, sessizce yok saymıyor.
  Kaydedilip yürürlüğe girmeyen bir ayar, bu depodaki en tanıdık arıza.
- **Sır hiç geri okunmuyor**, maskeli hâli bile.
- **Yeniden başlatma gerekmiyor:** arşivleyici kimliği her turda
  çözüyor. Açılışta bir kez okusaydı, panel "kaydedildi" der ve hiçbir
  şey olmazdı.

**Bir mutasyon yine test yazdırdı:** sunucudaki "host anahtarı
gölgelenemez" reddini kaldırdım ve panel testleri geçmeye devam etti —
koruma yalnızca arayüzdeydi. Bu deponun kendi kuralı ("koruma burada,
arayüzde değil") ihlal ediliyordu; sunucu tarafına üç test eklendi.

### B9 — `postern archive check` ✅ 2 Eylül'de kapatıldı

Kovanın sertleştirilip sertleştirilmediğini operatör hiçbir yerden
göremiyordu — ve postern'in kendisi de bunu doğrulayamadığını
söylemiyordu.

**Üç sütun**, ve üçüncüsü raporun asıl yarısı:

1. **Kova ne söyledi** — sürümleme, Object Lock (kip + varsayılan
   saklama), varsayılan şifreleme.
2. **Öğrenilemedi** — okuma yetkisi olmayan alanlar, kodu ve sebebiyle.
   "Yetkim yok" ile "kapalı" AYRI: ikincisini birincisi diye göstermek,
   var olan bir korumayı yok sandırırdı.
3. **postern asla öğrenemez** — silme yetkisi, kovaya erişen başka
   kimlikler, yarın değişecek bir politika, saklama süresinin yeterli
   olup olmadığı, ve en önemlisi: *bu cevapların hepsi bu makinedeki bir
   kimlikten geldi; makineyi ele geçiren aynı cevapları alır.*

**Silme yetkisi bilerek test EDİLMİYOR.** Kesin öğrenmenin tek yolu bir
nesne yazıp silmeyi denemek olurdu; bu, `objstore`'a silme yeteneği
eklemeyi gerektirirdi ve paketin kendi gerekçesini bozardı ("yeteneğin
olmaması, kimliğe o yetkinin verilmemesi gerektiğini kodda da
söylüyor"). Zaten gerekmiyor: **compliance kipinde Object Lock varsa
nesne IAM'den bağımsız olarak silinemiyor**, yani asıl bilinmesi gereken
kilidin durumu ve rapor onu veriyor.

**Çıkış kodu ayrımı:** yalnızca kova ŞU AN kullanılamıyorsa sıfır
olmayan (ulaşılamıyor, kimlik reddedildi, kova yok). Zayıf sertleştirme
uyarı — operatörün bilerek yaptığı bir tercih olabilir.

**Ölçerek bulunan bir hata:** `isNotConfigured` "NoSuch" alt dizesine
bakıyordu, dolayısıyla **olmayan bir kova** (`NoSuchBucket`) "sürümleme
yapılandırılmamış" diye raporlanıyor, rapor yeşil çıkıyor ve sıfırla
bitiyordu — oysa hiçbir kayıt yüklenemez. Raporun en tehlikeli hâli tam
olarak buydu.

**Ve bir mutasyon yine test yazdırdı:** "asla öğrenemez" bölümünü
*çağıran* satırı sildim, hiçbir test düşmedi — fonksiyonu ölçüyordum,
kablolamayı değil. Bölüm sessizce düşseydi rapor "kontrol ettim,
güvendeyim" diye okunur hâle gelirdi. Komutun gerçek çıktısını ölçen iki
test eklendi.

### B10 — Sağlık ucu yok ✅ 2 Eylül'de kapatıldı

Vekil, systemd ya da bir izleme sistemi "ayakta mı" diye soramıyordu;
TCP bağlantısının kurulması PostgreSQL'in yaşadığı anlamına gelmiyor.

**İki uç, ve bölünme bir güvenlik kararı** — endişemi tasarımla
çözdüm. İkisi de kimlik istemiyor (bir sağlık kontrolünün amacı zaten
o), dolayısıyla:

- `/healthz` **hiçbir şeye dokunmuyor**. Süreç ayakta mı, o kadar.
- `/readyz` veritabanına bakıyor ama cevabı **bir saniye
  önbellekleniyor** ve eşzamanlı istekler tek yoklamaya iniyor.
  Önbellek hız için değil: kimliksiz bir isteği veritabanı yüküne
  çevirmenin azami hızını bağlıyor.

**`/readyz` sebebi söylemiyor.** Veritabanı hata metni DSN parçası ya da
iç ana makine adı taşıyabiliyor; ayrıntı log'a gidiyor.

**Kurulum durumuna bakmıyorlar.** Kurulmamış bir bastion da ayakta; ilk
açılışta 503 dönmek, systemd'nin ve vekilin daha kimse kurulumu
bitirmeden servisi ölü sanmasına yol açardı.

**Canlı ölçüm:** veritabanını durdurdum — `/healthz` 200 kaldı,
`/readyz` 503 verdi, veritabanı geri gelince kendiliğinden 200'e döndü.

Üç mutasyon: önbelleği kaldırınca "50 istek 50 yoklama üretti" diye
düşüyor; hata sebebini gövdeye yazınca "iç ayrıntı sızdı" diyor;
`/healthz`'i veritabanına bağlayınca test panikle düşüyor (sahte
sunucuda depo yok — dokunmadığının kanıtı).

### B11 — Denetimin okuma yarısı CLI'da yoktu ✅ 2 Eylül'de kapatıldı

`admin_log`'a hem panel hem CLI yazıyordu ama host'tan okunamıyordu —
yani panelin çalışmadığı gün yapılan değişikliklerin izi yine
panelden okunuyordu. `store.AdminLog` vardı, çağıranı yalnızca panel.

```
postern log --limit 50
postern log --actor yigit
postern log --action session.
postern log --entity web-01
```

**En sinsi tuzak ve nasıl kapatıldı:** süzme istemcide yapılıyor
(store'da süzgeçli okuma yok). Limiti olduğu gibi kullansaydım,
`--actor yigit --limit 5` **son 5 satırdan** yigit'e ait olanları
gösterirdi — yani çoğu zaman boş çıkar ve operatör "hiç yapmamış" diye
okurdu. Süzgeç varken daha geniş okunuyor.

**İki şeyi bulanıklaştırmayı reddediyor:**

- **"Defter boş" ile "aradığın yok" ayrı cümleler.** İkincisini
  birincisi diye okumak, hiç kayıt tutulmadığını sanmaya yol açardı —
  bir denetim aracında en pahalı yanlış anlama.
- **Kesildiyse söylüyor.** Sessizce ilk N'i göstermek, "hepsi bu"
  sandırırdı.

**Bir pürüz canlı denemede çıktı:** eşleşme yokken tablo başlığı yine
basılıyordu. Boşluğun üstünde tek başına duran bir başlık "burada veri
var" demek; artık başlık ilk satırla birlikte yazılıyor.

Ve `user purge` ile `user allow-bind` çıktıları artık gerçekten var
olan bir komuta yönlendiriyor — B6'da panelin Admin log'una çevirmiştim.

### B12 — `Broker.Run` ölü hata dalları ✅ 2 Eylül'de kapatıldı

`Run` koşulsuz `nil` dönüyordu, yani `sshd/channel.go` ve
`httpapi/terminal.go`'daki `if err := sess.Run(...); err != nil` dalları
**hiçbir koşulda çalışmıyordu**. Bu, deponun tekrar eden sınıfının
tersi: yazılmış ve hiç tetiklenemeyen bir hata yolu.

Ve kaybolan sinyal gerçekti: SFTP çözücüsü akışı anlayamadığında oturumu
**kasten** kapatıyoruz (`abortAudit`) ve bu, "kullanıcı çıktı" ile
karıştırılmaması gereken bir bitiş. Artık sebep saklanıyor ve `Run` onu
döndürüyor.

Kapatma hataları döndürülmüyor: karşı taraf çoktan gitmiş olabilir ve o
gürültü asıl sinyali gömerdi.

⚠️ Yazarken bir veri yarışı çıktı: `abortErr` başka goroutine'den
yazılıyor ve `Run` her çıkış yolunda okuyordu. Yalnızca kanalın
kapandığı **görüldükten sonra** okunuyor — kapalı kanaldan alma,
close'dan önceki yazmayı görünür kılıyor.

### B13 — Cevap vermeyen istemcinin tuttuğu goroutine'ler ✅ ölçüldü, sınırı yazıldı

`Run`'ın beş goroutine'inden ikisi WaitGroup dışında ve bu **bilinçli**:
ikisi de istemciden okuyor, beklemeye alsaydık hiçbir şey yazmayan bir
istemci oturumun hiç bitmemesi demek olurdu.

**Bedeli ölçüldü.** x/crypto kaynağına bakıldı: `channel.Close()`
yalnızca `channelCloseMsg` **gönderiyor**; okuyucuyu serbest bırakan
`ch.close()` ancak karşı taraftan close **alındığında** çalışıyor. Yani
o ikisi, istemci cevap verene ya da TCP ölene kadar yaşıyor.

Sınırsız değil: bağlantı başına en fazla `max_channels_per_conn`,
toplamda `max_conns` ile çarpımı kadar. Düzeltmek ürünün en kritik veri
yolunu yeniden kurmayı gerektirirdi; **sınırı ölçüp yazmak** doğru
karşılık.

⚠️ **Bu arada koşumda bir yalan bulundu:** `fakeChannel.Close()`
okumada bekleyenleri uyandırıyor ve yorumu "gerçek kanal gibi" diyordu —
değil. Koşum gerçeklikten daha bağışlayıcı olduğu için mevcut testlerin
hiçbiri bu sınıfı göremiyordu. Yorum düzeltildi ve gerçeği taklit eden
`deafChannel` eklendi.

### B14 — Kayıtların bütünlük mührü: yazıldı, yapılmadı ✅

Kod değil, bir karar ve gerekçesi. Kayıt, olanın **kanıtı**; sonradan
değiştirilmediğinin **mührü** değil. Hash zinciri yok, imza yok.

Bilinçli: dosyalar `0600` ve servis kullanıcısının; onları yeniden
yazabilen zaten bastion'a sahip, ve postern'in aynı makinede hesaplayıp
sakladığı bir zinciri o saldırgan da yeniden hesaplar. Dikkatsiz bir
operatörü yakalardı, hasmı değil — ve garanti gibi okunurdu.

Arşivleme bunun **şeklini** değiştiriyor, gerekçesini değil: yüklemeyle
giden sağlama bir bozulma kontrolü, dürüstlük kanıtı değil. Arşivi
bastion'ı ele geçirene karşı koruyan şey kova: sürümleme ve compliance
kipinde Object Lock. `postern archive check` bunları raporluyor ve
doğrulayamadığını da söylüyor.

---

## Kapatılmayan eksikler

Kalmadı — onayladığın sıranın sekiz maddesi de kapandı.

Bu, "her şey bitti" demek değil: aşağıdaki **yapılmaması gerekenler**
listesi hâlâ geçerli ve `postern archive check`'in "asla öğrenemez"
sütunu, ürünün doğrulayamadığı şeylerin listesi olarak duruyor.


## Belgelerde düzelttiklerim (kod değil)

- `discover` örneklerinde sırrı komut satırında gösteriyordum. `ps` bunu
  herkese açar. `POSTERN_PROXMOX_TOKEN_SECRET` ve
  `POSTERN_VSPHERE_PASSWORD` zaten destekleniyor — belgeler artık onları
  kullanıyor.
- `terminal_enabled`'ın **varsayılan kapalı** olduğunu ve neden öyle
  olduğunu (paneldeki bir XSS'in hedefte komut çalıştırmaya dönüşmesi)
  yazmıyordum. Yazıldı.
- CLI örneklerinin çoğu uydurma bayrak kullanıyordu. Hepsi gerçek yüzeyle
  karşılaştırılıp düzeltildi.

---

## 1.0'da YAPILMAMASI gerekenler

Bunlara bakıp geçtim; her biri savunulabilir ama hiçbiri bu sürümde
değil.

| Fikir | Neden şimdi değil |
|---|---|
| Kayıt hash zinciri | Yukarıda: gerçek saldırganı yakalamıyor |
| WebAuthn | TOTP zaten var ve iş görüyor; ikinci bir faktör mekanizması yeni yüzey |
| Kümeleme / çok düğüm | Tek düğüm bilinçli sınır; paylaşılan durum bambaşka bir proje |
| Metrik / Prometheus | `admin_log` ve `session list` var; asıl eksik `/healthz` |
| SSH şifreleyici listesi ayarı | Go'nun varsayılanları makul; ayar yapılabilir olması yanlış ayarlanabilir olması demek |
| Panelden `is_admin` verme | Bilinçli olarak reddedildi, öyle kalmalı |

---

## Nerede kaldık

Onayladığın sekiz maddenin sekizi de kapandı:

| | |
|---|---|
| ~~Arşiv/disk görünürlüğü~~ | ✅ B8 |
| ~~Panelden S3 kimliği~~ | ✅ B8 |
| ~~`postern archive check`~~ | ✅ B9 |
| ~~`/healthz`~~ | ✅ B10 |
| ~~`postern log`~~ | ✅ B11 |
| ~~Ölü hata dalları~~ | ✅ B12 |
| ~~Goroutine sızıntısı~~ | ✅ B13 (ölçüldü, sınırı yazıldı) |
| ~~Bütünlük mührü~~ | ✅ B14 (yapılmadı, gerekçesi yazıldı) |

Toplamda on dört madde kapandı; hepsi `make ci` yeşilken commit edildi
ve mutasyon testinden geçti — **B13 ve B14 hariç**, ki onlar zaten kod
değişikliği değil: biri ölçüm ve gerekçe, diğeri bir karar.


## Yöntem notu

Bu gecenin üç bulgusu da **kodu okuyarak değil, çalıştırarak** çıktı:
silinen hesap gerçekten kabuk açtı, Entra deseni gerçekten elendi, SFTP
rename gerçekten kayboldu. Kod okuması üçünü de "var, yazılmış"
gösteriyordu — çünkü hepsi yazılmıştı. Bağlı değillerdi.

Bu, projede tekrar eden desen: *yazıldı, test edildi, çağrılmıyor*.
Bir sonraki gözden geçirmede aranacak ilk şey, ölü güvenlik yardımcıları
olsun — `grep`'le çağrısız kalan bir doğrulayıcı, neredeyse her zaman
kapalı sanılan açık bir kapıdır.
