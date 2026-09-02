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

## Bulunan ve DÜZELTİLEN altı şey

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

---

## Kapatılmayan eksikler


### S3 — Sağlık ucu yok

**Ciddiyet: düşük, tamamen operasyonel.**

`/healthz` yok. Vekil, systemd ya da bir izleme sistemi "ayakta mı"yı
soramıyor; TCP bağlantısı kurulması PostgreSQL'in yaşadığı anlamına gelmiyor.

**En küçük düzeltme:** kimlik istemeyen `GET /healthz`, DB ping'i yapıp
200/503 dönen. On satır.

---



### S7 — Denetim kaydının OKUMA yolu CLI'da yok

**Ciddiyet: düşük–orta.**

`admin_log`'a CLI de panel de yazıyor ama CLI'dan okunamıyor:
`store.AdminLog` var, çağıranı yalnızca panel. Yani panelin çalışmadığı
gün yapılan değişikliklerin izi, yine panelden okunabiliyor.

**En küçük düzeltme:** `postern log [--limit N]`. ~30 satır ve yazma
tarafı zaten duruyor.

### S6 — Kayıtlar nesne depolamaya gönderilemiyor

**Ciddiyet: orta. 1.0 kapsamına ALINDI (2 Eylül kararı).**

⚠️ **Bu maddede fikrimi değiştirdim ve sebebi kendi analizim değil.**
Raporun ilk hâlinde bunu "1.0'da yapılmamalı" listesine koymuştum;
gerekçem *"disk + `retain` yetiyor, bulut bağımlılığı kapsam değil"*di.
O gerekçe eksikti ve nedenini yazıyorum ki karar sonradan okunabilsin.

Bugün kayıtlar yalnızca bastion'ın diskinde. Bunun üç sonucu var ve
üçü de projenin kendi duruşuyla çelişiyor:

1. **Denetim izi, denetlenen makineyle aynı yerde duruyor.** Bastion'ı
   ele geçiren biri kayıtları da ele geçiriyor. "Kayıt açılamazsa oturum
   reddedilir" diyen bir tasarımın, o kaydı saldırganın erişebildiği tek
   diskte bırakması tutarsız.
2. **Saklama süresi diske bağlı.** `retain: 90d` ile `min_free: 5GB`
   çarpışınca kaybeden saklama süresi oluyor: disk dolduğunda oturumlar
   reddedilmeye başlıyor (doğru davranış) ama operatörün seçeneği
   kaydı kısaltmak. Yasal saklama yükümlülüğü olan bir kurulumda bu
   yeterli değil.
3. **Yedek alma operatörün elle çözdüğü bir problem.** Belgelerde
   "kayıtları da yedekle" yazıyoruz ve orada bırakıyoruz.

Kullanıcının kararı: **1.0 özelliği.**

**Yapılırken dikkat edilecekler** (analiz değil, şimdiden görünen
tuzaklar):

- **Kayıt yazma yolu ASLA ağa bağlanmamalı.** Bugün "kayıt açılamazsa
  oturum reddedilir" kuralı yerel bir dosya açmaya bakıyor. Aynı kuralı
  bir S3 PUT'una bağlamak, ağ arızasını oturum reddine çevirirdi —
  yani bastion'ı bulut sağlayıcısının uptime'ına zincirlemek. Doğru
  şekil: yerele yaz, **sonra** yükle.
- **Yükleme başarısızlığı sessiz kalmamalı.** Yüklenemeyen kayıt,
  silinmemiş ama korunmamış bir kayıttır; ikisi ayrı durum ve
  operatörün ayırt edebilmesi gerekir.
- **Budayıcı, yüklenmemiş kaydı silmemeli.** `retain` süresi dolan ama
  henüz yüklenememiş bir dosyayı silmek, denetim izini sessizce yok
  etmek olur.
- **Sırlar `secret_key_file` ile mühürlenmeli**, config'de düz metin
  anahtar durmamalı — LDAP/OIDC kimlik bilgileri için kurulan düzenin
  aynısı.
- **Sunucu tarafı şifreleme yetmez.** Bastion'ı ele geçiren, yükleme
  kimlik bilgisini de ele geçirir; silme yetkisi olmayan bir kimlik
  (append-only / object lock) bunun tek gerçek cevabı.

Kapsam kararı verirken tekrar bakılacak: yalnızca S3 uyumlu API mi,
yoksa `rclone`/`aws s3 cp` çağıran genel bir "arşiv komutu" mu — ikincisi
kod olarak neredeyse yok ve her sağlayıcıyı destekler.

**Koda bakıp çıkardığım iki somut nokta** (tasarımı doğrudan etkiler):

- **Budayıcı bugün yalnızca yaşa bakıyor.** `record.Prune(dir, keepFor,
  now)` dosyaları tarihe göre siliyor ve "bu yüklendi mi" diye
  soramıyor — sorabileceği bir yer de yok. Yükleme eklenirse budayıcının
  yüklenme durumunu okuyabilmesi gerekir, yoksa `retain` süresi dolan ama
  henüz yüklenememiş bir kayıt sessizce yok olur. En küçük hâli: yüklenen
  dosyanın yanına bir işaret dosyası ya da `sessions` tablosunda bir
  sütun.
- **`min_free` yükü kaydırmaz, oturumu reddeder.** `record.CheckSpace`
  eşiğin altında `ErrDiskLow` dönüyor ve `proxy.Open` oturumu reddediyor.
  Yükleme, diski boşaltmanın yolu olacaksa budama ile yükleme arasındaki
  sıra bir tasarım kararı: "yüklendi, artık silinebilir" ile "silindi,
  yüklenememişti" arasındaki fark bu sıradan çıkıyor.

### S5 — Kayıtların bütünlük mührü yok

**Ciddiyet: düşük — ve 1.0'da kapatılmasını ÖNERMİYORUM.**

Kayıtlar düz asciicast dosyaları. Dosyaya yazma yetkisi olan biri geçmişe
dönük değiştirebilir ve bunu fark eden bir şey yok.

Neden yine de kapatılmasını önermiyorum: dosyalar `0600` ve servis
kullanıcısının; o yetkiye sahip olan zaten bastion'ın kendisine sahip. Hash
zinciri gerçek bir saldırganı değil, yalnızca dikkatsiz bir operatörü
yakalardı. **Bunu bir "bilinen sınır" olarak yazmak doğru cevap**, kod
yazmak değil.

---

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

## Önerim

**B1–B6** kapandı; altısı da testli ve mutasyon testinden geçti.
Kalanlar için önerdiğim sıra:

1. **S6** — kayıtların nesne depolamaya gönderilmesi. 1.0 kapsamına
   alındı; en büyüğü ve tasarım kararı gerektiren tek madde.
2. **S7** — `postern log`; ~30 satır, denetimin okuma yarısı.
3. **S3** — on satır. Ama kimliksiz bir uç yeni bir yüzey ve DB'ye
   dokunuyor; bunu bilerek senin kararına bıraktım.
4. **S5** — kod değil, bir cümle: "bilinen sınırlar"a yazılır.

---

## Yöntem notu

Bu gecenin üç bulgusu da **kodu okuyarak değil, çalıştırarak** çıktı:
silinen hesap gerçekten kabuk açtı, Entra deseni gerçekten elendi, SFTP
rename gerçekten kayboldu. Kod okuması üçünü de "var, yazılmış"
gösteriyordu — çünkü hepsi yazılmıştı. Bağlı değillerdi.

Bu, projede tekrar eden desen: *yazıldı, test edildi, çağrılmıyor*.
Bir sonraki gözden geçirmede aranacak ilk şey, ölü güvenlik yardımcıları
olsun — `grep`'le çağrısız kalan bir doğrulayıcı, neredeyse her zaman
kapalı sanılan açık bir kapıdır.
