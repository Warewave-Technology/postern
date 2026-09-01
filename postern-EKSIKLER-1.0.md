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

## Bu gece bulunan ve DÜZELTİLEN dört şey

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

---

## Kapatılmayan eksikler

### S2 — Yönetici canlı bir oturumu sonlandıramıyor

**Ciddiyet: orta. Sömürülebilir bir açık değil; olay anında eksik bir
yetenek.**

Panel canlı oturumları **listeliyor** ([Overview.tsx:221](web/src/admin/Overview.tsx:221))
ama kesecek bir düğme yok, API'de de karşılığı yok (arandı: `Terminate`,
`Kill`, `Disconnect` — hiçbiri yok).

Roller bağlanma anında çözülüyor; bu iyi bir karar ama **açık bir oturumu
etkilemiyor.** Hesabı ele geçirilmiş birinin oturumu, erişimini iptal
ettikten sonra da `idle_timeout` ya da `max_lifetime` dolana kadar sürüyor.

Bir bastion için "şu an kes" çekirdek işlem. Kayıt tutup kesememek,
olaydan sonra ne olduğunu izleyip o sırada seyretmek demek.

**En küçük düzeltme:** canlı oturumları session id ile tutan bir kayıt
defteri, `DELETE /api/admin/sessions/{id}`, ve panelde bir düğme. Kesme
`admin_log`'a aktörüyle yazılmalı.

---

### S3 — Sağlık ucu yok

**Ciddiyet: düşük, tamamen operasyonel.**

`/healthz` yok. Vekil, systemd ya da bir izleme sistemi "ayakta mı"yı
soramıyor; TCP bağlantısı kurulması PostgreSQL'in yaşadığı anlamına gelmiyor.

**En küçük düzeltme:** kimlik istemeyen `GET /healthz`, DB ping'i yapıp
200/503 dönen. On satır.

---

### S4 — CLI, var olan bir kullanıcıya rol veremiyor

**Ciddiyet: orta. Acil çıkış yolunun eksik yarısı.**

`postern user add --role ...` yeni hesaba rol veriyor. Var olan bir
hesaba rol **eklemenin** ya da rolünü **almanın** CLI karşılığı yok:
`user modify` yalnızca e-posta, os-user, admin ve sso-only değiştiriyor;
`role` altında yalnızca `add` var.

Bu, panelde durduğu için normalde sorun değil. Sorun, CLI'ın tam olarak
**panelin çalışmadığı an** için var olması: kilitlendiğinde ya da IdP
düştüğünde host'a giriyorsun ve orada birine erişim veremiyorsun. Bu
gece demoyu kurarken de aynı duvara toslandı; çare, kullanıcının zaten
sahip olduğu role hedef eklemek oldu — doğru çözüm değil, dolambaç.

**En küçük düzeltme:** `postern user grant --name X --role Y` ve
`postern user revoke --name X --role Y`. Store'da `AssignRole` /
`RemoveRole` zaten var; eksik olan yalnızca komut. `admin_log`'a
aktörüyle yazılmalı.

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
| S3'e kayıt atma | Disk + `retain` yetiyor; bulut bağımlılığı 1.0'ın kapsamı değil |
| Metrik / Prometheus | `admin_log` ve `session list` var; asıl eksik `/healthz` |
| SSH şifreleyici listesi ayarı | Go'nun varsayılanları makul; ayar yapılabilir olması yanlış ayarlanabilir olması demek |
| Panelden `is_admin` verme | Bilinçli olarak reddedildi, öyle kalmalı |

---

## Önerim

Bu gece **B1–B4** kapandı; dördü de testli ve mutasyon testinden geçti.
Kalanlar için önerdiğim sıra:

1. **S2** — bir bastion'da "şu an kes" düğmesinin olmaması tuhaf. Kod
   olarak en büyüğü ve tek başına bir oturum işi.
2. **S4** — CLI'ın acil çıkış yolu yarım; iki komut, yarım saat.
3. **S3** — on satır. Ama kimliksiz bir uç yeni bir yüzey ve DB'ye
   dokunuyor; bunu bilerek senin kararına bıraktım.
4. **S5** — kod değil, bir cümle: "bilinen sınırlar"a yazılır.

Hiçbiri 1.0'ı bekletmez bence. **S2** ilk noktalama sürümünde olmalı:
kaydı tutup kesememek, olayı seyretmek demek.

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
