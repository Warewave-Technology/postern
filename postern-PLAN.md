# postern — Uygulama Planı

> *Postern: kale duvarındaki küçük, kontrollü yan kapı. Ana kapı değil —
> az sayıda kişinin, denetimli geçtiği yer.*

Sertifika tabanlı, OIDC kimlik doğrulamalı, oturum kaydeden SSH bastion.
"Çok sade Teleport" — tek protokol, tek node, tek binary.

**Lisans:** Apache-2.0 · **Dil:** Go · **Repo:** `github.com/warewave/postern`

---

## İçindekiler

- [0. Çalışma şekli](#0-çalışma-şekli)
- [1. Kapsam](#1-kapsam)
- [2. Teknoloji kararları](#2-teknoloji-kararları)
- [3. Repo yapısı](#3-repo-yapısı)
- [S1 — SSH proxy çekirdeği](#s1--ssh-proxy-çekirdeği-3-hafta)
- [S2 — Sertifika modeli](#s2--sertifika-modeli-3-hafta)
- [S3 — OIDC, kalıcılık, RBAC](#s3--oidc-kalıcılık-rbac-4-hafta)
- [S4 — Web terminal](#s4--web-terminal-3-hafta)
- [S5 — Uç durumlar ve sertleştirme](#s5--uç-durumlar-ve-sertleştirme-4-hafta)
- [Ek A — Test stratejisi](#ek-a--test-stratejisi)
- [Ek B — Güvenlik incelemesi kontrol listesi](#ek-b--güvenlik-incelemesi-kontrol-listesi)
- [Ek C — SSH protokol notları](#ek-c--ssh-protokol-notları)

---

## 0. Çalışma şekli

**Bölüşüm:** Ben yapıyı, arayüzleri, test iskeletlerini ve protokol
açıklamalarını veriyorum. İmplementasyonu sen yazıyorsun. Takıldığın yerde
birlikte açıyoruz.

**İstisna — bunları bana yazdırma:**

- `internal/ca/sign.go` — sertifika imzalama
- `internal/sshd/auth.go` — gelen kimlik doğrulama
- `internal/policy/authorize.go` — yetki kararı

Bu üç dosyayı satır satır sen yaz, ben gözden geçireyim. Görmediğim kod
hakkında kendinden emin yanlış konuşabildiğimi bu projede zaten test ettik.

**Her aşamanın sonunda çalışan bir şey var.** Herhangi bir aşamada durup
"yeterince öğrendim" diyebilirsin.

**Süre tahminleri** yarı zamanlı, tek kişi varsayımıyla. Sıkı takvim değil,
sıralama aracı.

---

## 1. Kapsam

### Var

| | |
|---|---|
| SSH proxy | Gelen bağlantıyı hedefe iletir, akışı kaydeder |
| Sertifika tabanlı hedef auth | Kısa ömürlü, principal'lı, kişiye özel |
| OIDC girişi | Keycloak / herhangi bir OIDC sağlayıcı |
| asciicast kayıt | Aranabilir, küçük, oynatılabilir |
| Web terminal | xterm.js |
| RBAC | kullanıcı → rol → target |
| SFTP | subsystem relay |

### Yok (kalıcı non-goal)

RDP · VNC · MySQL/Postgres/K8s proxy · HA/cluster · komut ACL · JIT onay
akışı · credential vault · video kayıt · mobil UI · branding

### Neden bu kesim

Warpgate'in 5 protokolünden 1'ini yapıyoruz. Tek kişilik ölçekte tutan şey bu.
Kapsam kaymasının ilk işareti "bir de MySQL ekleyelim" cümlesidir.

---

## 2. Teknoloji kararları

| Katman | Seçim | Gerekçe |
|---|---|---|
| SSH | `golang.org/x/crypto/ssh` (ham) | ⬇️ aşağıya bak |
| SFTP | `github.com/pkg/sftp` | Subsystem relay için |
| OIDC | `coreos/go-oidc` + `x/oauth2` | Standart, olgun |
| TOTP | `pquerna/otp` | |
| DB | `github.com/jackc/pgx/v5` | PostgreSQL sürücüsü; S5.5’te `modernc.org/sqlite` yerine geçti |
| Migration | `pressly/goose` | Basit, embed edilebilir |
| Query | `sqlc` | Tip güvenli, kod üretimi |
| HTTP | `go-chi/chi` | İnce, stdlib uyumlu |
| WebSocket | `coder/websocket` | Bakımlı, context tabanlı |
| Log | `log/slog` | Stdlib, yapılandırılmış |
| Config | `goccy/go-yaml` | |
| CLI | `spf13/cobra` | kvmbackup/exhume ile tutarlı |
| Test | stdlib + `testcontainers-go` | Gerçek sshd'ye karşı test |

### Neden `gliderlabs/ssh` değil, ham `x/crypto/ssh`

`gliderlabs/ssh` daha hızlı başlatır ama tam olarak öğrenmek istediğin
katmanı gizler: channel açma, request relay, payload parse. Ayrıca gerçek
bir proxy'nin `direct-tcpip` ve `subsystem` kanallarını ham iletmesi gerekir;
gliderlabs'ın session soyutlaması buna dar gelir ve S5'te göç etmek zorunda
kalırsın.

Bedeli: S1 bir hafta daha uzun. Karşılığı: SSH protokolünü gerçekten
öğrenmen ve sonra rewrite yapmaman.

### Neden Go

Teleport'un kendisi Go ile yazılmış ve `x/crypto/ssh`'ın bir fork'unu
kullanıyor. Sertifika desteği (`ssh.Certificate`, `ssh.CertChecker`)
kütüphanede birinci sınıf. Proxy = iki yönlü akış + goroutine, Go'nun tam
şekli. Ve sen zaten Go biliyorsun — öğrenme eğrisi dilde değil, protokolde
olacak.

---

## 3. Repo yapısı

```
postern/
├── cmd/postern/
│   ├── main.go              # cobra kök komut
│   ├── serve.go             # postern serve
│   ├── ca.go                # postern ca init | ca show
│   ├── target.go            # postern target add | list  (S3)
│   └── user.go              # postern user add | list    (S3)
├── internal/
│   ├── config/
│   │   ├── config.go        # şema
│   │   └── load.go          # yükleme + doğrulama
│   ├── model/
│   │   ├── target.go
│   │   ├── user.go
│   │   ├── role.go
│   │   └── session.go
│   ├── ca/
│   │   ├── ca.go            # CA yaşam döngüsü, anahtar saklama
│   │   ├── sign.go          # ⚠️ SEN YAZ — sertifika imzalama
│   │   └── sign_test.go
│   ├── sshd/                # GELEN bağlantı (server tarafı)
│   │   ├── server.go        # listener, handshake
│   │   ├── auth.go          # ⚠️ SEN YAZ — kimlik doğrulama
│   │   ├── username.go      # "user:target@host" parse
│   │   ├── channel.go       # kanal kabul + yönlendirme
│   │   └── request.go       # pty-req, shell, exec, window-change parse
│   ├── upstream/            # GİDEN bağlantı (client tarafı)
│   │   ├── dial.go          # hedefe bağlan
│   │   ├── session.go       # kanal aç, request relay
│   │   └── hostkey.go       # hedef host key doğrulama
│   ├── proxy/
│   │   ├── broker.go        # gelen ↔ giden eşleştirme
│   │   ├── pipe.go          # iki yönlü kopyalama + tee
│   │   └── lifecycle.go     # oturum başlat/bitir
│   ├── record/
│   │   ├── asciicast.go     # v2 yazıcı
│   │   ├── asciicast_test.go
│   │   └── store.go         # dosya yerleşimi, rotasyon
│   ├── auth/                # (S3)
│   │   ├── oidc.go
│   │   ├── totp.go
│   │   └── session.go       # web oturum token'ları
│   ├── policy/
│   │   ├── authorize.go     # ⚠️ SEN YAZ — yetki kararı
│   │   └── authorize_test.go
│   ├── store/               # (S3)
│   │   ├── migrations/
│   │   ├── queries/
│   │   └── store.go
│   └── httpapi/             # (S3/S4)
│       ├── router.go
│       ├── admin.go
│       └── terminal.go      # WS ↔ SSH köprüsü
├── web/                     # (S4) xterm.js
├── deploy/
│   ├── systemd/
│   └── ansible/
├── testdata/
├── test/integration/
├── LICENSE
├── Makefile
└── README.md
```

---

# S1 — SSH proxy çekirdeği (3 hafta)

**Hedef:** Sabit config'den okunan bir hedefe, anahtar auth ile bağlanan,
oturumu asciicast olarak kaydeden çalışan bir proxy.

**Aşama sonu kanıtı:** `ssh yigit:web01@localhost -p 2222` çalışıyor, `vim`
açılıyor, terminal resize doğru çalışıyor, kayıt `asciinema play` ile
oynatılabiliyor.

---

## S1.1 — İskelet ve config

**Dosyalar:** `cmd/postern/main.go`, `cmd/postern/serve.go`,
`internal/config/config.go`, `internal/config/load.go`

**Sorumluluk:** YAML config yükle, doğrula, `serve` komutunu bağla.

```go
// internal/config/config.go
type Config struct {
    Listen    ListenConfig    `yaml:"listen"`
    HostKey   string          `yaml:"host_key"`
    Recording RecordingConfig `yaml:"recording"`
    Targets   []TargetConfig  `yaml:"targets"`   // S1: statik, S3'te DB'ye taşınır
    Users     []UserConfig    `yaml:"users"`     // S1: statik
}

type TargetConfig struct {
    Name     string `yaml:"name"`
    Host     string `yaml:"host"`
    Port     int    `yaml:"port"`
    User     string `yaml:"user"`
    KeyFile  string `yaml:"key_file"`
    HostKey  string `yaml:"host_key"`  // hedefin beklenen host key'i
}

func (c *Config) Validate() error  // eksik alan, çakışan isim, dosya var mı
```

**Hedef:** Bozuk config açıkça ve erken hata versin.

**Test:** `internal/config/load_test.go` — `testdata/` altında 5 config:
geçerli, eksik host_key, çakışan target adı, olmayan dosya yolu, bozuk YAML.
Her biri için beklenen hata.

**Bitti:** `postern serve --config testdata/valid.yaml` config'i yükleyip
"not implemented" ile çıkıyor.

---

## S1.2 — Host key ve listener

**Dosyalar:** `internal/sshd/server.go`, `cmd/postern/ca.go`

**Sorumluluk:** Host key üret/yükle, `ssh.ServerConfig` kur, TCP dinle,
handshake yap.

```go
// internal/sshd/server.go
type Server struct {
    cfg      *config.Config
    signer   ssh.Signer
    logger   *slog.Logger
}

func New(cfg *config.Config, logger *slog.Logger) (*Server, error)
func (s *Server) ListenAndServe(ctx context.Context) error
func (s *Server) handleConn(ctx context.Context, nConn net.Conn)
```

Kritik akış:

```go
sshConn, chans, reqs, err := ssh.NewServerConn(nConn, serverConfig)
// chans: gelen kanal istekleri
// reqs:  global istekler (keepalive vb.) — DiscardRequests ile başla
```

**Hedef:** SSH handshake tamamlanıyor, kanal açılmadan bağlantı kapanıyor.

**Test:** `test/integration/handshake_test.go` — `ssh.Dial` ile bağlan,
handshake başarılı, `client.NewSession()` hata veriyor (henüz kanal yok).

**Bitti:** `ssh -p 2222 localhost` "connection closed" diyor ama
handshake log'da başarılı görünüyor.

---

## S1.3 — Kullanıcı adı ayrıştırma

**Dosya:** `internal/sshd/username.go`

**Sorumluluk:** `yigit:web01` formatını kullanıcı ve target'a ayır.

```go
type Route struct {
    User   string
    Target string
}

func ParseUsername(raw string) (Route, error)
```

**Hedef:** Kenar durumlar sessizce yanlış davranmasın.

**Test tablosu:**

| Girdi | Beklenen |
|---|---|
| `yigit:web01` | `{yigit, web01}` |
| `yigit` | hata: target yok |
| `yigit:` | hata: boş target |
| `:web01` | hata: boş user |
| `yigit:web:01` | `{yigit, web:01}` — ilk `:`'ten böl |
| `yigit:web01:extra` | `{yigit, web01:extra}` |
| `` (boş) | hata |
| 512 karakter | hata: çok uzun |

**Bitti:** Tablo testi geçiyor, %100 kapsama.

---

## S1.4 — Hedefe bağlanma

**Dosyalar:** `internal/upstream/dial.go`, `internal/upstream/hostkey.go`

**Sorumluluk:** Config'deki target'a SSH client olarak bağlan.

```go
// internal/upstream/dial.go
type Conn struct {
    client *ssh.Client
    target config.TargetConfig
}

func Dial(ctx context.Context, t config.TargetConfig) (*Conn, error)
func (c *Conn) Close() error
```

⚠️ **`ssh.InsecureIgnoreHostKey()` KULLANMA.** S1'de bile. Config'deki
`host_key` alanını `ssh.FixedHostKey` ile doğrula. Bu alışkanlığı baştan
kur; sonradan eklemek istemezsin.

```go
// internal/upstream/hostkey.go
func hostKeyCallback(expected string) (ssh.HostKeyCallback, error)
```

**Hedef:** Yanlış host key'de bağlantı reddedilsin.

**Test:** `test/integration/dial_test.go` — testcontainers ile bir
`linuxserver/openssh-server` konteyneri kaldır:
- Doğru host key → bağlanıyor
- Yanlış host key → `ssh: host key mismatch`
- Kapalı port → timeout, context'e saygı

**Bitti:** Gerçek bir sshd'ye bağlanıp `client.NewSession()` alabiliyorsun.

---

## S1.5 — Kanal ve request relay

**Dosyalar:** `internal/sshd/channel.go`, `internal/sshd/request.go`,
`internal/upstream/session.go`, `internal/proxy/broker.go`

**Sorumluluk:** Projenin kalbi. Gelen `session` kanalını kabul et, hedefte
karşılık gelen kanalı aç, request'leri iki yön arasında ilet.

```go
// internal/sshd/request.go
type PtyRequest struct {
    Term          string
    Columns, Rows uint32
    Width, Height uint32
    Modes         string
}

type WindowChangeRequest struct {
    Columns, Rows uint32
    Width, Height uint32
}

type ExecRequest struct{ Command string }

func ParsePty(payload []byte) (PtyRequest, error)  // ssh.Unmarshal
```

```go
// internal/proxy/broker.go
type Broker struct {
    down  ssh.Channel        // gelen (kullanıcı)
    downR <-chan *ssh.Request
    up    ssh.Channel        // giden (hedef)
    upR   <-chan *ssh.Request
    rec   *record.Writer
}

func (b *Broker) Run(ctx context.Context) error
```

Relay edilecek request'ler:

| Request | Yön | Not |
|---|---|---|
| `pty-req` | down→up | Payload'ı parse et, kayda başlangıç boyutu yaz |
| `env` | down→up | Whitelist uygula (S5) |
| `shell` | down→up | |
| `exec` | down→up | Komutu kayda metadata olarak yaz |
| `subsystem` | down→up | SFTP (S5) |
| `window-change` | down→up | Kayda `r` olayı yaz |
| `signal` | down→up | |
| `exit-status` | up→down | **Kritik** — yoksa istemci hep 0 döner |
| `exit-signal` | up→down | |

⚠️ **`WantReply` semantiğine dikkat.** `req.WantReply` true ise, upstream'in
cevabını bekleyip `req.Reply(ok, nil)` çağırmalısın. Yanlış yaparsan istemci
asılı kalır. Bu, en sık yapılan hata.

**Hedef:** Interaktif shell çalışıyor, çıkış kodu doğru dönüyor.

**Test:**
```go
// test/integration/shell_test.go
// 1. Proxy üzerinden bağlan, "echo hello" çalıştır, çıktı "hello"
// 2. "exit 3" çalıştır, ExitError.ExitStatus() == 3
// 3. PTY iste, "tput cols" çalıştır, istenen genişliği dönüyor
```

**Bitti:** `ssh yigit:web01@localhost -p 2222` ile interaktif shell açılıyor,
`vim` düzgün çiziliyor, `exit 3` doğru kod dönüyor.

---

## S1.6 — Terminal boyut değişimi

**Dosya:** `internal/proxy/broker.go` (genişletme)

**Sorumluluk:** `window-change` request'ini ilet ve kayda yansıt.

**Hedef:** Terminal penceresini sürüklerken uzaktaki `vim` doğru yeniden
çiziliyor.

**Test:** Manuel — `vim` aç, pencereyi yeniden boyutlandır, düzgün çiziliyor.
Otomatik test için: `window-change` gönder, hedefte `tput cols` yeni değeri
dönüyor.

**Bitti:** Boyut değişimi hem hedefe hem kayda yansıyor.

---

## S1.7 — asciicast kaydedici

**Dosyalar:** `internal/record/asciicast.go`, `internal/record/store.go`

**Sorumluluk:** Oturum akışını asciicast v2 formatında yaz.

Format — ilk satır başlık, sonrası olay satırları:

```
{"version":2,"width":80,"height":24,"timestamp":1723465329,"env":{"TERM":"xterm-256color","SHELL":"/bin/bash"}}
[0.248848,"o","\u001b[?1034h"]
[1.001376,"o","yigit@web01:~$ "]
[2.143881,"i","ls\r"]
[2.144992,"o","ls\r\n"]
[3.002100,"r","120x30"]
```

```go
// internal/record/asciicast.go
type Writer struct {
    w       io.WriteCloser
    start   time.Time
    mu      sync.Mutex
}

func NewWriter(w io.WriteCloser, width, height int, env map[string]string) (*Writer, error)
func (w *Writer) Output(b []byte) error   // "o"
func (w *Writer) Input(b []byte) error    // "i"
func (w *Writer) Resize(cols, rows int) error  // "r"
func (w *Writer) Close() error
```

⚠️ **Tasarım notları:**

1. **Mutex şart.** Çıktı ve girdi ayrı goroutine'lerden gelir.
2. **Zaman damgası göreli**, saniye cinsinden float, oturum başlangıcından.
3. **JSON escape'i kütüphaneye bırak.** Terminal çıktısı geçersiz UTF-8
   içerebilir; `json.Marshal` bunu handle eder, elle string birleştirme etmez.
4. **Girdiyi kaydetmek opsiyonel olsun.** Şifre yazımı da girdidir.
   Config'de `record_input: false` varsayılan.

**Test:** `internal/record/asciicast_test.go`
- Başlık satırı geçerli JSON ve doğru alanlar
- Olay sırası korunuyor
- Geçersiz UTF-8 baytları kaybetmeden yazılıyor
- Eş zamanlı `Output`/`Input` çağrılarında satır bozulmuyor (race test:
  `go test -race`)
- Üretilen dosya `asciinema play` ile oynatılabiliyor (manuel doğrulama)

**Bitti:** Bir oturum kaydedip `asciinema play kayit.cast` ile izleyebiliyorsun.

---

## S1.8 — exec oturumları

**Dosya:** `internal/proxy/broker.go` (genişletme)

**Sorumluluk:** PTY olmayan `exec` oturumlarını (scp, rsync, `ssh host cmd`)
düzgün geçir.

**Hedef:** `ssh yigit:web01@localhost -p 2222 'cat /etc/hostname'` çalışıyor.

**Test:**
- `exec` ile komut çalıştır, stdout doğru
- stderr ayrı kanaldan geliyor
- Çıkış kodu doğru
- `scp` ile dosya kopyalama çalışıyor (bu S1'de çalışmayabilir, S5'e kalabilir
  — o zaman testi `t.Skip` ile işaretle ve S5'e taşı)

**Bitti:** Non-PTY komut çalıştırma çalışıyor.

---

## S1.9 — Entegrasyon test altyapısı

**Dosya:** `test/integration/main_test.go`

**Sorumluluk:** Testler için gerçek bir sshd konteyneri kaldır.

```go
func TestMain(m *testing.M) {
    // testcontainers: linuxserver/openssh-server
    // test kullanıcısı + anahtar üret, konteynere ver
    // host key'i al, config'e yaz
    // proxy'yi rastgele portta başlat
    os.Exit(m.Run())
}
```

**Hedef:** `make test-integration` tek komutla çalışsın, CI'da da çalışsın.

**Bitti:** Testler mock'a değil gerçek OpenSSH'a karşı koşuyor.

> **S1 tamamlandı.** Burada durursan: SSH protokolünü öğrendin, çalışan bir
> proxy'n var. Warewave production'ı Warpgate'te kalmaya devam eder.

---

# S2 — Sertifika modeli (3 hafta)

**Hedef:** Hedefe statik anahtarla değil, o oturuma özel, kullanıcının
kimliğini taşıyan kısa ömürlü sertifikayla bağlan.

**Bu aşama driver 1'i kapatıyor.** Warpgate'in `target = tek username`
kısıtı ortadan kalkıyor: kullanıcı hedefe **kendi adıyla** düşüyor,
`loginuid` gerçek kişiye set oluyor, redthread'in join'i basitleşiyor.

---

## S2.1 — CA yaşam döngüsü

**Dosyalar:** `internal/ca/ca.go`, `cmd/postern/ca.go`

```go
type CA struct {
    signer ssh.Signer
}

func Init(path string) (*CA, error)      // anahtar üret, 0600 ile yaz
func Load(path string) (*CA, error)
func (c *CA) PublicKey() ssh.PublicKey   // TrustedUserCAKeys içeriği
```

CLI:
```bash
postern ca init                  # anahtar çifti üret
postern ca show                  # public key'i bas (authorized dağıtım için)
```

**Test:** Init idempotent değil (var olanı ezmez, hata verir); Load
üretileni okuyabiliyor; dosya izinleri 0600.

**Bitti:** `postern ca show` çıktısını hedefteki
`/etc/ssh/postern_ca.pub` dosyasına koyabiliyorsun.

---

## S2.2 — Sertifika imzalama ⚠️ SEN YAZ

**Dosya:** `internal/ca/sign.go`

```go
type CertRequest struct {
    PublicKey   ssh.PublicKey
    KeyID       string          // "yigit@warewave.io"
    Principals  []string        // izinli OS kullanıcı adları
    ValidFor    time.Duration
    Extensions  map[string]string
}

func (c *CA) Sign(req CertRequest) (*ssh.Certificate, error)
```

Doğru implementasyonun taşıması gerekenler:

- `CertType: ssh.UserCert`
- `ValidAfter`: **şimdiden 60 sn önce** (saat kayması toleransı)
- `ValidBefore`: `ValidAfter + ValidFor`
- `Serial`: monotonik veya rastgele — audit için benzersiz
- `KeyId`: kim için kesildiği, audit log'a düşer
- `ValidPrincipals`: **asla boş bırakma** — boş principal listesi
  OpenSSH'ta "her kullanıcı" anlamına gelir
- `Permissions.Extensions`: `permit-pty` gerekli; `permit-port-forwarding`,
  `permit-agent-forwarding` **varsayılan kapalı**
- `CriticalOptions`: gerekirse `source-address`, `force-command`

**Test:** `internal/ca/sign_test.go`
- İmzalanan sertifika `ssh.CertChecker` ile doğrulanıyor
- Süresi dolmuş sertifika reddediliyor
- Yanlış principal ile giriş reddediliyor
- Boş principal listesi **hata döndürüyor** (izin vermiyor)
- `permit-port-forwarding` istenmemişse sertifikada yok

**Bitti:** Testler geçiyor ve ben kodu gözden geçirdim.

---

## S2.3 — Sertifika ile hedefe bağlanma

**Dosyalar:** `internal/upstream/dial.go` (değişiklik),
`internal/proxy/lifecycle.go`

**Sorumluluk:** Bağlantı anında geçici anahtar çifti üret, CA ile imzala,
hedefe o sertifikayla bağlan.

```go
func DialWithCert(ctx context.Context, t Target, identity Identity, ca *ca.CA) (*Conn, error)
```

Akış:
1. Efemeral ed25519 anahtar çifti üret (oturuma özel, diske yazılmaz)
2. `ca.Sign` ile principal = `identity.OSUser`
3. `ssh.PublicKeys(certSigner)` ile bağlan

**Hedef tarafı yapılandırması** (`deploy/ansible/` içine):

```
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/postern_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

```bash
# /etc/ssh/auth_principals/yigit
yigit
```

**Test:** `test/integration/cert_test.go`
- Sertifika ile bağlanma çalışıyor
- Süresi dolmuş sertifika reddediliyor
- Yanlış principal reddediliyor
- **Hedefte `who am i` doğru kullanıcıyı gösteriyor**

**Bitti:** Kullanıcı hedefe kendi adıyla düşüyor; `authorized_keys`'te hiçbir
statik anahtar yok.

---

## S2.4 — Principal politikası

**Dosyalar:** `internal/policy/authorize.go` ⚠️ SEN YAZ,
`internal/policy/authorize_test.go`

**Sorumluluk:** "Bu kullanıcı bu hedefe hangi OS kullanıcısı olarak
bağlanabilir?" kararı.

```go
type Decision struct {
    Allowed    bool
    OSUser     string
    Reason     string      // reddedilme sebebi, audit için
}

func Authorize(u model.User, t model.Target, requested string) Decision
```

**Test tablosu** — her satır ayrı test:

| Kullanıcı rolü | Hedef | İstenen OS user | Beklenen |
|---|---|---|---|
| ops | web01 | (boş) | izin, varsayılan `yigit` |
| ops | web01 | `root` | **red** |
| readonly | web01 | `yigit` | izin |
| readonly | db01 | `yigit` | red — hedef yetkisi yok |
| (rolsüz) | web01 | `yigit` | red |
| ops | web01 | `../etc` | red — geçersiz kullanıcı adı |

⚠️ Son satır önemli: OS kullanıcı adını doğrula. Principal'a giden değer
hiçbir zaman doğrudan kullanıcı girdisinden gelmemeli.

**Bitti:** Tablo testi geçiyor, varsayılan **deny**.

> **S2 tamamlandı.** Driver 1 kapandı. Burada durursan: elinde Warpgate'in
> çözemediği problemi çözen çalışan bir proxy var.

---

# S3 — OIDC, kalıcılık, RBAC (4 hafta)

**Hedef:** Config dosyasından DB'ye geç, OIDC ile giriş ekle, kullanıcı/rol/
target modelini gerçek hale getir.

## S3.1 — Şema ve store

**Dosyalar:** `internal/store/migrations/001_init.sql`,
`internal/store/queries/*.sql`, `internal/store/store.go`

```sql
CREATE TABLE users (
  id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE, os_user TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE targets (
  id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
  host TEXT NOT NULL, port INTEGER NOT NULL, host_key TEXT NOT NULL
);
CREATE TABLE user_roles (user_id TEXT, role_id TEXT, PRIMARY KEY (user_id, role_id));
CREATE TABLE role_targets (role_id TEXT, target_id TEXT, PRIMARY KEY (role_id, target_id));
CREATE TABLE sessions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, target_id TEXT NOT NULL,
  os_user TEXT NOT NULL, src_ip TEXT, started_at INTEGER NOT NULL,
  ended_at INTEGER, recording_path TEXT
);
```

**Test:** Migration up/down çalışıyor; `sqlc generate` üretilen kod derleniyor;
temel CRUD testleri.

## S3.2 — OIDC

**Dosya:** `internal/auth/oidc.go`

Authorization Code + PKCE. `state` ve `nonce` doğrulaması **zorunlu** —
Warpgate'in CVE-2026-44347'si tam olarak `state` doğrulamamaktan çıktı.

**Test:** Keycloak testcontainer'ına karşı tam akış; `state` uyuşmazlığında
red; süresi dolmuş token'da red.

## S3.3 — CLI'da OOB akışı

**Dosya:** `internal/sshd/auth.go` (genişletme)

Kullanıcı SSH ile bağlandığında terminale login linki ve güvenlik anahtarı
bas, tarayıcıda onay bekle. Warpgate'in yaptığı şey.

**Test:** Link üretiliyor; onay sonrası bağlantı devam ediyor; timeout'ta
temiz kapanıyor.

## S3.4 — Oturum kaydı ve CLI

`postern session list`, `postern session show <id>`,
`postern target add|list`, `postern user add|list`

> **S3 tamamlandı.** Kullanılabilir ürün. Web terminal olmadan da Warewave'de
> pilot çalıştırabilirsin.

---

# S4 — Web terminal (3 hafta)

**Dosyalar:** `internal/httpapi/terminal.go`, `web/`

WebSocket ↔ SSH kanal köprüsü + xterm.js. Bu aşamada web UI desteğini
kullanacağını söylemiştin; backend sözleşmesi:

```
WS /api/terminal/{target}
  → binary frame: terminal çıktısı
  ← binary frame: klavye girdisi
  ← JSON frame: {"type":"resize","cols":120,"rows":30}
```

**Test:** WS bağlantısı kuruluyor; girdi/çıktı akıyor; resize iletiliyor;
bağlantı kopunca SSH oturumu kapanıyor.

---

# S5 — Uç durumlar ve sertleştirme (4 hafta)

Bu aşamayı şimdi detaylandırmıyorum — S1–S4'ten gelecek gerçek bilgi planı
değiştirecek. Kabaca kapsam:

- SFTP subsystem relay — ✅ BİTTİ, ama plandakinden BAŞKA bir yolla.
  Plan `pkg/sftp` ile relay diyordu; bu, araya tam bir SFTP sunucusu
  koymak demekti. Onun yerine akış SONLANDIRILMIYOR: baytlar hedefe
  olduğu gibi gidiyor, kopyası çözümlenip dosya olaylarına dönüşüyor
  (`internal/sftpaudit`, `internal/proxy/sftp.go`). Gerekçe: protokolü
  yeniden uygulamak, kendi hatalarımızı kullanıcıyla hedefin arasına
  koymak olurdu. `pkg/sftp` yalnızca TEST bağımlılığı olarak duruyor —
  gerçek bir istemcinin ürettiği paketlerle doğrulamak için.
  Açılması `session.sftp` ile, VARSAYILAN KAPALI. Olaylar
  `session_files` tablosunda ve oturum detayında.
- `scp` protokol modu — ✅ modern `scp` zaten SFTP kullanıyor, aynı iş
- Proxmox etiket biçimi — ✅ ÖLÇÜLDÜ ve düzeltildi: etiket ayrıştırıcısı
  yalnızca `anahtar=değer` ve `anahtar:değer` tanıyordu, ama Proxmox
  etiket karakter kümesi `[a-z0-9_.+-]` (pve-common `pve-tag`) ve `=`
  ile `:` bir etikete HİÇ yazılamıyor. Yani özellik gerçek Proxmox'ta
  hiç çalışmıyordu: her makine sessizce `unknown` rolüne düşüyordu.
  Ayırıcıya `_` eklendi ve eşleşme ÖN EK üzerinden yapılıyor (alt çizgi
  anahtarın da değerin de içinde geçebiliyor). Ayrıca hiçbir etiket
  eşleşmediğinde rapor artık bağırıyor ve görülen etiketleri basıyor.
- AD aralıklı getirme (ranged retrieval) — ✅ ÖLÇÜLDÜ ve düzeltildi:
  AD ~1500 üyeden büyük grupta `member` yerine `member;range=0-1499`
  gönderiyor, düz niteliği HİÇ vermiyor. Yönetici grubu ONAY EKRANI bu
  yüzden en büyük grupları "kimse yok" diye gösteriyordu. Gerçek
  OpenLDAP bunu üretmediği için entegrasyon testi yakalayamıyordu →
  `internal/ldap/ldaptest` (sahte LDAP sunucusu) yazıldı; yönlendirme
  (referral) yolu da ilk kez orada test edilebildi.
- Port forwarding (`direct-tcpip`) — istenirse. Şu an kanal tipi
  reddediliyor (`internal/sshd/channel.go`)
- Agent forwarding — ✅ reddediliyor (request süzgeci)
- `env` whitelist — ✅ bitti (`session.accept_env`, varsayılan LANG/LC_*)
- Keepalive, yarı kapalı bağlantı, timeout'lar — ✅ handshake son tarihi
  (+ OOB uzatması), oturum boşta kalma ve mutlak ömür sınırları
- Rate limiting, bağlantı sayısı sınırı — ✅ eşzamanlı bağlantı sınırı
  (küresel + IP başına), kanal sınırı, bekleyen giriş kotası,
  MaxAuthTries. İSTEK HIZI sınırı ölçülmeden eklenmedi: eşzamanlılık
  sınırı tek kaynağı zaten dar bir bant genişliğine indiriyor
- `go test -race` tüm pakette temiz — ✅
- `gosec`, `govulncheck` CI'da — ✅ (`.github/workflows/ci.yml`, `make audit`)
  - govulncheck ilk koşuda 7 açık buldu: 6'sı standart kütüphanede
    (go 1.26.5 → 1.26.6), 1'i testcontainers'ın bağımlılığında
  - gosec 47 bulgu verdi; gerçek olanlar düzeltildi (HTTP
    ReadHeaderTimeout, ters vekil arkasında Secure çerez, saat 1970
    öncesindeyse sertifika imzalamayı reddetme), kalanlar tek tek
    gerekçelendirildi
- Fuzz: `ParseUsername`, request payload parser'ları — ✅ 15 hedef
  (`make fuzz`, haftalık cron). Hepsi ÖZELLİK doğruluyor, çökme değil:
  x/crypto ile diferansiyel, kayıpsızlık, parça-bağımsızlık, kabul
  kümesi kapsaması. Beş gerçek hata buldu — en ciddisi `dsn`'in host'suz
  bir URI'de "//" düşürüp pgx'i anahtar=değer parser'ına çevirmesi ve
  TLS'i tamamen kaybetmesiydi
- Periyodik dizin senkronizasyonu — ✅ üç değerli varlık sorusu, dizin
  sondası, patlama yarıçapı tavanı, grace penceresi ve koşu geçmişi.
  Kritik olan iptal etmek değil, KESİNTİDE iptal ETMEMEK
- Harici güvenlik incelemesi (mümkünse)

---

# Ek A — Test stratejisi

| Katman | Ne | Araç |
|---|---|---|
| Unit | Parser'lar, asciicast, policy | stdlib `testing`, tablo testleri |
| Integration | Gerçek sshd'ye karşı | `testcontainers-go` |
| Race | Tüm paketler | `go test -race ./...` |
| Fuzz | Protokol parser'ları | `go test -fuzz` |
| E2E | Gerçek OpenSSH istemcisi | shell script + `expect` |
| Manuel | `vim`, `tmux`, `top`, resize | Kontrol listesi |

**Manuel kontrol listesi** (her sürüm öncesi):

- [ ] `vim` açılıyor, renkler doğru, `:q` çıkıyor
- [ ] `tmux` çalışıyor, pencere bölme doğru çiziliyor
- [ ] `top` canlı güncelleniyor
- [ ] Terminal penceresi resize edilince uzak uygulama uyum sağlıyor
- [ ] `Ctrl+C` sinyali iletiliyor
- [ ] `exit 3` → istemci 3 dönüyor
- [x] `scp` dosya kopyalıyor (SFTP üzerinden, denetimli)
- [ ] Uzun çıktı (`yes | head -1000000`) tıkanmıyor
- [ ] Kayıt `asciinema play` ile oynatılıyor
- [ ] Bağlantı koparsa kayıt bozulmadan kapanıyor

---

# Ek B — Güvenlik incelemesi kontrol listesi

Her sürüm öncesi, tek tek:

**Kimlik doğrulama**
- [ ] Varsayılan **deny** — yetki bulunamazsa reddet
- [ ] Sertifika süresi kontrol ediliyor
- [ ] Principal listesi asla boş değil
- [ ] `state`/`nonce` OIDC'de doğrulanıyor
- [x] TOTP replay koruması var (store.UseTOTPStep: tek ifadede karşılaştır-ve-yaz; 16 yollu yarışla ölçüldü)

**SSH**
- [ ] `InsecureIgnoreHostKey` hiçbir yerde yok
- [ ] Hedef host key doğrulanıyor
- [ ] Agent forwarding varsayılan kapalı
- [ ] Port forwarding varsayılan kapalı

**Girdi**
- [ ] OS kullanıcı adı doğrulanıyor (regex allowlist)
- [ ] Target adı doğrulanıyor
- [ ] Dosya yolları kullanıcı girdisinden türetilmiyor
- [ ] Request payload'ları uzunluk sınırlı

**Sırlar**
- [ ] CA anahtarı 0600
- [ ] Efemeral anahtarlar diske yazılmıyor
- [ ] Log'da sır yok (client_secret, token, şifre)
- [ ] Kayıtta girdi varsayılan kapalı

**Kaynak**
- [ ] Eş zamanlı bağlantı sınırı
- [ ] Oturum başına kayıt boyutu sınırı
- [ ] Timeout'lar tanımlı (handshake, idle, toplam)

---

# Ek C — SSH protokol notları

Öğrenirken sık takılınan yerler:

**1. Kanal ≠ bağlantı.** Bir SSH bağlantısı üzerinde birden fazla kanal
açılabilir. `session`, `direct-tcpip`, `forwarded-tcpip` farklı tiplerdir.

**2. Request'lerin `WantReply`'si var.** True ise cevap **zorunlu**. Proxy'de
upstream'in cevabını beklemeden `Reply` çağırırsan yanlış cevap verirsin;
hiç çağırmazsan istemci asılır.

**3. `exit-status` ayrı bir request'tir.** Kanal kapanması çıkış kodunu
taşımaz. İletmezsen her komut 0 döner ve bunu fark etmen zaman alır.

**4. PTY modes opaque bir string'dir.** Parse etmene gerek yok, olduğu gibi
ilet.

**5. stderr ayrı bir "extended data" akışıdır** (`ssh.Channel.Stderr()`).
Ayrı kopyalaman gerekir.

**6. Yarı kapalı bağlantı gerçektir.** İstemci stdin'i kapatıp çıktı almaya
devam edebilir (`cat file | ssh host 'wc -l'`). `CloseWrite()` kullan,
`Close()` değil.

**7. Kayıt için terminal emülasyonu gerekmez.** asciicast ham byte akışını
saklar; oynatıcı emülasyonu yapar. Bu, video kaydına göre en büyük avantaj.

---

## Zaman çizelgesi

| Aşama | Süre | Kümülatif | Çıktı |
|---|---|---|---|
| S1 | 3 hafta | 3 hafta | Çalışan proxy + kayıt |
| S2 | 3 hafta | 6 hafta | **Sertifika modeli — driver 1 kapandı** |
| S3 | 4 hafta | 10 hafta | OIDC + RBAC, kullanılabilir ürün |
| S4 | 3 hafta | 13 hafta | Web terminal |
| S5 | 4 hafta | 17 hafta | Production adayı |

**Warewave production'ı S5 bitene kadar Warpgate'te kalsın.** Öğrenme
projesi ile kurumun tek erişim kapısı aynı anda olmaz; ikincisine dönüştüğü
an tüm kapsam kesimleri geri gelir.
