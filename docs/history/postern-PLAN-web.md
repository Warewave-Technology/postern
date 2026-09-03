# postern — Web İş Kolu (W)

> Ana plan `postern-PLAN.md`'e paralel ilerleyen iş kolu.
> **Sorumlu: Claude.** Yiğit gözden geçirir ve API sözleşmesini onaylar.

---

## 0. Sıralama kararı — neden UI'dan önce sözleşme

Admin UI'ı bugün kodlamaya başlamak cazip ama iki kez yazmaya yol açar:
veri modeli S3'te (DB şeması) oturuyor, ondan önce yazılan her ekran
geçici bir yapıya bağlanır.

Doğru sıra:

| Ne zaman | Ne yapılır | Neden |
|---|---|---|
| **Şimdi** | API sözleşmesi kilitlenir (W0) | Model kararlarını öne çeker, backend'i yönlendirir |
| S1 boyunca | UI iskeleti + mock backend (W1) | Sözleşmeye karşı çalışır, gerçek veri beklemez |
| S2 boyunca | CRUD ekranları (W2) | Hâlâ mock'a karşı |
| S3'te | Gerçek API'ye bağlanma (W3) | Sözleşme değişmediyse tek satır: mock kapatılır |
| S3 sonu | Oturum listesi + kayıt oynatıcı (W4) | Veri gerçek olmadan anlamsız |
| S4 | Web terminal (W5) | Ana plandaki S4 |

**Sözleşmeyi öne çekmenin asıl faydası:** UI'ı tasarlarken "bu ekran hangi
alanlara ihtiyaç duyuyor" sorusu, veri modelindeki eksikleri S3'ten önce
ortaya çıkarır. Şema yazıldıktan sonra keşfetmekten çok daha ucuz.

**Motivasyon argümanı da gerçek:** 17 haftalık tek kişilik bir projede,
3. haftada çalışan bir arayüz görmek işi sürdürülebilir kılar. W1 bunu
sözleşmeyi bozmadan sağlıyor.

---

## 1. Teknoloji kararı

| Katman | Seçim | Gerekçe |
|---|---|---|
| Framework | React 18 + TypeScript | En geniş ekosistem; ben yokken de sürdürülebilir |
| Build | Vite | Hızlı, yapılandırması az |
| Stil | Tailwind CSS | Ayrı CSS dosyası yönetimi yok |
| Router | React Router | |
| Veri | TanStack Query | Cache, refetch, loading state hazır |
| Terminal | `@xterm/xterm` + `@xterm/addon-fit` | W5 |
| Kayıt oynatıcı | `asciinema-player` | **asciicast seçiminin bedava kazancı — ⚠️ DEĞİL: 3.x sürümleri VT emülasyonunu gömülü WASM olarak taşıyor ve script-src 'self' onu engelliyor (ölçüldü). Oynatma xterm.js'e yapılıyor** |
| API tipleri | `openapi-typescript` | Sözleşmeden otomatik üretim |
| Dağıtım | `go:embed` | Tek binary korunur |

**Neden React, Svelte değil:** Warpgate Svelte kullanıyor ve bundle'ı daha
küçük. Ama bu projede belirleyici olan sürdürülebilirlik: ben bu projeden
çıkarsam React'te yardım bulmak çok daha kolay. Bundle boyutu bir admin
paneli için kritik değil.

**`asciinema-player` önemli bir kazanç.** S1.7'de asciicast formatını
seçtiğimiz için kayıt oynatıcıyı yazmıyoruz — hazır bileşeni gömüyoruz.
Metin araması, hız kontrolü, zaman çizelgesinde atlama hepsi geliyor.
Video kaydı seçseydik bunların hepsini yazmak gerekirdi.

---

## W0 — API sözleşmesi (şimdi, 3 gün)

**Dosya:** `api/openapi.yaml`

**Sorumluluk:** Backend ve frontend arasındaki sözleşmeyi kilitle. Bu dosya
hem `openapi-typescript` ile TS tiplerini, hem (istersen) `oapi-codegen` ile
Go handler iskeletlerini üretir.

### Kaynak modelleri

```yaml
Target:
  id: string (uuid)
  name: string
  host: string
  port: integer
  host_key: string          # beklenen host key (fingerprint)
  roles: [string]           # erişebilen rol adları
  created_at: string (date-time)

User:
  id: string (uuid)
  username: string          # postern kullanıcı adı
  email: string
  os_user: string           # hedefteki OS kullanıcı adı (principal)
  roles: [string]
  source: enum [local, oidc]
  last_login: string (date-time) | null
  created_at: string (date-time)

Role:
  id: string (uuid)
  name: string
  target_count: integer
  user_count: integer

Session:
  id: string (uuid)
  user: { id, username, email }
  target: { id, name, host }
  os_user: string
  src_ip: string
  auth_method: enum [sso, publickey, certificate]
  started_at: string (date-time)
  ended_at: string (date-time) | null
  recording: { available: boolean, size_bytes: integer } | null
  exit_status: integer | null
```

### Uç noktalar

| Metod | Yol | Açıklama |
|---|---|---|
| GET | `/api/v1/info` | Sürüm, CA public key, özellik bayrakları |
| GET | `/api/v1/targets` | Liste, `?q=` arama |
| POST | `/api/v1/targets` | Oluştur |
| GET/PATCH/DELETE | `/api/v1/targets/{id}` | |
| GET | `/api/v1/users` | Liste |
| POST | `/api/v1/users` | Oluştur |
| GET/PATCH/DELETE | `/api/v1/users/{id}` | |
| GET | `/api/v1/roles` | Liste |
| POST | `/api/v1/roles` | Oluştur |
| PUT | `/api/v1/roles/{id}/targets` | Rol→target atama (toplu) |
| PUT | `/api/v1/users/{id}/roles` | Kullanıcı→rol atama (toplu) |
| GET | `/api/v1/sessions` | `?user=&target=&from=&to=&active=` |
| GET | `/api/v1/sessions/{id}` | Detay |
| GET | `/api/v1/sessions/{id}/recording` | asciicast dosyası (`text/plain`) |
| DELETE | `/api/v1/sessions/{id}` | Aktif oturumu sonlandır |
| WS | `/api/v1/terminal/{target_id}` | W5 |

### Sözleşme kuralları

- Hata gövdesi her zaman: `{"error": {"code": "...", "message": "..."}}`
- Liste yanıtları sayfalı: `{"items": [...], "total": N, "cursor": "..."}`
- Tarihler RFC3339, UTC
- `id` alanları UUID v4
- Kısmi güncelleme `PATCH`, tam değiştirme `PUT`

**Hedef:** Backend ve frontend birbirini beklemeden ilerleyebilsin.

**Test:** `make api-lint` — `redocly lint api/openapi.yaml` temiz geçiyor.

**Bitti:** Sen sözleşmeyi onayladın. Değişiklik gerekirse versiyonlu yapılır
(`/api/v2/`), sessizce kırılmaz.

---

## W1 — UI iskeleti + mock backend (S1 boyunca, 1 hafta)

**Dosyalar:**

```
web/
├── package.json
├── vite.config.ts
├── tailwind.config.ts
├── index.html
├── src/
│   ├── main.tsx
│   ├── App.tsx
│   ├── api/
│   │   ├── types.gen.ts        # openapi-typescript çıktısı
│   │   ├── client.ts           # fetch sarmalayıcı, hata normalizasyonu
│   │   └── mock/
│   │       ├── handlers.ts     # MSW handler'ları
│   │       └── fixtures.ts     # örnek veri
│   ├── components/
│   │   ├── Layout.tsx          # sidebar + header
│   │   ├── DataTable.tsx       # sıralama, arama, sayfalama
│   │   ├── EmptyState.tsx
│   │   └── ErrorBoundary.tsx
│   ├── pages/
│   │   └── Dashboard.tsx       # aktif oturum sayısı, target sayısı
│   └── lib/
│       └── format.ts           # tarih, boyut, süre biçimleme
└── embed.go                    # go:embed dist/
```

Mock için **MSW** (Mock Service Worker) — gerçek `fetch` çağrılarını
yakalar, yani W3'te mock'u kapatmak dışında hiçbir değişiklik gerekmez.

**Hedef:** `npm run dev` ile çalışan, gezinilebilir bir admin paneli.
Veri sahte ama şekil gerçek.

**Test:**
- `npm run build` temiz
- `npm run typecheck` temiz
- Vitest: `DataTable` sıralama/arama davranışı
- Go tarafında: `go build` ile embed edilen dosyalar binary'de

**Bitti:** `postern serve` binary'si `/admin` yolunda paneli sunuyor
(mock veriyle).

---

## W2 — CRUD ekranları (S2 boyunca, 2 hafta)

**Dosyalar:** `web/src/pages/` altında

| Sayfa | İçerik |
|---|---|
| `Targets.tsx` | Liste, arama, ekle/düzenle/sil modal'ı |
| `TargetDetail.tsx` | Host key, erişebilen roller, son oturumlar |
| `Users.tsx` | Liste, kaynak rozeti (local/oidc), rol atama |
| `UserDetail.tsx` | Roller, son oturumlar, son giriş |
| `Roles.tsx` | Liste, rol→target ve rol→kullanıcı atama matrisi |

**Tasarım notu:** Rol atama için matris görünümü (satır: rol, sütun: target,
hücre: onay kutusu). Toplu değişikliği tek `PUT` ile gönderir. Tek tek
ekleme/çıkarma yerine bu, hem daha az istek hem daha az yarış durumu.

**Hedef:** Bir hedefi, kullanıcıyı ve rolü baştan sona arayüzden yönetebilmek.

**Test:**
- Vitest + Testing Library: her sayfa için render + temel etkileşim
- Playwright (opsiyonel): mock'a karşı e2e "target ekle → listede gör"
- Erişilebilirlik: form etiketleri, klavye navigasyonu

**Bitti:** Mock'a karşı tüm CRUD akışları çalışıyor.

---

## W3 — Gerçek API'ye bağlanma (S3 içinde, 3 gün)

**Sorumluluk:** MSW'yi kapat, gerçek endpoint'lere bağlan, farkları düzelt.

Adımlar:
1. `openapi-typescript` ile tipleri yeniden üret
2. MSW'yi sadece test ortamında bırak
3. Auth: admin paneli için OIDC oturum cookie'si
4. Sözleşmeden sapmaları raporla — **backend'i sözleşmeye uydur, UI'ı değil**

**Hedef:** W0'daki sözleşme doğruysa bu adım 3 gün sürer. Uzuyorsa sözleşme
yeterince spesifik değilmiş demektir — o bilgi de değerli.

**Test:** Entegrasyon: gerçek `postern serve` binary'sine karşı Playwright.

**Bitti:** Panel gerçek veriyle çalışıyor, mock sadece testlerde.

---

## W4 — Oturumlar ve kayıt oynatıcı (S3 sonu, 1 hafta) — ✅

**Dosyalar:** `web/src/pages/Sessions.tsx`, `web/src/pages/SessionDetail.tsx`,
`web/src/components/CastPlayer.tsx`

| Özellik | Not |
|---|---|
| Oturum listesi | Kullanıcı, target, süre, durum filtreleri |
| Aktif oturum göstergesi | Canlı rozet, sonlandırma butonu |
| Kayıt oynatma | `asciinema-player` gömülü |
| Kayıt içinde arama | Oynatıcının kendi özelliği |
| Kayıt indirme | Ham `.cast` dosyası |

```tsx
// CastPlayer.tsx — özet
import * as AsciinemaPlayer from 'asciinema-player';
import 'asciinema-player/dist/bundle/asciinema-player.css';

// create(src, element, opts) — src: /api/v1/sessions/{id}/recording
```

⚠️ Aktif oturum sonlandırma butonuna **onay diyaloğu** koy ve kullanıcı
adı + target adını göster. Yanlış oturumu kesmek production'da kötü bir gün
demek.

**Hedef:** Bir oturumu listeden bulup kaydını tarayıcıda izlemek.

**Test:** Sabit bir `.cast` fixture'ı ile oynatıcı render testi; filtrelerin
doğru query parametresi ürettiği testi.

**Bitti:** Kayıt tarayıcıda oynuyor, içinde metin araması çalışıyor.

---

## W5 — Web terminal (S4, 3 hafta)

Ana plandaki S4 ile aynı. Backend sözleşmesi:

```
WS /api/v1/terminal/{target_id}
  → binary frame  : terminal çıktısı (hedeften kullanıcıya)
  ← binary frame  : klavye girdisi
  ← text frame    : {"type":"resize","cols":120,"rows":30}
  → text frame    : {"type":"error","message":"..."}
                    {"type":"exit","status":0}
```

**Dosyalar:** `web/src/pages/Terminal.tsx`,
`web/src/components/XTerm.tsx`

Dikkat edilecekler:

- `@xterm/addon-fit` ile boyut hesapla, `ResizeObserver` ile pencere
  değişimini yakala, debounce ile resize mesajı gönder
- Binary frame kullan — base64'e çevirme, gereksiz %33 şişme
- Bağlantı koptuğunda kullanıcıya net mesaj göster, sessizce donma
- `Ctrl+C`, `Ctrl+D` gibi kontrol dizilerinin tarayıcı kısayollarıyla
  çakışmasını engelle

**Test:** Mock WS sunucusuna karşı: girdi gönderiliyor, çıktı yazılıyor,
resize mesajı doğru formatta, kopma durumu ele alınıyor.

**Bitti:** Tarayıcıdan hedefe bağlanıp interaktif çalışabiliyorsun.

---

## İş bölümü özeti

| İş | Kim |
|---|---|
| `api/openapi.yaml` taslağı | Claude |
| Sözleşme onayı | **Yiğit** |
| `web/` altındaki her şey | Claude |
| Go tarafı HTTP handler'ları | Yiğit |
| `internal/httpapi/terminal.go` (WS↔SSH köprüsü) | Yiğit |
| `internal/sshd/auth.go`, `ca/sign.go`, `policy/authorize.go` | **Yiğit — devredilmez** |

Sınır net: **ben tarayıcı tarafını ve sözleşmeyi yazıyorum, sen sunucu
tarafını.** WS↔SSH köprüsü kritik yolda olduğu için sende — orada bir hata
oturum izolasyonunu bozar.

---

## Güncellenmiş zaman çizelgesi

| Hafta | Ana kol (Yiğit) | Web kolu (Claude) |
|---|---|---|
| 0 | — | **W0: API sözleşmesi** |
| 1–3 | S1: SSH proxy çekirdeği | W1: UI iskeleti + mock |
| 4–6 | S2: Sertifika modeli | W2: CRUD ekranları |
| 7–10 | S3: OIDC + DB + RBAC | W3: Gerçek API · W4: Oturumlar |
| 11–13 | S4: WS↔SSH köprüsü | W5: Web terminal |
| 14–17 | S5: Uç durumlar + sertleştirme | Düzeltmeler, erişilebilirlik |

Web kolu ana kolu bloklamıyor; sözleşme sabit olduğu sürece paralel akıyor.
