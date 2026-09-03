package httpapi

// Bu dosyadaki hedefler SAF: ne WebSocket, ne veritabanı, ne disk.
// handleControl yalnızca c.reqs'e dokunuyor, sameOriginURL iki dizeye,
// spaHandler ise gömülü (derlemeye kaçmış) bir dosya sistemine — üçü de
// saniyede binlerce kez çağrılmaya uygun.

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/proxy"
	"github.com/Warewave-Technology/postern/web"
)

// --- 1. handleControl -------------------------------------------------

// maxTerminalDim, bir terminal boyutunun taşıyabileceği en büyük değer.
//
// Sınır keyfi değil, DONANIMDAN geliyor: pty boyutu çekirdekte
// struct winsize'dır ve alanları unsigned short — 16 bit. Bundan büyük
// bir sayı TIOCSWINSZ'e giderken 65536'ya göre modunu alır, yani hedefte
// kaydın söylediğinden BAŞKA bir boyut oluşur. Denetim kaydı ile
// gerçeğin ayrışması bir bastion için tek başına yeterli sebep.
// Sabit ÜRETİM KODUNDAN geliyor (bkz. broker.go / wschannel.go):
// testin kendi kopyasını tutması, sınır değişince testin sessizce
// eski değeri doğrulamaya devam etmesi demek olurdu.
var _ = maxTerminalDim

// FuzzHandleControl checks what a browser control frame can enqueue.
//
// Denetlenen özellik: ya hiçbir şey kuyruğa girmez, ya da TAM OLARAK bir
// "window-change" girer ve o request'in payload'ı
//
//   - proxy.ParseWindowChange ile çözülür (kuyruğa broker'ın
//     ayrıştıramayacağı bir şey koymak, hatayı bu dosyadan 3 katman
//     uzakta bir log satırına çevirirdi),
//   - JSON'da yazan sayının AYNISINI taşır (JSON → uint32 → SSH wire
//     yolunda hiçbir daralma olmamalı),
//   - 0 < cols,rows <= 65535 aralığındadır,
//   - WantReply taşımaz: WS'te cevap kanalı yok, cevap bekleyen bir
//     request'i kimse yanıtlayamaz.
//
// Bu, internal/proxy'deki resize taşmasının tarayıcı tarafındaki ikizi:
// JSON negatif sayıyı uint32'ye almaz ama 4294967295'i alır ve o sayı
// broker'da int()'e daralarak hedefe gider.
func FuzzHandleControl(f *testing.F) {
	f.Add([]byte(`{"type":"resize","cols":120,"rows":30}`))
	f.Add([]byte(`{"type":"resize","cols":1,"rows":1}`))
	// Sınırın tam üstünde duran tohum: tek bir rakam eklenmesi motoru
	// doğrudan taşma bölgesine götürüyor.
	f.Add([]byte(`{"type":"resize","cols":65535,"rows":65535}`))
	f.Add([]byte(`{"type":"resize","cols":0,"rows":0}`))
	f.Add([]byte(`{"type":"resize","cols":-1,"rows":24}`))
	f.Add([]byte(`{"type":"resize","cols":"80","rows":24}`))
	f.Add([]byte(`{"type":"ping"}`))
	f.Add([]byte(`{"type":"resize","cols":80,"rows":24,"unknown":true}`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Tampon boyutu üretimdekiyle aynı (newWSChannel): "taşarsa
		// düşür" davranışını da kapsasın diye.
		c := &wsChannel{reqs: make(chan *ssh.Request, 8)}

		c.handleControl(data)

		// handleControl senkron, kanal tamponlu: len kesin sayıdır.
		got := make([]*ssh.Request, 0, len(c.reqs))
		for len(c.reqs) > 0 {
			got = append(got, <-c.reqs)
		}

		if len(got) == 0 {
			return
		}
		if len(got) > 1 {
			t.Fatalf("tek mesaj %d request üretti: %+v", len(got), got)
		}

		req := got[0]
		if req.Type != "window-change" {
			t.Fatalf("kuyruğa %q girdi; istemciden gelen tek kontrol mesajı "+
				"resize ve karşılığı window-change", req.Type)
		}
		if req.WantReply {
			t.Errorf("window-change WantReply=true — WS'te cevap kanalı yok, " +
				"cevap bekleyen request'i kimse yanıtlayamaz")
		}

		p, err := proxy.ParseWindowChange(req.Payload)
		if err != nil {
			t.Fatalf("kuyruğa broker'ın çözemeyeceği payload girdi: %v", err)
		}

		// Referans çözüm: aynı JSON'u sayıyı DARALTMADAN oku. Amaç
		// "cols alanı ne diyorsa payload'da o var mı" — JSON ile SSH
		// wire'ı arasında sessiz bir dönüşüm olmadığının kanıtı.
		var ref struct {
			Cols json.Number `json:"cols"`
			Rows json.Number `json:"rows"`
		}
		if err := json.Unmarshal(data, &ref); err != nil {
			t.Fatalf("üretim kabul etti ama referans çözemedi: %v", err)
		}
		wantCols, colErr := strconv.ParseUint(ref.Cols.String(), 10, 64)
		wantRows, rowErr := strconv.ParseUint(ref.Rows.String(), 10, 64)
		if colErr != nil || rowErr != nil {
			t.Fatalf("kuyruğa girdi ama cols/rows tam sayı değil: %q/%q",
				ref.Cols, ref.Rows)
		}
		if uint64(p.Columns) != wantCols || uint64(p.Rows) != wantRows {
			t.Fatalf("JSON %s×%s dedi, payload %d×%d taşıyor",
				ref.Cols, ref.Rows, p.Columns, p.Rows)
		}

		if p.Columns == 0 || p.Rows == 0 {
			t.Errorf("sıfır boyut kuyruğa girdi: %d×%d", p.Columns, p.Rows)
		}
		if p.Columns > maxTerminalDim || p.Rows > maxTerminalDim {
			t.Errorf("boyut pty sınırını (%d) aşıyor: %d×%d — hedefte "+
				"TIOCSWINSZ'e giderken 16 bit'e sığdırılır ve kayıt ile "+
				"gerçek terminal ayrışır", maxTerminalDim, p.Columns, p.Rows)
		}
	})
}

// --- 2. sameOriginURL -------------------------------------------------

// fuzzExternalURL, hedefin sabit "bizim adresimiz" tarafı.
//
// Sabit olması şart: sameOriginURL'in sınanan yanı SALDIRGANIN
// yazabildiği taraf, yani Origin başlığı. Dış adres yapılandırmadan
// gelir ve saldırgan ona dokunamaz.
const fuzzExternalURL = "https://postern.sirket.local:8443"

// FuzzSameOriginURL checks the accept set of the WebSocket origin guard.
//
// Neden bu fonksiyon: /api/terminal'de tarayıcı SameSite kuralını
// UYGULAMAZ ve CORS da WS'i kapsamaz. Kurbanın cookie'siyle bağlanmaya
// çalışan kötü niyetli bir sayfaya karşı tek engel bu karşılaştırma ve
// girdisi ham, saldırgan tarafından yazılan bir başlık.
//
// Denetlenen özellik KAPSAMA: kabul edilen her origin, url.Parse'a göre
// dış adresle harf duyarsız AYNI şema ve AYNI host'u taşımak zorunda.
// Ters yön bilerek denetlenmiyor — reddetmek her zaman güvenlidir,
// kabul etmek değil.
func FuzzSameOriginURL(f *testing.F) {
	f.Add(fuzzExternalURL)
	f.Add("https://POSTERN.SIRKET.LOCAL:8443")
	f.Add("HTTPS://postern.sirket.local:8443")
	f.Add("https://postern.sirket.local")
	f.Add("https://postern.sirket.local:8443/")
	f.Add("http://postern.sirket.local:8443")
	f.Add("https://evil.example/")
	f.Add("https://postern.sirket.local:8443@evil.example")
	f.Add("https://evil.example@postern.sirket.local:8443")
	f.Add("https://postern.sirket.local:08443")
	f.Add("null")
	f.Add("")
	f.Add("//postern.sirket.local:8443")

	ext, err := url.Parse(fuzzExternalURL)
	if err != nil {
		f.Fatalf("sabit dış adres ayrıştırılamadı: %v", err)
	}

	f.Fuzz(func(t *testing.T, origin string) {
		if !sameOriginURL(origin, fuzzExternalURL) {
			return
		}

		u, err := url.Parse(origin)
		if err != nil {
			t.Fatalf("kabul edilen origin %q ayrıştırılamıyor: %v", origin, err)
		}
		if !strings.EqualFold(u.Scheme, ext.Scheme) {
			t.Errorf("origin %q kabul edildi ama şeması %q, bizimki %q",
				origin, u.Scheme, ext.Scheme)
		}
		if !strings.EqualFold(u.Host, ext.Host) {
			t.Errorf("origin %q kabul edildi ama host'u %q, bizimki %q",
				origin, u.Host, ext.Host)
		}
		// Host'u olmayan bir origin asla geçmemeli. Sabit dış adresle
		// bu koşul yukarıdakinden zaten çıkıyor; burada durmasının
		// sebebi dış adresin BOŞ olduğu hâli sabitlemek — o durumda
		// "null" ve "/x" gibi origin'ler eşleşir (bkz.
		// TestSameOriginURLShapes).
		if u.Host == "" {
			t.Errorf("host'suz origin %q kabul edildi", origin)
		}
	})
}

// TestSameOriginURLShapes documents which origin shapes the guard accepts.
//
// Fuzz hedefi "kabul edilen her şey aynı host'u taşır" diyor; bu tablo
// bir adım ötesini yazıya döküyor: userinfo, yol, sorgu ve parça taşıyan
// origin'ler de GEÇİYOR. Delik değil — tarayıcı Origin başlığını asla o
// biçimde göndermez ve host yine de tutmak zorunda — ama davranışın
// kendiliğinden değişmediğini görmek istiyoruz.
func TestSameOriginURLShapes(t *testing.T) {
	cases := []struct {
		origin string
		want   bool
		why    string
	}{
		{fuzzExternalURL, true, "tam eşleşme"},
		{"HTTPS://POSTERN.SIRKET.LOCAL:8443", true, "şema ve host harf duyarsız"},
		{"https://user:pass@postern.sirket.local:8443", true, "userinfo yok sayılır; host yine tutuyor"},
		{"https://postern.sirket.local:8443/a?b=c#d", true, "yol/sorgu/parça yok sayılır"},
		{"http://postern.sirket.local:8443", false, "şema farkı"},
		{"https://postern.sirket.local", false, "port farkı (varsayılan port genişletilmiyor)"},
		{"https://postern.sirket.local:08443", false, "port metni birebir karşılaştırılıyor"},
		{"https://postern.sirket.local.:8443", false, "sondaki nokta ayrı host sayılıyor"},
		{"https://postern.sirket.local:8443@evil.example", false, "asıl host userinfo'ya kayıyor — doğru karar"},
		{"null", false, "sandbox'lı iframe'in gönderdiği origin"},
		{"//postern.sirket.local:8443", false, "şemasız"},
		{"", false, "boş"},
	}

	for _, tc := range cases {
		if got := sameOriginURL(tc.origin, fuzzExternalURL); got != tc.want {
			t.Errorf("sameOriginURL(%q) = %v, beklenen %v (%s)", tc.origin, got, tc.want, tc.why)
		}
	}

	// Dış adres BOŞSA kontrol çöküyor: şemasız/host'suz her origin
	// eşleşir, "null" dahil. Yapılandırma bu hâle izin vermiyor
	// (config.Validate: terminal_enabled ⇒ https ya da loopback bir
	// external_url), yani ulaşılabilir değil — ama EnableTerminal'e
	// boş dize geçiren bir gelecek değişiklik bu satırda görünsün.
	if !sameOriginURL("null", "") {
		t.Error("boş dış adres davranışı değişmiş — artık \"null\" reddediliyor; " +
			"iyi haber, ama testin bu notu güncellenmeli")
	}
}

// --- 3. spaHandler ----------------------------------------------------

// distContents indexes every embedded file by the SHA-256 of its bytes.
//
// Ada göre değil İÇERİĞE göre: Vite çıktısındaki dosya adları içerik
// özeti taşıyor (index-Cu_nacil.js) ve arayüzün her düzenlemesinde
// değişiyor. Ada bakan bir test ilk UI değişikliğinde kırmızıya döner ve
// gerçek bir şey söylemez.
func distContents(t testing.TB, dist fs.FS) map[[32]byte]string {
	t.Helper()

	out := map[[32]byte]string{}
	err := fs.WalkDir(dist, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(dist, p)
		if err != nil {
			return err
		}
		out[sha256.Sum256(b)] = p
		return nil
	})
	if err != nil {
		t.Fatalf("gömülü dosya sistemi gezilemedi: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("web/dist boş — hedef hiçbir şeyi ispatlayamaz")
	}
	return out
}

// FuzzSPAPath checks what bytes the SPA handler can be made to return.
//
// Denetlenen özellik: 200 dönen HER cevabın gövdesi, gömülü dosya
// sistemindeki bir dosyanın TAM baytlarıdır. Ne 5xx, ne panik, ne de
// gömülü ağacın dışından/üretilmiş bir içerik.
//
// Özellik dosya ADI üzerinden değil İÇERİK üzerinden kuruluyor: Vite
// çıktısındaki adlar içerik özeti taşıyor ve her UI düzenlemesinde
// değişiyor.
//
// 3xx ve 4xx dışarıda: yönlendirme (dizin → "/", "/index.html" → "./")
// ve stdlib'in "invalid URL path" reddi gövde olarak dosya İÇERMEZ,
// dolayısıyla sızdıracak bir şeyleri de yok.
func FuzzSPAPath(f *testing.F) {
	dist := web.Dist()
	contents := distContents(f, dist)

	f.Add("/")
	f.Add("/index.html")
	f.Add("/sessions")
	f.Add("/targets/web01")
	f.Add("/assets")
	f.Add("/nope")
	f.Add("/..")
	f.Add("/a/../../etc/passwd")
	f.Add("//")
	f.Add("/./")
	f.Add("")
	f.Add("\x00")

	// Gerçek varlık yolları tohuma buradan giriyor: adlar derleme
	// çıktısından okunuyor, teste sabitlenmiyor.
	for _, p := range contents {
		f.Add("/" + p)
	}

	h := spaHandler()

	f.Fuzz(func(t *testing.T, urlPath string) {
		// İstek elle kuruluyor: httptest.NewRequest hedefi
		// ayrıştıramazsa PANİKLER ve fuzz motoru o paniği bizim
		// hatamız sanardı. Handler yalnızca r.URL.Path'e bakıyor,
		// dolayısıyla ÇÖZÜLMÜŞ yolu doğrudan koymak modeli bozmuyor.
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.URL.Path = urlPath

		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		res := w.Result()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("gövde okunamadı: %v", err)
		}

		if res.StatusCode >= 500 {
			t.Fatalf("path %q → %d: statik bir dosya sunucusunun sunucu "+
				"hatası verebileceği bir durum yok", urlPath, res.StatusCode)
		}
		if res.StatusCode != http.StatusOK {
			return
		}

		if _, ok := contents[sha256.Sum256(body)]; !ok {
			t.Fatalf("path %q → 200 ama gövde (%d bayt) gömülü dosyaların "+
				"hiçbiri değil; sözleşme \"dosya varsa dosya, yoksa "+
				"index.html\": %.120q", urlPath, len(body), body)
		}
	})
}

// ⚠️ EKSİK Origin BAŞLIĞI GEÇMEMELİ.
//
// Eskiden yokluğunda kontrol true dönüyordu — güvenlik başlığının
// yokluğunda açık kalmak, sonradan ısıran desenin ta kendisi.
// Tarayıcılar WebSocket el sıkışmasında Origin'i her zaman gönderir ve
// siteler arası bir sayfa onu bastıramaz; kontrolün dayandığı şey bu.
func TestTerminalOriginCheckRejectsMissingHeader(t *testing.T) {
	s := &Server{externalURL: "https://postern.sirket.local"}

	cases := map[string]bool{
		"":                             false, // eksik: reddedilmeli
		"https://postern.sirket.local": true,
		"HTTPS://POSTERN.SIRKET.LOCAL": true,  // şema/host harf duyarsız
		"http://postern.sirket.local":  false, // şema farklı
		"https://evil.example":         false,
		"null":                         false, // sandbox'lı iframe
		"https://postern.sirket.local.evil.example": false,
	}

	for origin, want := range cases {
		r := httptest.NewRequest("GET", "/api/terminal/web01", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if got := s.checkTerminalOrigin(r); got != want {
			t.Errorf("Origin %q = %v, beklenen %v", origin, got, want)
		}
	}
}
