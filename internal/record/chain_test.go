package record

import (
	"bytes"
	"strings"
	"testing"
)

// lineSpy, her Write çağrısını AYRI AYRI saklar — zincirin dayandığı
// "satır başına tek yazma" değişmezini ölçebilmek için.
type lineSpy struct {
	writes [][]byte
	buf    bytes.Buffer
}

func (l *lineSpy) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	l.writes = append(l.writes, cp)

	return l.buf.Write(p)
}

func (l *lineSpy) Close() error { return nil }

/*
 * ⚠️ DOĞRULAMANIN TAMAMI BU DEĞİŞMEZE DAYANIYOR.
 *
 * Zincir yazarken halkalar Write ÇAĞRILARINA göre kuruluyor; doğrularken
 * ise dosya '\n' sonrasından ayrılıyor. İkisinin aynı sonucu vermesi,
 * her Write'ın tam olarak bir satır olmasına bağlı. Bir gün biri
 * writeEvent'i iki çağrıya bölerse (ör. önce satır, sonra '\n'), yazma
 * ve doğrulama sessizce ayrışır ve HER kayıt doğrulanamaz olur — bu test
 * o günü yakalar.
 */
func TestEveryWriteIsExactlyOneLine(t *testing.T) {
	spy := &lineSpy{}

	w, err := NewWriter(spy, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Output([]byte("merhaba")); err != nil {
		t.Fatal(err)
	}
	if err := w.Input([]byte("ls -la\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Resize(120, 40); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if len(spy.writes) == 0 {
		t.Fatal("hiç yazma olmadı")
	}
	for i, p := range spy.writes {
		if len(p) == 0 {
			t.Errorf("%d. yazma boş", i)
			continue
		}
		if p[len(p)-1] != '\n' {
			t.Errorf("%d. yazma '\\n' ile bitmiyor: %q", i, p)
		}
		if bytes.Count(p, []byte("\n")) != 1 {
			t.Errorf("%d. yazma birden çok satır taşıyor: %q", i, p)
		}
	}
}

// yaz, kısa bir kayıt üretip zincir başını döner.
func yaz(t *testing.T, out *nopCloser) (head string, links int64) {
	t.Helper()

	w, err := NewWriter(out, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Output([]byte("bir")); err != nil {
		t.Fatal(err)
	}
	if err := w.Output([]byte("iki")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	return w.Chain()
}

func TestChainVerifiesAWrittenRecording(t *testing.T) {
	out := &nopCloser{}
	head, links := yaz(t, out)

	if head == "" {
		t.Fatal("baş boş")
	}
	if links < 2 {
		t.Errorf("halka sayısı = %d, en az 2 bekleniyordu (başlık + olay)", links)
	}

	ok, got, err := VerifyChain(strings.NewReader(out.String()), head)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("yazılan kayıt kendi başıyla doğrulanmadı")
	}
	if got != links {
		t.Errorf("doğrulayıcı %d halka saydı, yazıcı %d yazdı", got, links)
	}
}

/*
 * ⚠️ ASIL ÖLÇÜM: değiştirilmiş bir kayıt doğrulamayı GEÇMEMELİ.
 *
 * Tek bir baytı çevirmek, kaydı "az değiştirmek" değil; bu özelliğin
 * varlık sebebi tam olarak o baytı görmek.
 */
func TestTamperedRecordingFailsVerification(t *testing.T) {
	out := &nopCloser{}
	head, _ := yaz(t, out)

	raw := []byte(out.String())
	i := bytes.Index(raw, []byte("bir"))
	if i < 0 {
		t.Fatal("kayıtta beklenen içerik yok")
	}
	raw[i] = 'B' // tek bayt

	ok, _, err := VerifyChain(bytes.NewReader(raw), head)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("değiştirilmiş kayıt doğrulamayı geçti — zincir bir şey kanıtlamıyor")
	}
}

/*
 * Kesilmiş kayıt: baş tutmamalı, ama halka sayısı NEREYE KADAR tuttuğunu
 * söylemeli. "Bozuk" demek yetmiyor; olay müdahalesinde asıl soru
 * kaydın nerede kesildiği.
 */
func TestTruncatedRecordingReportsHowFarItGot(t *testing.T) {
	out := &nopCloser{}
	head, links := yaz(t, out)

	raw := out.String()
	cut := strings.LastIndex(raw[:len(raw)-1], "\n")
	if cut < 0 {
		t.Fatal("kayıt tek satır, kesme testi anlamsız")
	}

	ok, got, err := VerifyChain(strings.NewReader(raw[:cut+1]), head)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("kesilmiş kayıt doğrulamayı geçti")
	}
	if got >= links {
		t.Errorf("kesilmiş dosyada %d halka sayıldı, tamı %d idi", got, links)
	}
}

/*
 * ⚠️ BAŞLIK DA ZİNCİRDE. Başlık zaman damgası ve terminal boyutu
 * taşıyor; zincirin dışında kalsaydı, bir kaydın ne zaman başladığı
 * sessizce değiştirilebilirdi.
 */
func TestChainCoversTheHeader(t *testing.T) {
	a, b := &nopCloser{}, &nopCloser{}

	w1, err := NewWriter(a, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := w1.Close(); err != nil {
		t.Fatal(err)
	}
	h1, _ := w1.Chain()

	w2, err := NewWriter(b, 120, 40, nil) // yalnızca boyut farklı
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	h2, _ := w2.Chain()

	if h1 == h2 {
		t.Fatal("farklı başlıklar aynı zincir başını verdi — başlık kapsanmıyor")
	}
}

// Yarım kalmış son satır (disk dolması) zincirin dışında bırakılmamalı.
func TestPartialFinalLineIsStillALink(t *testing.T) {
	full := "{\"version\":2}\n[0.1,\"o\",\"x\"]\n"
	partial := full + "[0.2,\"o\",\"kes"

	okFull, linksFull, err := VerifyChain(strings.NewReader(full), "")
	if err != nil {
		t.Fatal(err)
	}
	okPart, linksPart, err := VerifyChain(strings.NewReader(partial), "")
	if err != nil {
		t.Fatal(err)
	}
	if okFull || okPart {
		t.Fatal("boş beklenen başla doğrulama geçti")
	}
	if linksPart != linksFull+1 {
		t.Errorf("yarım son satır halka sayılmadı: tam=%d yarım=%d", linksFull, linksPart)
	}
}

// Kayıtsız yazıcı (w nil) boş baş döner, panik etmez.
func TestNilWriterHasNoChain(t *testing.T) {
	w, err := NewWriter(nil, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	head, links := w.Chain()
	if head != "" || links != 0 {
		t.Errorf("kayıtsız yazıcıda baş = %q/%d, boş bekleniyordu", head, links)
	}
}
