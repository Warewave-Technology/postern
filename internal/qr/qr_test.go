package qr

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
)

/*
 * ⚠️ REFERANS MATRİSLER BİZİM KODUMUZDAN GELMİYOR.
 *
 * testdata/coreimage.json, Apple CoreImage'in (CIQRCodeGenerator)
 * ürettiği modül matrisleri: bağımsız, olgun, bizimkini hiç görmemiş bir
 * uygulama. Kendi çıktımızdan üretilmiş altın dosyalar yalnızca
 * gerilemeyi yakalar, DOĞRULUĞU hiç ölçmez — yanlış bir kodlayıcı kendi
 * çıktısıyla mükemmel uyumludur.
 *
 * Bu ayrım burada teorik değil. Elle yazılmış bir QR kodlayıcının en
 * olası arızası "kod okunmuyor" değil, TARANABİLİR AMA YANLIŞ bir kod
 * üretmek: kullanıcı okutur, uygulaması yanlış bir sır kaydeder, ve
 * arıza günler sonra "kodlarım hiç tutmuyor" olarak çıkar. O noktada
 * kişi hesabına giremez.
 *
 * ⚠️ YÜKLER SADECE KÜÇÜK HARF — bilerek. CoreImage girdiyi bölütleyip
 * mod karıştırabiliyor (büyük harf+rakam koşularını alfanümerik moda
 * alıyor) ve o zaman BİZDEN KÜÇÜK bir sürüm seçiyor. Bu bir hata değil,
 * başka bir tasarım kararı; ama karşılaştırmayı anlamsız kılar. Küçük
 * harfler alfanümerik kümede olmadığı için her iki taraf da bayt modu
 * kullanmak zorunda kalıyor ve matrisler karşılaştırılabilir oluyor.
 * (İlk denemede bu gözden kaçtı: 97 vakanın 89'u "ayrışıyor" göründü ve
 * sebep bizim kodumuz değil, bu bölütlemeydi.)
 */

type refCase struct {
	Text    string `json:"text"`
	Level   string `json:"level"`
	Size    int    `json:"size"`
	Version int    `json:"version"`
	Bits    string `json:"bits"`
}

func (c refCase) rows(t *testing.T) []string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(c.Bits)
	if err != nil {
		t.Fatalf("referans bozuk: %v", err)
	}
	var sb strings.Builder
	for _, b := range raw {
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) != 0 {
				sb.WriteByte('1')
			} else {
				sb.WriteByte('0')
			}
		}
	}
	bits := sb.String()
	out := make([]string, c.Size)
	for y := 0; y < c.Size; y++ {
		out[y] = bits[y*c.Size : (y+1)*c.Size]
	}
	return out
}

func levelOf(t *testing.T, s string) Level {
	t.Helper()
	switch s {
	case "L":
		return L
	case "M":
		return M
	case "Q":
		return Q
	case "H":
		return H
	}
	t.Fatalf("bilinmeyen seviye %q", s)
	return L
}

func loadRefs(t *testing.T) []refCase {
	t.Helper()
	b, err := os.ReadFile("testdata/coreimage.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []refCase
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	/*
	 * ⚠️ KAPSAM İDDİA EDİLMİYOR, SAYILIYOR.
	 *
	 * Dosyada 40 sürüm x 4 seviye = 160 hücrenin HER BİRİ için bir vaka
	 * var. Kırpılmış ya da eksik bir referans dosyası, testi sessizce
	 * dar bir bantta koşar hâle getirir ve yeşil kalır — o yüzden
	 * eksiksizlik burada doğrulanıyor.
	 */
	if len(cases) != 160 {
		t.Fatalf("referans vaka sayısı = %d, 160 bekleniyordu (40 sürüm x 4 seviye)", len(cases))
	}
	cells := map[[2]string]bool{}
	for _, c := range cases {
		cells[[2]string{c.Level, string(rune('a' + c.Version))}] = true
	}
	if len(cells) != 160 {
		t.Fatalf("kapsanan hücre = %d, 160 bekleniyordu — bazı sürüm/seviye "+
			"birleşimleri hiç sınanmıyor", len(cells))
	}
	return cases
}

func render(m [][]bool) []string {
	out := make([]string, len(m))
	for y, row := range m {
		var sb strings.Builder
		for _, dark := range row {
			if dark {
				sb.WriteByte('1')
			} else {
				sb.WriteByte('0')
			}
		}
		out[y] = sb.String()
	}
	return out
}

/*
 * maskOf, bir matristen KULLANILAN MASKEYİ okur.
 *
 * Biçim bilgisi 15 bit ve 0x5412 ile maskelenmiş; üst 5 biti seviye+maske
 * taşıyor. Referansın seçtiği maskeyi buradan çıkarıp kendi kodlayıcımıza
 * dayatıyoruz — sebebi aşağıdaki testte.
 */
func maskOf(rows []string) int {
	get := func(y, x int) int {
		if rows[y][x] == '1' {
			return 1
		}
		return 0
	}
	bits := 0
	for i := 0; i <= 5; i++ {
		bits |= get(i, 8) << uint(i)
	}
	bits |= get(7, 8) << 6
	bits |= get(8, 8) << 7
	bits |= get(8, 7) << 8
	for i := 9; i < 15; i++ {
		bits |= get(8, 14-i) << uint(i)
	}
	return (bits ^ 0x5412) >> 10 & 7
}

/*
 * ⚠️ MASKE REFERANSINKİNE SABİTLENEREK KARŞILAŞTIRILIYOR.
 *
 * Maske seçimi bir SEZGİSELDİR, doğruluk değil: sekiz maskenin hepsi
 * geçerli, hangisinin kullanıldığı biçim bilgisinde yazılı, her çözücü
 * hepsini okuyor. Standardın 3. ceza kuralı birden çok okumaya açık ve
 * olgun uygulamalar bu yüzden ~%3 girdide farklı (ikisi de geçerli)
 * maske seçiyor.
 *
 * Maskeyi sabitlemek, geriye kalan HER ŞEYİ tam olarak sınıyor: sürüm
 * seçimi, mod ve uzunluk alanları, dolgu, Reed-Solomon kelimeleri, blok
 * bölme ve ARALAMA, işlev desenleri, hizalama, sürüm bilgisi ve biçim
 * bilgisi. Veriyi bozabilecek ne varsa burada.
 */
func TestMatchesIndependentEncoderAtItsOwnMask(t *testing.T) {
	cases := loadRefs(t)
	versions := map[int]bool{}
	levels := map[string]bool{}

	for _, c := range cases {
		want := c.rows(t)
		got, err := encode(c.Text, levelOf(t, c.Level), maskOf(want))
		if err != nil {
			t.Errorf("len=%d %s: %v", len(c.Text), c.Level, err)
			continue
		}
		versions[c.Version] = true
		levels[c.Level] = true

		if len(got) != c.Size {
			t.Errorf("len=%d %s: boyut = %d, %d bekleniyordu (sürüm %d) — "+
				"yanlış sürüm seçimi veriyi sessizce kaybettirir",
				len(c.Text), c.Level, len(got), c.Size, c.Version)
			continue
		}
		gotRows := render(got)
		for y := range want {
			if gotRows[y] != want[y] {
				t.Errorf("len=%d %s sürüm %d: %d. satır ayrışıyor\n  bizim    : %s\n  bağımsız : %s",
					len(c.Text), c.Level, c.Version, y, gotRows[y], want[y])
				break
			}
		}
	}

	if len(versions) != 40 || len(levels) != 4 {
		t.Errorf("kapsanan sürüm = %d (40), seviye = %d (4)", len(versions), len(levels))
	}
}

/*
 * Encode'un KENDİ seçtiği maske de geçerli bir kod üretmeli ve boyutu
 * referansla aynı olmalı: sezgisel farkı yalnızca maskeyi değiştirir,
 * sürümü değil.
 */
func TestDefaultMaskKeepsTheSameVersion(t *testing.T) {
	for _, c := range loadRefs(t) {
		got, err := Encode(c.Text, levelOf(t, c.Level))
		if err != nil {
			t.Errorf("len=%d %s: %v", len(c.Text), c.Level, err)
			continue
		}
		if len(got) != c.Size {
			t.Errorf("len=%d %s: boyut = %d, %d bekleniyordu", len(c.Text), c.Level, len(got), c.Size)
		}
	}
}

// Seçilen maske, sekizi arasında EN DÜŞÜK cezalı olmalı — sezgiselin
// kendisi bozulursa kod hâlâ okunur ama gereksiz zor taranır.
func TestChosenMaskHasTheLowestPenalty(t *testing.T) {
	texts := []string{
		"a",
		"otpauth://totp/postern:yigit?algorithm=SHA1&digits=6&issuer=postern&period=30&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		strings.Repeat("kaptan", 60),
	}
	for _, txt := range texts {
		for _, lv := range []Level{L, M, Q, H} {
			chosen, err := Encode(txt, lv)
			if err != nil {
				t.Fatal(err)
			}
			best := penalty(chosen)
			for mask := 0; mask < 8; mask++ {
				alt, err := encode(txt, lv, mask)
				if err != nil {
					t.Fatal(err)
				}
				if p := penalty(alt); p < best {
					t.Errorf("len=%d seviye=%d: maske %d cezası %d, seçilenin cezası %d — "+
						"daha iyi bir maske varken seçilmemiş", len(txt), lv, mask, p, best)
				}
			}
		}
	}
}

/*
 * ⚠️ SIĞMAYAN VERİ HATA VERMELİ, KIRPILMAMALI.
 *
 * Sessizce kırpan bir kodlayıcı taranabilir ama YANLIŞ bir kod üretir:
 * kullanıcı okutur, uygulaması eksik bir sır kaydeder, ve arıza kodun
 * okunduğu yerde değil günler sonra ortaya çıkar.
 */
func TestOversizedDataIsRefused(t *testing.T) {
	if _, err := Encode(strings.Repeat("a", 2953), L); err != nil {
		t.Fatalf("sürüm 40-L tam kapasitesi reddedildi: %v", err)
	}
	if _, err := Encode(strings.Repeat("a", 2954), L); err == nil {
		t.Fatal("kapasitenin üstündeki veri kabul edildi — kod sessizce " +
			"kırpılmış olur ve yanlış bir sır taranır")
	}
	// Yüksek düzeltme seviyesi daha az veri taşır.
	if _, err := Encode(strings.Repeat("a", 2953), H); err == nil {
		t.Fatal("H seviyesinde L kapasitesi kabul edildi")
	}
}

func TestSmallestVersionIsChosen(t *testing.T) {
	m, err := Encode("a", L)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 21 {
		t.Fatalf("boyut = %d, 21 bekleniyordu — en küçük sürüm seçilmiyor", len(m))
	}
}

func TestMatrixIsSquare(t *testing.T) {
	m, err := Encode("otpauth://totp/postern:yigit?secret=ABCDEFGH", M)
	if err != nil {
		t.Fatal(err)
	}
	for y, row := range m {
		if len(row) != len(m) {
			t.Fatalf("%d. satır %d hücre, %d bekleniyordu", y, len(row), len(m))
		}
	}
}

func TestInvalidLevelIsRefused(t *testing.T) {
	if _, err := Encode("a", Level(9)); err == nil {
		t.Fatal("geçersiz seviye kabul edildi")
	}
	if _, err := Encode("a", Level(-1)); err == nil {
		t.Fatal("negatif seviye kabul edildi")
	}
}

// Boş girdi ve çok baytlı UTF-8 panik ETMEMELİ: değerler kullanıcı
// adından geliyor ve orada Türkçe harf olması olağan.
func TestOddInputsDoNotPanic(t *testing.T) {
	if _, err := Encode("", M); err != nil {
		t.Logf("boş girdi hata veriyor (kabul edilebilir): %v", err)
	}
	if _, err := Encode("otpauth://totp/postern:şüheda?secret=ABCDEFGH", M); err != nil {
		t.Fatalf("çok baytlı kullanıcı adı reddedildi: %v", err)
	}
}

/*
 * ⚠️ EŞZAMANLI KULLANIM NORMAL AKIŞ.
 *
 * Bu paket HTTP işleyicisinden çağrılıyor. Sürüm tablolarını ilk çağrıda
 * dolduran tembel bir önbellek burada veri yarışı üretirdi — ve yazılan
 * değerler aynı olduğu için çoğu koşuda SESSİZ kalırdı. Bu test yarış
 * dedektörü altında koşuyor (make ci: test-race).
 */
func TestConcurrentEncodeIsSafe(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if _, err := Encode("otpauth://totp/postern:yigit?secret=ABCDEFGH", M); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}
