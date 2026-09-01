// Package qr encodes data as a QR Code symbol (ISO/IEC 18004), byte mode.
//
// NEDEN VAR: TOTP kaydında kullanıcıya bir `otpauth://` bağlantısı
// veriliyor ve o bağlantıyı telefona geçirmenin normal yolu QR. Elle
// giriş de duruyor (kamerasız masaüstü, kodu başka cihaza taşıyan
// kullanıcı) ama tek yol olarak bırakmak, herkesi 32 karakter yazmaya
// zorlamak demekti.
//
// ⚠️ NEDEN BAĞIMLILIK DEĞİL, NEDEN PANELDE DEĞİL:
//
// Elle yazılmış bir QR kodlayıcının en olası arızası "çalışmıyor" değil,
// TARANABİLİR AMA YANLIŞ bir kod üretmek. Kullanıcı okutur, uygulaması
// yanlış bir sır kaydeder, ve arıza günler sonra "kodlarım hiç tutmuyor"
// olarak ortaya çıkar — o noktada kişi hesabına giremez. Bu yüzden bu
// paketin doğruluğu İDDİA EDİLMİYOR, ÖLÇÜLÜYOR: çıktı, Apple CoreImage'in
// (CIQRCodeGenerator) ürettiği matrislerle bit bit karşılaştırılıyor —
// 40 sürümün tamamı, dört düzeltme seviyesi (qr_test.go). Referans
// bizim kodumuzdan değil, bizimkini hiç görmemiş olgun bir uygulamadan
// geliyor; kendi çıktısından üretilen altın dosyalar yalnızca gerilemeyi
// yakalar, doğruluğu hiç ölçmez.
//
// Kodlayıcı sunucuda: panelde ikinci bir uygulama tutmak, ikinci bir
// doğrulama yükü ve sessizce ayrışabilecek iki gerçek demek olurdu.
package qr

import (
	"errors"
	"fmt"
)

// Level is the error correction level.
type Level int

const (
	L Level = iota // ~7% recovery
	M              // ~15%
	Q              // ~25%
	H              // ~30%
)

/*
 * ⚠️ YALNIZCA BAYT MODU.
 *
 * QR'ın sayısal ve alfanümerik modları daha sıkı paketliyor ve olgun
 * kodlayıcılar (CoreImage dahil) girdiyi bölütleyip mod karıştırarak
 * bir sürüm kazanabiliyor. Burada bilerek yapmıyoruz:
 *
 *   - Kazanç bizim yükümüzde yok denecek kadar az. Tipik otpauth
 *     bağlantısı 117 bayt; bayt modunda sürüm 7 (45x45), bölütlemeyle
 *     sürüm 6 (41x41). İkisi de rahat taranıyor.
 *   - Bedeli gerçek: bölütleme ayrı bir eniyileme problemi, ve
 *     kullanılmayan bir mod kolu test edilmemiş bir kol demek. Bu
 *     paketin bütün güvencesi ÖLÇÜLMÜŞ olmasından geliyor; ölçemediğimiz
 *     bir kol o güvenceyi zayıflatır.
 */
const modeByte = 4

// formatBits, seviyenin biçim bilgisindeki 2 bitlik göstergesi.
// Sıra L,M,Q,H değil — standart bu değerleri böyle atıyor.
var formatBits = [4]int{1, 0, 3, 2}

/*
 * Blok başına düzeltme kelimesi ve blok sayısı (ISO/IEC 18004 Tablo 13-22).
 *
 * ⚠️ HESAPLANMIYOR, YAZILIYOR. Bu değerlerin kapalı bir formülü yok;
 * standart bunları tablo olarak veriyor. Tek bir yanlış satır, o sürüme
 * düşen her kodu bozar — ve bozukluk "kod okunmuyor" değil, "kod
 * okunuyor ama veri yanlış" biçiminde çıkabilir. Bu yüzden tabloların
 * doğruluğu, 40 sürümün tamamının bağımsız bir uygulamayla
 * karşılaştırıldığı testle sabitleniyor.
 */
var ecCodewordsPerBlock = [4][41]int{
	{-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	{-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
	{-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	{-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
}

var numECBlocks = [4][41]int{
	{-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},
	{-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},
	{-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},
	{-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},
}

// numRawDataModules, veri ve düzeltme kelimelerine kalan modül sayısı.
func numRawDataModules(ver int) int {
	result := (16*ver+128)*ver + 64
	if ver >= 2 {
		numAlign := ver/7 + 2
		result -= (25*numAlign-10)*numAlign - 55
		if ver >= 7 {
			// Sürüm 7'den itibaren iki adet 18 modüllük sürüm bilgisi.
			result -= 36
		}
	}
	return result
}

func totalCodewords(ver int) int { return numRawDataModules(ver) / 8 }

func dataCodewords(ver int, lvl Level) int {
	return totalCodewords(ver) - ecCodewordsPerBlock[lvl][ver]*numECBlocks[lvl][ver]
}

// charCountBits, bayt modunda karakter sayısı alanının genişliği.
func charCountBits(ver int) int {
	if ver <= 9 {
		return 8
	}
	return 16
}

// byteCapacity, bir sürüm/seviye çiftinin taşıyabileceği en fazla bayt.
func byteCapacity(ver int, lvl Level) int {
	avail := dataCodewords(ver, lvl)*8 - 4 - charCountBits(ver)
	if avail < 0 {
		return 0
	}
	n := avail / 8
	// ⚠️ Sayı alanı kendi taşıyabileceğinden fazlasını ifade edemez.
	// Bu sınır olmadan, uzunluğu alana sığmayan bir yük "sığıyor"
	// sayılır ve kodlanan uzunluk sessizce sarardı.
	if max := (1 << charCountBits(ver)) - 1; n > max {
		n = max
	}
	return n
}

// alignmentPatternPositions, hizalama desenlerinin merkez koordinatları.
func alignmentPatternPositions(ver int) []int {
	if ver == 1 {
		return nil
	}
	numAlign := ver/7 + 2
	step := (ver*4 + numAlign*2 + 1) / (numAlign*2 - 2) * 2
	if ver == 32 {
		// ⚠️ Sürüm 32 standardın TEK istisnası: formül 26 vermiyor,
		// tablo veriyor. Formüle güvenen bir uygulama yalnızca bu
		// sürümde bozuk kod üretir ve bunu ancak o boyutta bir yük
		// denendiğinde fark eder.
		step = 26
	}
	result := make([]int, numAlign)
	result[0] = 6
	for i, pos := numAlign-1, ver*4+10; i >= 1; i, pos = i-1, pos-step {
		result[i] = pos
	}
	return result
}

// --- GF(256), ilkel polinom x^8+x^4+x^3+x^2+1 (0x11D) -----------------

func gfMul(a, b byte) byte {
	var z byte
	for i := 7; i >= 0; i-- {
		z = byte(int(z)<<1) ^ byte((int(z)>>7)*0x11D)
		z ^= byte((int(b)>>uint(i))&1) * a
	}
	return z
}

// rsGenerator, verilen dereceden Reed-Solomon bölen polinomu.
func rsGenerator(degree int) []byte {
	result := make([]byte, degree)
	result[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := 0; j < degree; j++ {
			result[j] = gfMul(result[j], root)
			if j+1 < degree {
				result[j] ^= result[j+1]
			}
		}
		root = gfMul(root, 0x02)
	}
	return result
}

// rsRemainder, veri bloğunun düzeltme kelimeleri.
func rsRemainder(data, divisor []byte) []byte {
	result := make([]byte, len(divisor))
	for _, b := range data {
		factor := b ^ result[0]
		copy(result, result[1:])
		result[len(result)-1] = 0
		for i, d := range divisor {
			result[i] ^= gfMul(d, factor)
		}
	}
	return result
}

type bitBuffer []bool

func (b *bitBuffer) appendBits(val uint32, n int) {
	for i := n - 1; i >= 0; i-- {
		*b = append(*b, (val>>uint(i))&1 != 0)
	}
}

// --- kodlama ----------------------------------------------------------

// Encode returns the module matrix for data, true = dark. No quiet zone.
// It picks the smallest version that fits.
//
// ⚠️ DURUM TUTMUYOR VE TEMBEL ÖNBELLEK YOK. Bu paket HTTP işleyicisinden
// çağrılıyor, yani eşzamanlı kullanım normal akış. Sürüm tablolarını ilk
// çağrıda dolduran bir önbellek, aynı anda gelen iki istekte veri yarışı
// üretirdi — değerler aynı olduğu için de çoğu koşuda sessiz kalırdı.
func Encode(data string, level Level) ([][]bool, error) {
	return encode(data, level, -1)
}

/*
 * encode, forceMask >= 0 ise maskeyi SEÇMEZ, dayatır.
 *
 * ⚠️ NEDEN VAR: maske seçimi bir SEZGİSELDİR, doğruluk değil. Sekiz
 * maskenin hepsi geçerli; hangisinin kullanıldığı biçim bilgisinde
 * yazılı ve her çözücü hepsini okuyor. Ceza kurallarının işi yalnızca
 * tarayıcıyı zorlayan desenlerden kaçınmak — ve standardın 3. kuralı
 * birden çok okumaya açık, olgun uygulamalar bu yüzden bazı girdilerde
 * farklı (ikisi de geçerli) maskeler seçiyor.
 *
 * Test bunu kullanıyor: referans uygulamanın SEÇTİĞİ maske dayatılınca
 * matrisler bit bit aynı çıkmalı. Böylece veri kodlaması, düzeltme
 * kelimeleri, aralama ve yerleşim tam olarak sınanıyor; sezgisel
 * ayrışma testi bulandırmıyor.
 */
func encode(data string, level Level, forceMask int) ([][]bool, error) {
	if level < L || level > H {
		return nil, fmt.Errorf("qr: invalid error correction level %d", int(level))
	}
	payload := []byte(data)

	ver := 0
	for v := 1; v <= 40; v++ {
		if len(payload) <= byteCapacity(v, level) {
			ver = v
			break
		}
	}
	/*
	 * ⚠️ SIĞMIYORSA HATA — KIRPMA YOK.
	 *
	 * Sessizce kırpan bir kodlayıcı taranabilir ama YANLIŞ bir kod
	 * üretir: kullanıcı okutur, uygulaması eksik bir sır kaydeder, ve
	 * arıza kodun okunduğu yerde değil günler sonra ortaya çıkar.
	 */
	if ver == 0 {
		return nil, errors.New("qr: data too long for any QR version")
	}

	codewords := buildCodewords(payload, ver, level)
	blocks := interleave(codewords, ver, level)

	size := ver*4 + 17
	base, isFunc := newTemplate(ver, size)
	drawCodewords(base, isFunc, blocks)

	if forceMask >= 0 {
		m := cloneMatrix(base)
		applyMask(m, isFunc, forceMask)
		drawFormatBits(m, isFunc, level, forceMask, size)
		return m, nil
	}

	var best [][]bool
	bestScore := 0
	for mask := 0; mask < 8; mask++ {
		m := cloneMatrix(base)
		applyMask(m, isFunc, mask)
		drawFormatBits(m, isFunc, level, mask, size)
		if score := penalty(m); best == nil || score < bestScore {
			bestScore, best = score, m
		}
	}
	return best, nil
}

/*
 * buildCodewords, mod göstergesi + uzunluk + yük + sonlandırıcı + dolgu.
 *
 * ⚠️ DEĞİŞMEZ: len(payload) <= byteCapacity(ver, lvl), yani en fazla
 * 2953. Çağıran (encode) sürümü tam bu koşula göre seçiyor ve
 * sığmıyorsa hata döndürüyor. Aşağıdaki uint32 dönüşümü bu yüzden
 * taşamaz — ama koşul BURADA görünmediği için bir gün başka bir
 * çağıran eklenirse sessizce bozulurdu. O yüzden yazılı, ve aşağıda
 * ayrıca doğrulanıyor.
 */
func buildCodewords(payload []byte, ver int, lvl Level) []byte {
	if n := byteCapacity(ver, lvl); len(payload) > n {
		// Buraya düşülmesi bir programlama hatasıdır: sessizce yanlış
		// uzunluk kodlamaktansa görünür biçimde çökmek yeğdir, çünkü
		// yanlış uzunluk taranabilir ama YANLIŞ bir kod üretir.
		panic("qr: payload exceeds the capacity of the chosen version")
	}
	var bb bitBuffer
	bb.appendBits(modeByte, 4)
	// #nosec G115 -- yukarıdaki değişmez len(payload) <= 2953 garantiliyor
	bb.appendBits(uint32(len(payload)), charCountBits(ver))
	for _, b := range payload {
		bb.appendBits(uint32(b), 8)
	}

	capacityBits := dataCodewords(ver, lvl) * 8
	// Sonlandırıcı en fazla dört sıfır bit — ama kalan yer daha azsa
	// o kadar. Koşulsuz dört bit yazmak kapasiteyi taşırırdı.
	term := capacityBits - len(bb)
	if term > 4 {
		term = 4
	}
	bb.appendBits(0, term)
	bb.appendBits(0, (8-len(bb)%8)%8)
	// Dönüşümlü dolgu baytları (standart 0xEC / 0x11).
	for pad := uint32(0xEC); len(bb) < capacityBits; pad ^= 0xEC ^ 0x11 {
		bb.appendBits(pad, 8)
	}

	out := make([]byte, len(bb)/8)
	for i, bit := range bb {
		if bit {
			out[i>>3] |= 1 << uint(7-i%8)
		}
	}
	return out
}

/*
 * interleave, veriyi bloklara böler, her bloğun düzeltme kelimelerini
 * hesaplar ve hepsini ARALAYARAK tek diziye yazar.
 *
 * ⚠️ ARALAMA HATASI EN SİNSİ HATA. Blokları sırayla yazan (aralamayan)
 * bir kodlayıcı, gözle bakınca doğru görünen bir kod üretir; kod
 * taranır ve yanlış veri çıkar ya da hafif bir lekede tamamen ölür.
 * Aralamanın amacı, fiziksel bir lekenin hasarını bloklara YAYMAK.
 */
func interleave(data []byte, ver int, lvl Level) []byte {
	numBlocks := numECBlocks[lvl][ver]
	ecLen := ecCodewordsPerBlock[lvl][ver]
	rawTotal := totalCodewords(ver)
	// Bloklar EŞİT UZUNLUKTA DEĞİL: bir kısmı bir kelime uzun.
	numShort := numBlocks - rawTotal%numBlocks
	shortLen := rawTotal/numBlocks - ecLen

	div := rsGenerator(ecLen)
	dataBlocks := make([][]byte, numBlocks)
	ecBlocks := make([][]byte, numBlocks)
	for i, k := 0, 0; i < numBlocks; i++ {
		n := shortLen
		if i >= numShort {
			n++
		}
		dataBlocks[i] = data[k : k+n]
		ecBlocks[i] = rsRemainder(dataBlocks[i], div)
		k += n
	}

	result := make([]byte, 0, rawTotal)
	for i := 0; i < shortLen+1; i++ {
		for j := 0; j < numBlocks; j++ {
			if i < len(dataBlocks[j]) {
				result = append(result, dataBlocks[j][i])
			}
		}
	}
	for i := 0; i < ecLen; i++ {
		for j := 0; j < numBlocks; j++ {
			result = append(result, ecBlocks[j][i])
		}
	}
	return result
}

// --- matris ------------------------------------------------------------

func newMatrix(size int) [][]bool {
	m := make([][]bool, size)
	cells := make([]bool, size*size)
	for i := range m {
		m[i] = cells[i*size : (i+1)*size : (i+1)*size]
	}
	return m
}

func cloneMatrix(src [][]bool) [][]bool {
	dst := newMatrix(len(src))
	for i := range src {
		copy(dst[i], src[i])
	}
	return dst
}

// newTemplate, işlev desenlerini çizer ve hangi modüllerin veri
// TAŞIMADIĞINI işaretler. İşaret olmadan veri, bulucu desenlerin üstüne
// yazılır ve kod hiç okunmaz.
func newTemplate(ver, size int) (m, isFunc [][]bool) {
	m = newMatrix(size)
	isFunc = newMatrix(size)

	set := func(x, y int, dark bool) {
		m[y][x] = dark
		isFunc[y][x] = true
	}

	for i := 0; i < size; i++ {
		set(6, i, i%2 == 0)
		set(i, 6, i%2 == 0)
	}

	drawFinder := func(cx, cy int) {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				dist := abs(dx)
				if abs(dy) > dist {
					dist = abs(dy)
				}
				x, y := cx+dx, cy+dy
				if x >= 0 && x < size && y >= 0 && y < size {
					set(x, y, dist != 2 && dist != 4)
				}
			}
		}
	}
	drawFinder(3, 3)
	drawFinder(size-4, 3)
	drawFinder(3, size-4)

	// Hizalama desenleri — bulucuların olduğu üç köşe ATLANIR.
	pos := alignmentPatternPositions(ver)
	n := len(pos)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if (i == 0 && j == 0) || (i == 0 && j == n-1) || (i == n-1 && j == 0) {
				continue
			}
			cx, cy := pos[j], pos[i]
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					dist := abs(dx)
					if abs(dy) > dist {
						dist = abs(dy)
					}
					set(cx+dx, cy+dy, dist != 1)
				}
			}
		}
	}

	reserveFormat(isFunc, size)
	m[size-8][8] = true // her zaman koyu modül

	// Sürüm bilgisi 7 ve üstünde; altında bu alan YOK ve veri taşır.
	if ver >= 7 {
		rem := ver
		for i := 0; i < 12; i++ {
			rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
		}
		bits := ver<<12 | rem
		for i := 0; i < 18; i++ {
			dark := (bits>>uint(i))&1 != 0
			a, b := size-11+i%3, i/3
			set(a, b, dark)
			set(b, a, dark)
		}
	}
	return m, isFunc
}

// reserveFormat, biçim bilgisinin kapladığı modülleri işaretler.
func reserveFormat(isFunc [][]bool, size int) {
	for i := 0; i <= 5; i++ {
		isFunc[i][8] = true
	}
	isFunc[7][8] = true
	isFunc[8][8] = true
	isFunc[8][7] = true
	for i := 9; i < 15; i++ {
		isFunc[8][14-i] = true
	}
	for i := 0; i < 8; i++ {
		isFunc[8][size-1-i] = true
	}
	for i := 8; i < 15; i++ {
		isFunc[size-15+i][8] = true
	}
	isFunc[size-8][8] = true
}

// drawFormatBits, seviye ve maskeyi taşıyan 15 bitlik biçim bilgisini
// İKİ KEZ yazar: bir kopyası zarar görürse kod yine okunabilsin diye.
func drawFormatBits(m, isFunc [][]bool, lvl Level, mask, size int) {
	data := formatBits[lvl]<<3 | mask
	rem := data
	for i := 0; i < 10; i++ {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	// ⚠️ 0x5412 maskesi ŞART: olmadan, biçim bilgisi tamamen sıfır olan
	// geçerli bir birleşim ortaya çıkar ve tarayıcı onu boş alan sanar.
	bits := (data<<10 | rem) ^ 0x5412

	get := func(i int) bool { return (bits>>uint(i))&1 != 0 }

	for i := 0; i <= 5; i++ {
		m[i][8] = get(i)
	}
	m[7][8] = get(6)
	m[8][8] = get(7)
	m[8][7] = get(8)
	for i := 9; i < 15; i++ {
		m[8][14-i] = get(i)
	}
	for i := 0; i < 8; i++ {
		m[8][size-1-i] = get(i)
	}
	for i := 8; i < 15; i++ {
		m[size-15+i][8] = get(i)
	}
	m[size-8][8] = true
}

// drawCodewords, kelimeleri iki modül genişliğinde zikzak sütunlar
// hâlinde yerleştirir; işlev modülleri atlanır.
func drawCodewords(m, isFunc [][]bool, cw []byte) {
	size := len(m)
	i := 0
	total := len(cw) * 8
	for right := size - 1; right >= 1; right -= 2 {
		// 6. sütun dikey zamanlama deseni: sütun sayacı onu ATLAR.
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				upward := ((right + 1) & 2) == 0
				y := vert
				if upward {
					y = size - 1 - vert
				}
				if !isFunc[y][x] && i < total {
					m[y][x] = (cw[i>>3]>>uint(7-i%8))&1 != 0
					i++
				}
				// Kalan modüller açık kalır (artık bitler).
			}
		}
	}
}

// maskBit, (x,y) modülünün bu maskede ters çevrilip çevrilmediği.
func maskBit(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (y/2+x/3)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	case 7:
		return ((x+y)%2+x*y%3)%2 == 0
	}
	panic("qr: unreachable mask")
}

func applyMask(m, isFunc [][]bool, mask int) {
	for y := range m {
		for x := range m[y] {
			if !isFunc[y][x] && maskBit(mask, x, y) {
				m[y][x] = !m[y][x]
			}
		}
	}
}

// --- ceza puanı --------------------------------------------------------

const (
	penaltyN1 = 3
	penaltyN2 = 3
	penaltyN3 = 40
	penaltyN4 = 10
)

// penalty, maskelenmiş matrisin tarayıcı için ne kadar zor olduğunu
// puanlar. Düşük olan seçilir.
func penalty(m [][]bool) int {
	size := len(m)
	total := 0

	// Kural 1 ve 3 satır/sütun taramasında birlikte (lineScore).
	for y := 0; y < size; y++ {
		total += lineScore(m, size, true, y)
	}
	for x := 0; x < size; x++ {
		total += lineScore(m, size, false, x)
	}

	// Kural 2: tek renk 2x2 bloklar.
	for y := 0; y < size-1; y++ {
		for x := 0; x < size-1; x++ {
			c := m[y][x]
			if m[y][x+1] == c && m[y+1][x] == c && m[y+1][x+1] == c {
				total += penaltyN2
			}
		}
	}

	// Kural 4: koyu modül oranının %50'den sapması.
	dark := 0
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if m[y][x] {
				dark++
			}
		}
	}
	cells := size * size
	prev := 5 * (20 * dark / cells)
	next := prev + 5
	a, b := abs(prev-50)/5, abs(next-50)/5
	if b < a {
		a = b
	}
	total += a * penaltyN4

	return total
}

// finderPattern, 3. kuralın aradığı 1:1:3:1:1 dizisi ve yanındaki dört
// açık modül.
var finderPattern = [11]bool{true, false, true, true, true, false, true, false, false, false, false}

/*
 * lineScore, tek bir satır ya da sütunda 1. ve 3. kuralları puanlar.
 *
 * ⚠️ 3. KURALIN OKUNUŞU TARTIŞMALI. Standart, desenin "önünde ya da
 * ardında" dört açık modül arıyor; uygulamalar bunu farklı yorumluyor
 * (yalnızca ileri, ileri+geri, örtüşenleri sayma...). Burada iki yön de
 * sayılıyor. Bu seçim ~%3 girdide CoreImage'den FARKLI bir maske
 * seçilmesine yol açıyor — ve bu bir hata değil: maskelerin hepsi
 * geçerli, hangisinin kullanıldığı biçim bilgisinde yazılı, her çözücü
 * hepsini okuyor. Testin maskeyi dayatarak karşılaştırmasının sebebi bu.
 */
func lineScore(m [][]bool, size int, horizontal bool, idx int) int {
	at := func(i int) bool {
		if horizontal {
			return m[idx][i]
		}
		return m[i][idx]
	}

	score := 0
	runLen := 1
	for i := 1; i < size; i++ {
		if at(i) == at(i-1) {
			runLen++
			if runLen == 5 {
				score += penaltyN1
			} else if runLen > 5 {
				score++
			}
		} else {
			runLen = 1
		}
	}
	for i := 0; i+11 <= size; i++ {
		fwd, rev := true, true
		for j := 0; j < 11; j++ {
			if at(i+j) != finderPattern[j] {
				fwd = false
			}
			if at(i+j) != finderPattern[10-j] {
				rev = false
			}
			if !fwd && !rev {
				break
			}
		}
		if fwd {
			score += penaltyN3
		}
		if rev {
			score += penaltyN3
		}
	}
	return score
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
