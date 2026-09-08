package sftpaudit

// Denetim satırının DEFTERE SIĞMASI.
//
// Buradaki testlerin hepsi tek bir arızanın parçaları: session_files'a
// yazılamayan bir alan, satırı değil oturumun BÜTÜN dosya olaylarını
// düşürüyordu (grup tek transaction). Sınırlar ölçülerek konuldu; sayılar
// audit.go'daki maxPath / maxDetail gerekçelerinde duruyor.

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// storable, metnin PostgreSQL'in TEXT olarak kabul edeceği hâlde olup
// olmadığını söyler: geçerli UTF-8 ve NUL'suz.
func storable(s string) bool {
	return utf8.ValidString(s) && !strings.Contains(s, "\x00")
}

/*
 * ⚠️ ASIL ARIZA: 2692 İLE 4096 ARASINDAKİ YOL.
 *
 * maxPath 4096'ydı ve gerekçesi PATH_MAX'tı; defterin kabul ettiği ise
 * ölçülmemişti. session_files.path btree indeksli ve PostgreSQL girdiyi
 * 2704 baytta reddediyor — aradaki aralıkta kalan bir yol INSERT'i
 * düşürüyordu. İç içe dizin açan sıradan bir SFTP istemcisi o yolu
 * üretebiliyor.
 */
func TestStoredPathFitsTheLedgerIndex(t *testing.T) {
	s, got := collect(t)

	// 3000 bayt: PATH_MAX'ın altında (yani hedefte GEÇERLİ bir yol) ama
	// indeksin sınırının üstünde — düşen satırın tam olarak aralığı.
	long := "/" + strings.Repeat("d/", 1500)
	if len(long) <= maxPath {
		t.Fatalf("test verisi sınırın altında kalmış (%d bayt)", len(long))
	}
	feedClient(t, s, newPkt(fxpOpen).u32(1).str(long).u32(1).u32(0).bytes())
	feedTarget(t, s, newPkt(fxpHandle).u32(1).str("h").bytes())

	if len(*got) != 1 {
		t.Fatalf("olay yazılmadı: %+v", *got)
	}
	e := (*got)[0]
	if len(e.Path) > maxPath {
		t.Fatalf("SAKLANAN YOL DEFTERE SIĞMIYOR: %d bayt, sınır %d — "+
			"bu satırın INSERT'i düşer ve grubun tamamını götürür",
			len(e.Path), maxPath)
	}
	// Kesildiği görünmeli: kısaltılmış bir yolu gerçek yol sanan bir
	// operatör yanlış dosya üzerinde işlem yapabilir.
	if !strings.HasSuffix(e.Path, markTruncated) {
		t.Errorf("kesilmiş yol işaretlenmemiş: %q", last(e.Path, 40))
	}
	// Önek KORUNUYOR: "bu dizinin altında ne oldu" araması (031) kesilmiş
	// satırı da bulabilmeli.
	if !strings.HasPrefix(e.Path, "/d/d/d/") {
		t.Errorf("yolun öneki korunmamış: %q", first(e.Path, 20))
	}
}

/*
 * ⚠️ UZUN YOLDAN DAHA KOLAY ULAŞILAN ARIZA: GEÇERSİZ UTF-8.
 *
 * SFTP'de dosya adı uzunluk önekli bir bayt dizisi; geçerli UTF-8 olma
 * zorunluluğu yok. Latin-1 adlandırılmış tek bir dosya
 * ("rapor-\xe7\xf6\xfc.txt", gerçek sunucularda olağan) oturumun bütün
 * dosya olaylarını düşürüyordu:
 *
 *	ERROR: invalid byte sequence for encoding "UTF8": 0xe7 0xf6 0xfc
 */
func TestUnstorableBytesAreRemovedFromThePath(t *testing.T) {
	s, got := collect(t)

	// Geçerli UTF-8 (Türkçe) korunmalı, latin-1 baytları atılmalı.
	bad := "/home/ayşe/rapor-\xe7\xf6\xfc.txt"
	feedClient(t, s, newPkt(fxpOpen).u32(1).str(bad).u32(1).u32(0).bytes())
	feedTarget(t, s, newPkt(fxpHandle).u32(1).str("h").bytes())

	if len(*got) != 1 {
		t.Fatalf("olay yazılmadı: %+v", *got)
	}
	e := (*got)[0]
	if !storable(e.Path) {
		t.Fatalf("YOL DEFTERE YAZILAMAZ: %q — PostgreSQL bu satırı "+
			"SQLSTATE 22021 ile reddeder", e.Path)
	}
	if !strings.Contains(e.Path, "ayşe") {
		t.Errorf("geçerli UTF-8 de atılmış: %q", e.Path)
	}
	if !strings.HasSuffix(e.Path, markStripped) {
		t.Errorf("atılan baytlar işaretlenmemiş: %q", e.Path)
	}
}

// NUL geçerli UTF-8'dir (U+0000) ama PostgreSQL onu TEXT'te kabul etmiyor:
// utf8.ValidString'e güvenen bir eleme bunu kaçırırdı.
func TestNULIsRemovedFromThePath(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpOpen).u32(1).str("/tmp/a\x00b").u32(1).u32(0).bytes())
	feedTarget(t, s, newPkt(fxpHandle).u32(1).str("h").bytes())

	if len(*got) != 1 {
		t.Fatalf("olay yazılmadı: %+v", *got)
	}
	if p := (*got)[0].Path; strings.Contains(p, "\x00") {
		t.Fatalf("NUL saklanan yolda kaldı: %q — satır yazılamaz", p)
	}
}

/*
 * ⚠️ GEREKÇE METNİNİ HEDEF YAZIYOR, SINIRI HEDEF KOYAMAZ.
 *
 * STATUS mesajı Detail'e SINIRSIZ giriyordu. Kolon TEXT ve indekssiz,
 * yani uzunluk satırı DÜŞÜRMÜYOR — ölçtük, 100 KiB'lık bir detail
 * sorunsuz yazılıyor; tehlike kaybolan satır değil, şişen tablo. Tek bir
 * mesajın tavanını çerçeveleyici koyuyor (maxHeader, 64 KiB) ve binlerce
 * başarısız açılış bunu tek bir transaction'da çarpıyor. Denetim
 * tablosunun boyunu karşı tarafın kalemine bırakamayız.
 */
func TestDetailFromTheTargetIsBounded(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpOpen).u32(1).str("/etc/shadow").u32(1).u32(0).bytes())
	feedTarget(t, s, statusErr(1, 3, strings.Repeat("R", 60*1024)))

	if len(*got) != 1 {
		t.Fatalf("olay yazılmadı: %+v", *got)
	}
	e := (*got)[0]
	if len(e.Detail) > maxDetail {
		t.Fatalf("HEDEFİN METNİ SINIRSIZ SAKLANIYOR: %d bayt (sınır %d) — "+
			"tek bir oturum denetim tablosunu şişirebilir",
			len(e.Detail), maxDetail)
	}
	if !strings.HasSuffix(e.Detail, markTruncated) {
		t.Errorf("kesilmiş gerekçe işaretlenmemiş: %q", last(e.Detail, 40))
	}
	// Olayın kendisi duruyor: kırpma satırı yutmuyor.
	if e.OK || e.Op != OpOpen {
		t.Errorf("reddedilen açılış kaydı bozuldu: %+v", e)
	}
}

// Gerekçe metni de aynı bayt eleğinden geçiyor: hedefin hata cümlesi
// yerelleştirilmiş ve latin-1 olabilir.
func TestUnstorableBytesAreRemovedFromTheDetail(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpOpen).u32(1).str("/etc/shadow").u32(1).u32(0).bytes())
	feedTarget(t, s, statusErr(1, 3, "izin yok: \xff\xfe"))

	if len(*got) != 1 {
		t.Fatalf("olay yazılmadı: %+v", *got)
	}
	if d := (*got)[0].Detail; !storable(d) {
		t.Fatalf("GEREKÇE DEFTERE YAZILAMAZ: %q", d)
	}
}

/*
 * ⚠️ KIRPMA İKİ KEZ UYGULANIYOR: addPending bir kez (bekleyen tablosunun
 * bellek sınırı), write bir kez (defterin sınırı). İşaret bütçeye dahil
 * olmasaydı ikinci çağrı birincinin işaretini kesip üstüne yenisini
 * koyardı — ve sonuç sınırı aşmaya devam ederdi.
 */
func TestClampingTwiceChangesNothing(t *testing.T) {
	cases := []string{
		"/etc/shadow",
		"/" + strings.Repeat("z", maxPath+500),
		"/veri/\xe7\xf6\xfc",
		"/" + strings.Repeat("y", maxPath) + "\xff",
	}
	for _, in := range cases {
		once := clampPath(in)
		twice := clampPath(once)
		if once != twice {
			t.Errorf("clampPath sabit değil:\n bir kez: %q\n iki kez: %q",
				last(once, 60), last(twice, 60))
		}
		if len(once) > maxPath {
			t.Errorf("sonuç sınırı aşıyor: %d bayt", len(once))
		}
		if !storable(once) {
			t.Errorf("sonuç yazılamaz: %q", last(once, 60))
		}
	}
}

// Kesme yarım rune bırakmamalı: bıraksaydı, giderdiğimiz arızayı kendi
// elimizle geri getirirdik.
func TestTruncationDoesNotSplitARune(t *testing.T) {
	// Sınırın tam üstüne 3 baytlık rune'lar bindiriyoruz; kesme noktası
	// bir rune'un ortasına düşecek.
	in := strings.Repeat("ş", maxPath)
	out := clampPath(in)
	if !storable(out) {
		t.Fatalf("kesme geçersiz UTF-8 üretti: %q", last(out, 20))
	}
	if len(out) > maxPath {
		t.Fatalf("sonuç %d bayt, sınır %d", len(out), maxPath)
	}
}

func first(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func last(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
