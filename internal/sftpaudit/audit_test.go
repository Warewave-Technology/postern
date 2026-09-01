package sftpaudit

import (
	"encoding/binary"
	"strings"
	"testing"
)

// --- paket kurucular: testler gerçek tel biçimini üretiyor -------------

type pkt struct{ b []byte }

func newPkt(typ byte) *pkt { return &pkt{b: []byte{typ}} }

func (p *pkt) u32(v uint32) *pkt {
	p.b = binary.BigEndian.AppendUint32(p.b, v)
	return p
}
func (p *pkt) u64(v uint64) *pkt {
	p.b = binary.BigEndian.AppendUint64(p.b, v)
	return p
}
func (p *pkt) str(s string) *pkt {
	p.b = binary.BigEndian.AppendUint32(p.b, uint32(len(s)))
	p.b = append(p.b, s...)
	return p
}

// bytes, uzunluk önekiyle birlikte tam paketi döner.
func (p *pkt) bytes() []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(p.b)))
	return append(out, p.b...)
}

func statusOK(id uint32) []byte {
	return newPkt(fxpStatus).u32(id).u32(fxOK).str("").str("").bytes()
}
func statusErr(id, code uint32, msg string) []byte {
	return newPkt(fxpStatus).u32(id).u32(code).str(msg).str("").bytes()
}

// collect, bir olay toplayıcı oturum kurar.
func collect(t *testing.T) (*Session, *[]Event) {
	t.Helper()
	var got []Event
	s := NewSession(func(e Event) { got = append(got, e) })
	return s, &got
}

func feedClient(t *testing.T, s *Session, chunks ...[]byte) {
	t.Helper()
	for _, c := range chunks {
		if err := s.FromClient(c); err != nil {
			t.Fatalf("FromClient: %v", err)
		}
	}
}
func feedTarget(t *testing.T, s *Session, chunks ...[]byte) {
	t.Helper()
	for _, c := range chunks {
		if err := s.FromTarget(c); err != nil {
			t.Fatalf("FromTarget: %v", err)
		}
	}
}

// --- asıl kanıt: bir indirme denetim satırı üretiyor mu ---------------

/*
 * Bu paketin VAR OLMA SEBEBİNİN testi: `subsystem sftp` daha önce
 * reddediliyordu çünkü transfer yalnızca ham ikili olarak kayda düşüyor,
 * "kim hangi dosyayı aldı" cevapsız kalıyordu. Burada tam o cümle
 * üretiliyor.
 */
func TestDownloadProducesAFileLevelRecord(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpOpen).u32(1).str("/etc/shadow").u32(flagRead).u32(0).bytes())
	feedTarget(t, s, newPkt(fxpHandle).u32(1).str("h1").bytes())

	feedClient(t, s, newPkt(fxpRead).u32(2).str("h1").u64(0).u32(4096).bytes())
	feedTarget(t, s, newPkt(fxpData).u32(2).str(strings.Repeat("x", 4096)).bytes())

	// İkinci okuma dosya sonuna denk geldi: İSTENEN 4096, GELEN 100.
	feedClient(t, s, newPkt(fxpRead).u32(3).str("h1").u64(4096).u32(4096).bytes())
	feedTarget(t, s, newPkt(fxpData).u32(3).str(strings.Repeat("y", 100)).bytes())

	feedClient(t, s, newPkt(fxpClose).u32(4).str("h1").bytes())
	feedTarget(t, s, statusOK(4))

	if len(*got) != 2 {
		t.Fatalf("olay sayısı = %d, 2 bekleniyordu: %+v", len(*got), *got)
	}
	if (*got)[0].Op != OpOpen || (*got)[0].Path != "/etc/shadow" {
		t.Errorf("open olayı yanlış: %+v", (*got)[0])
	}
	tr := (*got)[1]
	if tr.Op != OpTransfer || tr.Path != "/etc/shadow" {
		t.Fatalf("transfer olayı yanlış: %+v", tr)
	}
	// ⚠️ 4196 = GELEN bayt. 8192 çıksaydı, denetim hiç okunmamış
	// baytları okunmuş gösteriyor olurdu.
	if tr.Read != 4196 {
		t.Errorf("Read = %d, 4196 bekleniyordu — istenen değil gelen bayt sayılmalı", tr.Read)
	}
	if tr.Wrote != 0 {
		t.Errorf("Wrote = %d, salt okuma transferinde 0 olmalı", tr.Wrote)
	}
	if tr.Flags != "read" {
		t.Errorf("Flags = %q", tr.Flags)
	}
}

func TestUploadCountsOnlyAcceptedBytes(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpOpen).u32(1).str("/srv/app.tar").
		u32(flagWrite|flagCreat|flagTrunc).u32(0).bytes())
	feedTarget(t, s, newPkt(fxpHandle).u32(1).str("h1").bytes())

	feedClient(t, s, newPkt(fxpWrite).u32(2).str("h1").u64(0).str(strings.Repeat("a", 1000)).bytes())
	feedTarget(t, s, statusOK(2))

	// ⚠️ Bu yazma REDDEDİLDİ (disk dolu). Sayılmamalı: gönderilen bayt
	// taşınmış bayt değildir.
	feedClient(t, s, newPkt(fxpWrite).u32(3).str("h1").u64(1000).str(strings.Repeat("b", 500)).bytes())
	feedTarget(t, s, statusErr(3, 4, "failure"))

	feedClient(t, s, newPkt(fxpClose).u32(4).str("h1").bytes())
	feedTarget(t, s, statusOK(4))

	tr := (*got)[len(*got)-1]
	if tr.Wrote != 1000 {
		t.Errorf("Wrote = %d, 1000 bekleniyordu — reddedilen yazma sayılmış", tr.Wrote)
	}
	if tr.Flags != "write,creat,trunc" {
		t.Errorf("Flags = %q", tr.Flags)
	}
}

/*
 * ⚠️ İSTEK BİR OLAY DEĞİLDİR.
 *
 * İzinsizlikten dönen bir silme, denetim kaydında "silindi" diye
 * görünürse kayıt yalan söyler. Silinmemiş bir dosyayı silinmiş sanan
 * bir soruşturma yanlış yere bakar.
 */
func TestFailedRemoveIsNotRecordedAsARemoval(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpRemove).u32(1).str("/etc/passwd").bytes())
	feedTarget(t, s, statusErr(1, 3, "permission denied"))

	if len(*got) != 1 {
		t.Fatalf("olay sayısı = %d: %+v", len(*got), *got)
	}
	e := (*got)[0]
	if e.Op != OpRemove || e.Path != "/etc/passwd" {
		t.Fatalf("olay yanlış: %+v", e)
	}
	if e.OK {
		t.Error("başarısız silme OK=true yazılmış — kayıt olmayan bir silmeyi bildiriyor")
	}
	if e.Detail != "permission denied" {
		t.Errorf("Detail = %q — sebep kaybolmuş", e.Detail)
	}
}

func TestSuccessfulRemoveAndRenameAreRecorded(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpRemove).u32(1).str("/tmp/a").bytes())
	feedTarget(t, s, statusOK(1))
	feedClient(t, s, newPkt(fxpRename).u32(2).str("/tmp/b").str("/tmp/c").bytes())
	feedTarget(t, s, statusOK(2))

	if len(*got) != 2 {
		t.Fatalf("olay sayısı = %d: %+v", len(*got), *got)
	}
	if !(*got)[0].OK || (*got)[0].Op != OpRemove {
		t.Errorf("silme: %+v", (*got)[0])
	}
	r := (*got)[1]
	if r.Op != OpRename || r.Path != "/tmp/b" || r.NewPath != "/tmp/c" {
		t.Errorf("yeniden adlandırma iki yolu da taşımalı: %+v", r)
	}
}

// Reddedilen açma da kayda girer: engelin çalıştığını görmek denetimin işi.
func TestDeniedOpenIsRecorded(t *testing.T) {
	s, got := collect(t)
	feedClient(t, s, newPkt(fxpOpen).u32(1).str("/root/.ssh/id_ed25519").u32(flagRead).u32(0).bytes())
	feedTarget(t, s, statusErr(1, 3, "permission denied"))

	if len(*got) != 1 || (*got)[0].OK {
		t.Fatalf("reddedilen açma kayda girmemiş: %+v", *got)
	}
	if (*got)[0].Path != "/root/.ssh/id_ed25519" {
		t.Errorf("yol = %q", (*got)[0].Path)
	}
}

/*
 * ⚠️ AKIŞ PARÇALARI PAKET SINIRI DEĞİLDİR.
 *
 * Bu kod veri yolunun üstünde bir io.Writer olarak duruyor ve TCP'nin
 * verdiği parçalarla besleniyor. "Her Write bir pakettir" varsayımı
 * büyük transferlerde sessizce yanlış olay üretirdi. Aynı bayt dizisi
 * bayt bayt beslendiğinde AYNI olayları vermeli.
 */
func TestPacketsSplitAcrossWritesDecodeIdentically(t *testing.T) {
	build := func() ([]byte, []byte) {
		var c, tg []byte
		c = append(c, newPkt(fxpOpen).u32(1).str("/var/log/auth.log").u32(flagRead).u32(0).bytes()...)
		c = append(c, newPkt(fxpRead).u32(2).str("h1").u64(0).u32(32).bytes()...)
		c = append(c, newPkt(fxpClose).u32(3).str("h1").bytes()...)
		tg = append(tg, newPkt(fxpHandle).u32(1).str("h1").bytes()...)
		tg = append(tg, newPkt(fxpData).u32(2).str(strings.Repeat("z", 32)).bytes()...)
		tg = append(tg, statusOK(3)...)
		return c, tg
	}

	// Bütün hâlde.
	whole, gotWhole := collect(t)
	c, tg := build()
	feedClient(t, whole, c[:56])
	feedTarget(t, whole, tg[:19])
	feedClient(t, whole, c[56:])
	feedTarget(t, whole, tg[19:])

	// Bayt bayt, iki yön dönüşümlü.
	split, gotSplit := collect(t)
	c2, tg2 := build()
	// Sıra korunmalı: open→handle→read→data→close→status.
	byteFeed := func(s *Session, f func([]byte) error, b []byte) {
		for i := range b {
			if err := f(b[i : i+1]); err != nil {
				t.Fatalf("bayt %d: %v", i, err)
			}
		}
	}
	byteFeed(split, split.FromClient, c2[:56])
	byteFeed(split, split.FromTarget, tg2[:19])
	byteFeed(split, split.FromClient, c2[56:])
	byteFeed(split, split.FromTarget, tg2[19:])

	if len(*gotWhole) != len(*gotSplit) {
		t.Fatalf("olay sayıları farklı: bütün=%d parçalı=%d\n%+v\n%+v",
			len(*gotWhole), len(*gotSplit), *gotWhole, *gotSplit)
	}
	for i := range *gotWhole {
		a, b := (*gotWhole)[i], (*gotSplit)[i]
		if a.Op != b.Op || a.Path != b.Path || a.Read != b.Read || a.Wrote != b.Wrote {
			t.Errorf("olay %d farklı:\n bütün  = %+v\n parçalı = %+v", i, a, b)
		}
	}
	if len(*gotWhole) != 2 || (*gotWhole)[1].Read != 32 {
		t.Fatalf("beklenen open+transfer(32): %+v", *gotWhole)
	}
}

/*
 * ⚠️ YARIM KALAN TRANSFER KAYBOLMAMALI.
 *
 * Bağlantı transfer ortasında koparsa CLOSE hiç gelmez. Bu olmadan,
 * veriyi çekip bağlantıyı koparmak izi silmenin yolu olurdu.
 */
func TestInterruptedTransferIsStillRecorded(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpOpen).u32(1).str("/data/dump.sql").u32(flagRead).u32(0).bytes())
	feedTarget(t, s, newPkt(fxpHandle).u32(1).str("h1").bytes())
	feedClient(t, s, newPkt(fxpRead).u32(2).str("h1").u64(0).u32(9000).bytes())
	feedTarget(t, s, newPkt(fxpData).u32(2).str(strings.Repeat("q", 9000)).bytes())

	// CLOSE yok — bağlantı koptu.
	s.Finish()

	if len(*got) != 2 {
		t.Fatalf("olay sayısı = %d, yarım transfer yazılmamış: %+v", len(*got), *got)
	}
	tr := (*got)[1]
	if tr.Op != OpTransfer || tr.Read != 9000 {
		t.Fatalf("yarım transfer yanlış: %+v", tr)
	}
	if tr.OK {
		t.Error("yarım kalan transfer OK=true — tamamlanmış gibi görünüyor")
	}
	// İkinci çağrı özeti tekrar yazmamalı.
	s.Finish()
	if len(*got) != 2 {
		t.Errorf("Finish iki kez yazdı: %d olay", len(*got))
	}
}

// --- düşman girdisi ---------------------------------------------------

/*
 * ⚠️ TEK BİR SAYIYLA DENETİM SUSTURULAMAMALI.
 *
 * Uzunluk alanı karşı taraftan geliyor. Sınır olmasa "uzunluk = 4 GB"
 * yazan bir başlık, çözümleyiciyi hiç gelmeyecek veriyi beklemeye
 * sokar ve oturumun geri kalanında tek bir olay bile üretilmezdi.
 */
func TestOversizedLengthIsRejectedNotAwaited(t *testing.T) {
	s, _ := collect(t)
	hdr := binary.BigEndian.AppendUint32(nil, 0xFFFFFFFF)
	err := s.FromClient(hdr)
	if err == nil {
		t.Fatal("devasa uzunluk kabul edildi — çözümleyici sonsuza dek bekler")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("hata = %v", err)
	}
}

func TestZeroLengthPacketIsRejected(t *testing.T) {
	s, _ := collect(t)
	if err := s.FromClient(binary.BigEndian.AppendUint32(nil, 0)); err == nil {
		t.Fatal("sıfır uzunluklu paket kabul edildi")
	}
}

// Pakete sığmayan dizgi uzunluğu: uydurma bir dosya adı üretmektense hata.
func TestFieldLongerThanPacketIsRejected(t *testing.T) {
	s, _ := collect(t)
	body := []byte{fxpOpen}
	body = binary.BigEndian.AppendUint32(body, 1)
	body = binary.BigEndian.AppendUint32(body, 9999) // 9999 baytlık ad, gövde yok
	full := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	full = append(full, body...)

	if err := s.FromClient(full); err == nil {
		t.Fatal("pakete sığmayan alan kabul edildi — kayda uydurma yol yazılırdı")
	}
}

/*
 * ⚠️ CEVABI OKUMAYAN İSTEMCİ BELLEK TÜKETEMEMELİ.
 *
 * Bekleyen istek tablosu karşı taraftan besleniyor. Sınırsız bırakılsa,
 * hiç cevap beklemeyen bir istemci bastion'ı düşürebilirdi.
 */
func TestUnansweredRequestsAreBounded(t *testing.T) {
	s, _ := collect(t)
	var err error
	for i := 0; i < maxPending+10; i++ {
		p := newPkt(fxpRemove).u32(uint32(i)).str("/tmp/x").bytes()
		if err = s.FromClient(p); err != nil {
			break
		}
	}
	if err == nil {
		t.Fatalf("%d cevapsız istek sınırsız kabul edildi", maxPending+10)
	}
	if !strings.Contains(err.Error(), "outstanding") {
		t.Errorf("hata = %v", err)
	}
}

/*
 * ⚠️ DOSYA İÇERİĞİ BELLEĞE ALINMAMALI.
 *
 * Çözümleyici veri yolunun kopyasını görüyor. Paketleri bütün hâlde
 * biriktirseydi, 1 GB'lık bir transfer bastion'da 1 GB bellek anlamına
 * gelirdi — kaydın ham veriyi almama gerekçesinin aynısı.
 */
func TestFileBodiesAreNotBuffered(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpOpen).u32(1).str("/big").u32(flagRead).u32(0).bytes())
	feedTarget(t, s, newPkt(fxpHandle).u32(1).str("h1").bytes())
	feedClient(t, s, newPkt(fxpRead).u32(2).str("h1").u64(0).u32(900000).bytes())

	big := newPkt(fxpData).u32(2).str(strings.Repeat("Z", 900000)).bytes()

	// ⚠️ ÖLÇÜM PAKET AKARKEN YAPILMALI. Paket tamamlanınca saklanan ön
	// kısım bırakılıyor; bittikten sonra bakan bir test her zaman 0
	// görür ve tavan kaldırılsa bile geçerdi. (Bu testin ilk hâli tam
	// olarak buydu ve mutasyon testinde yakalandı.)
	if err := s.FromTarget(big[:len(big)/2]); err != nil {
		t.Fatal(err)
	}
	if c := cap(s.fromTarget.head); c > maxHeader {
		t.Errorf("akış ortasında saklanan gövde = %d bayt, tavan %d — "+
			"dosya içeriği belleğe alınıyor", c, maxHeader)
	}
	if err := s.FromTarget(big[len(big)/2:]); err != nil {
		t.Fatal(err)
	}

	feedClient(t, s, newPkt(fxpClose).u32(3).str("h1").bytes())
	feedTarget(t, s, statusOK(3))

	// İçerik saklanmasa da SAYI doğru olmalı.
	tr := (*got)[len(*got)-1]
	if tr.Read != 900000 {
		t.Errorf("Read = %d, 900000 bekleniyordu — gövde atlanırken sayı kayboldu", tr.Read)
	}
}

// Dizin açma transfer özeti üretmemeli: dizin okumak dosya taşımak değil.
func TestOpendirDoesNotProduceATransfer(t *testing.T) {
	s, got := collect(t)
	feedClient(t, s, newPkt(fxpOpendir).u32(1).str("/srv").bytes())
	feedTarget(t, s, newPkt(fxpHandle).u32(1).str("d1").bytes())
	feedClient(t, s, newPkt(fxpClose).u32(2).str("d1").bytes())
	feedTarget(t, s, statusOK(2))

	for _, e := range *got {
		if e.Op == OpTransfer {
			t.Fatalf("dizin için transfer olayı yazılmış: %+v", *got)
		}
	}
	if len(*got) != 1 || (*got)[0].Op != OpOpendir {
		t.Fatalf("beklenen tek opendir olayı: %+v", *got)
	}
}
