package proxy

// Yazılamayan tek bir satır, defterin tamamını götürmemeli.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * pickyFiles, tek bir satırı ASLA kabul etmeyen fileWriter.
 *
 * Gerçek deponun davranışını taklit ediyor: grup tek transaction, yani
 * zehirli satırı İÇEREN her grup tümüyle reddediliyor ve ret "bu değer
 * kabul edilmiyor" diye sınıflanıyor (store.ErrInvalid).
 *
 * ⚠️ İŞARET SATIRI KABUL EDİLİYOR. Atılan satırın yerine yazılan satırın
 * yolu sert kırpılmış oluyor (castSafe); onu da reddeden bir taklit,
 * gerçekte olmayan bir arızayı ölçerdi.
 */
type pickyFiles struct {
	poison  string
	down    error // boş değilse: bundan sonraki her yazma GEÇİCİ hatayla düşer
	wrote   []store.SessionFile
	batches int
}

func (p *pickyFiles) AddSessionFiles(_ context.Context, _ string, files []store.SessionFile) error {
	p.batches++
	for _, f := range files {
		if strings.HasPrefix(f.Op, "dropped.") {
			continue
		}
		if f.Path == p.poison {
			return fmt.Errorf("fake: %w: index row size exceeds btree maximum",
				store.ErrInvalid)
		}
		if p.down != nil {
			return p.down
		}
	}
	p.wrote = append(p.wrote, files...)
	return nil
}

func (p *pickyFiles) paths() []string {
	out := make([]string, 0, len(p.wrote))
	for _, f := range p.wrote {
		out = append(out, f.Path)
	}
	return out
}

/*
 * ⚠️ ASIL ARIZA: ZEHİRLİ SATIR DEFTERİ TIKIYORDU.
 *
 * Yazma çöktüğünde grup tamponun BAŞINA geri konuyordu. Satır değeri
 * yüzünden reddedilmişse (2704 baytı aşan yol, geçersiz UTF-8) bu, aynı
 * satırı sonsuza kadar sıranın başında tutmak demekti: bir sonraki
 * boşaltma da, Close'daki son boşaltma da aynı yere çarpıyor ve oturumun
 * BÜTÜN dosya olayları o satırın arkasında kayboluyordu.
 */
func TestAnUnwritableRowDoesNotBlockTheRestOfTheLedger(t *testing.T) {
	w := &pickyFiles{poison: "/zehir"}
	failed := make(chan error, 4)
	j := &sftpJournal{store: w, log: testLogger(), fail: func(e error) { failed <- e }}

	j.buf = []store.SessionFile{
		{Op: "open", Path: "/once"},
		{Op: "open", Path: "/zehir"},
		{Op: "transfer", Path: "/sonra-1"},
		{Op: "transfer", Path: "/sonra-2"},
	}
	j.flush()

	var got []string
	for _, p := range w.paths() {
		if p != "" {
			got = append(got, p)
		}
	}
	for _, want := range []string{"/once", "/sonra-1", "/sonra-2"} {
		if !contains(got, want) {
			t.Errorf("DENETİM SATIRI KAYBOLDU: %q yazılmadı; yazılanlar: %v\n"+
				"tek bir yazılamaz satır grubun tamamını götürüyor", want, got)
		}
	}

	j.mu.Lock()
	kept, dropped := len(j.buf), j.dropped
	j.mu.Unlock()

	if kept != 0 {
		t.Errorf("zehirli satır tamponda kaldı (%d satır); sonraki her "+
			"boşaltma aynı yere çarpar", kept)
	}
	if dropped != 1 {
		t.Errorf("atılan satır sayısı = %d, 1 bekleniyordu — kayıp SAYILMALI", dropped)
	}
	// ⚠️ OTURUM YİNE ÖLÜYOR: atılan satır bir denetim kaybı ve bu deponun
	// kuralı değişmedi. Değişen tek şey, kalan satırların kaybolmaması.
	select {
	case <-failed:
	default:
		t.Error("denetim satırı atıldı ama oturum bitirilmedi")
	}
}

// Atılan satırın izi DEFTERE düşüyor: yalnızca log'a yazmak, veritabanına
// bakan bir denetçiye eksik listeyi tam liste gibi gösterirdi.
func TestADroppedRowLeavesAMarkInTheLedger(t *testing.T) {
	w := &pickyFiles{poison: "/zehir"}
	j := &sftpJournal{store: w, log: testLogger(), fail: func(error) {}}

	j.buf = []store.SessionFile{{Op: "open", Path: "/zehir", Detail: "x"}}
	j.flush()

	var mark *store.SessionFile
	for i, f := range w.wrote {
		if strings.HasPrefix(f.Op, "dropped.") {
			mark = &w.wrote[i]
		}
	}
	if mark == nil {
		t.Fatalf("atılan satırın yerine hiçbir şey yazılmadı: %+v", w.wrote)
	}
	if mark.Op != "dropped.open" {
		t.Errorf("işaret satırının işlemi = %q, olayın ne olduğu kayboldu", mark.Op)
	}
	if mark.OK {
		t.Error("işaret satırı ok=true; kayıp başarı gibi görünüyor")
	}
	if !strings.Contains(mark.Detail, "could not be stored") {
		t.Errorf("işaret satırı sebebi söylemiyor: %q", mark.Detail)
	}
}

/*
 * ⚠️ BÖLME BİR VERİ KAYBI MAKİNESİNE DÖNÜŞMEMELİ.
 *
 * Veritabanı düştüğünde de her yazma başarısız olur. Ayrım yapmayan bir
 * bölme, grubu tek tek satırlara indirip HEPSİNİ "yazılamaz" diye atardı:
 * bir bağlantı kesintisi, bekleyen bütün denetim satırlarının silinmesi
 * demek olurdu.
 */
func TestATransientFailureDropsNothing(t *testing.T) {
	down := errors.New("database is down")
	w := &pickyFiles{down: down}
	failed := make(chan error, 1)
	j := &sftpJournal{store: w, log: testLogger(), fail: func(e error) { failed <- e }}

	j.buf = []store.SessionFile{
		{Op: "open", Path: "/a"},
		{Op: "open", Path: "/b"},
		{Op: "open", Path: "/c"},
	}
	j.flush()

	j.mu.Lock()
	kept, dropped := len(j.buf), j.dropped
	j.mu.Unlock()

	if dropped != 0 {
		t.Errorf("geçici arızada %d satır ATILDI; hepsi geri konmalıydı", dropped)
	}
	if kept != 3 {
		t.Fatalf("tamponda %d satır kaldı, 3 bekleniyordu", kept)
	}
	if w.batches != 1 {
		t.Errorf("düşmüş bir veritabanına %d ayrı yazma denendi; geçici "+
			"arızada bölmenin bir anlamı yok", w.batches)
	}
	select {
	case <-failed:
	default:
		t.Error("yazma çöktü ama oturum bitirilmedi")
	}
}

/*
 * Zehirli satır ayıklandıktan SONRA geçici arıza gelirse, denenmemiş
 * satırlar SIRASIYLA geri konmalı: sıra, "önce açtı sonra okudu"
 * cümlesinin kendisi.
 */
/*
 * splitBreaker, bölme BAŞLADIKTAN SONRA düşen bir depo.
 *
 * Zehirli satırı içeren gruba "bu değer kabul edilmiyor" (ErrInvalid)
 * diyor — yani bölmeyi başlatıyor. Zehirsiz bir grup geldiğinde ise
 * GEÇİCİ bir arıza veriyor: veritabanı tam da bölmenin ortasında düşmüş
 * oluyor.
 *
 * ⚠️ pickyFiles BU HÂLİ ÜRETEMİYOR ve sebebi ince: oradaki döngü zehri
 * gördüğü anda dönüyor, yani zehir grubun başındayken `down` hiç
 * tetiklenmiyor. İki taklidi ayrı tutmak, var olan testlerin ölçtüğü
 * şeyi de değiştirmiyor.
 */
type splitBreaker struct {
	poison string
	down   error
	// seen, depoya GÖNDERİLEN grupların yolları — hangi satırın hiç
	// denenmediğini ölçmek için.
	seen [][]string
}

func (s *splitBreaker) AddSessionFiles(_ context.Context, _ string, files []store.SessionFile) error {
	paths := make([]string, 0, len(files))
	poisoned := false
	for _, f := range files {
		paths = append(paths, f.Path)
		if f.Path == s.poison {
			poisoned = true
		}
	}
	s.seen = append(s.seen, paths)

	if poisoned {
		return fmt.Errorf("fake: %w: index row size exceeds btree maximum",
			store.ErrInvalid)
	}

	return s.down
}

// groups, depoya gönderilen grupları "a,b" biçiminde döner.
func (s *splitBreaker) groups() []string {
	out := make([]string, 0, len(s.seen))
	for _, g := range s.seen {
		out = append(out, strings.Join(g, ","))
	}

	return out
}

/*
 * ⚠️ POSTERN'İN KENDİ KAYBI, MÜDAHALE GİBİ RAPORLANMAMALI — ve bu, iki
 * dalın birleşmesinde tek taşıyıcı karar.
 *
 * Yazılamayan satır ayıklanıp atılıyor ve yerine bir işaret satırı
 * yazılıyor. O işaret satırı InRecording TAŞIMIYOR (yolu ve işlemi
 * bozulmuş, kayıttaki satırı üretemez), yani defteri kaydın mührüyle
 * karşılaştıran kontrolün saydığı satırlardan düşüyor: mühür N olay
 * diyor, defterde N-1 satır var.
 *
 * O farkın adı iki şeyden biri olabilir — "postern yazamadı"
 * (incomplete) ya da "birileri sildi" (missing). Ayıran tek şey,
 * kaybın Close'un döndürdüğü sayıya girmesi. Girmezse kontrol, bu
 * bastion'ın kendi arızasını KURCALAMA diye raporlar; üç PR'ın birden
 * önlemeye çalıştığı şeyin tam tersi.
 */
func TestADroppedRowIsCountedAsOurOwnLoss(t *testing.T) {
	w := &pickyFiles{poison: "/zehir"}
	j := &sftpJournal{
		store: w, log: testLogger(), recorded: true, fail: func(error) {},
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	close(j.done) // loop koşmuyor: flush'ı testin kendisi sürüyor.

	j.buf = []store.SessionFile{
		{Op: "open", Path: "/a", InRecording: true},
		{Op: "open", Path: "/zehir", InRecording: true},
		{Op: "open", Path: "/b", InRecording: true},
	}
	j.flush()

	written, lost, _ := j.Close()

	if written != 2 {
		t.Errorf("yazılan satır %d, 2 bekleniyordu", written)
	}
	if lost != 1 {
		t.Fatalf("ATILAN SATIR KAYBA SAYILMADI: lost = %d, 1 bekleniyordu — "+
			"defteri mühürle karşılaştıran kontrol bunu 'satır silinmiş' "+
			"diye raporlar", lost)
	}

	/*
	 * Karşı kanıt: işaret satırı gerçekten yazıldı ve gerçekten
	 * InRecording taşımıyor. Taşısaydı sayı tutardı ama ÖZET tutmazdı
	 * ve kontrol bu kez "ROWS ALTERED" derdi — aynı yanlış suçlamanın
	 * öteki yüzü.
	 */
	var marker *store.SessionFile
	for i := range w.wrote {
		if strings.HasPrefix(w.wrote[i].Op, "dropped.") {
			marker = &w.wrote[i]
		}
	}
	if marker == nil {
		t.Fatalf("işaret satırı yazılmadı: %+v", w.paths())
	}
	if marker.InRecording {
		t.Error("işaret satırı kayıtta varmış gibi damgalandı; özet tutmaz")
	}
}

/*
 * ⚠️ BÖLMENİN ORTASINDAKİ GEÇİCİ ARIZA — ayıklamanın en tehlikeli hâli.
 *
 * TestATransientFailureDropsNothing yalnızca bölme HİÇ BAŞLAMADIĞI hâli
 * ölçüyor. Asıl risk şurada: grup zehirli olduğu için ikiye bölünüyor,
 * ilk yarı denenirken veritabanı düşüyor — ve İKİNCİ YARI HİÇ
 * DENENMEMİŞ oluyor. O yarıyı geri koymayan bir uygulama, yazılabilir
 * satırları sessizce yok eder: log yok, dropped artmıyor, işaret satırı
 * yok. Yani "yalnızca yazılamayan satır atılır" sözü, tam da ayıklamanın
 * kendi arıza yolunda tutmazdı.
 *
 * Bu dal kapsam profilinde SIFIR kez giriliyordu: `return left, lerr`
 * diye bozan bir değişiklik bütün testlerden geçiyordu.
 */
func TestATransientFailureMidSplitKeepsTheUntriedHalf(t *testing.T) {
	down := errors.New("database is down")
	w := &splitBreaker{poison: "/zehir", down: down}
	j := &sftpJournal{store: w, log: testLogger(), fail: func(error) {}}

	batch := []store.SessionFile{
		{Op: "open", Path: "/a"},
		{Op: "open", Path: "/b"},
		{Op: "open", Path: "/zehir"},
		{Op: "open", Path: "/d"},
	}

	rest, err := j.writeBatch(context.Background(), batch)
	if !errors.Is(err, down) {
		t.Fatalf("geçici arıza çağırana dönmedi: %v", err)
	}

	/*
	 * HEPSİ geri gelmeli. /a ve /b denendi ve yazılamadı; /zehir ve /d
	 * ise HİÇ denenmedi — ikisinin de yazılabilir olup olmadığı hâlâ
	 * bilinmiyor ve bilinmeyen bir satır atılamaz.
	 */
	got := make([]string, 0, len(rest))
	for _, f := range rest {
		got = append(got, f.Path)
	}
	want := []string{"/a", "/b", "/zehir", "/d"}
	if len(got) != len(want) {
		t.Fatalf("geri konan satırlar %v, %v bekleniyordu — denenmemiş "+
			"yarı sessizce düştü", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("geri konan sıra %v, %v bekleniyordu", got, want)
		}
	}

	/*
	 * ⚠️ KARŞI KANIT: BÖLME GERÇEKTEN ORTASINDA KESİLDİ.
	 *
	 * "/d hiç denenmedi" diye sormak yanlış soruydu: dış çağrı zaten
	 * dört satırın hepsini gönderiyor. Doğru soru, bölmeden SONRA hangi
	 * grubun denendiği — yalnızca sol yarı denenmiş olmalı. Sağ yarı da
	 * denenseydi bu test bölmenin ortasını değil sonunu ölçerdi.
	 */
	want2 := []string{"/a,/b,/zehir,/d", "/a,/b"}
	got2 := w.groups()
	if len(got2) != len(want2) {
		t.Fatalf("denenen gruplar %v, %v bekleniyordu", got2, want2)
	}
	for i := range want2 {
		if got2[i] != want2[i] {
			t.Fatalf("denenen gruplar %v, %v bekleniyordu", got2, want2)
		}
	}

	// Ve hiçbir şey atılmadı: bilinmeyen satır atılacak satır değil.
	j.mu.Lock()
	dropped := j.dropped
	j.mu.Unlock()
	if dropped != 0 {
		t.Errorf("geçici arızada %d satır atıldı", dropped)
	}
}

func TestRowsLeftUnwrittenGoBackInOrder(t *testing.T) {
	w := &pickyFiles{poison: "/zehir", down: errors.New("database is down")}
	j := &sftpJournal{store: w, log: testLogger(), fail: func(error) {}}

	j.buf = []store.SessionFile{
		{Op: "open", Path: "/zehir"},
		{Op: "open", Path: "/kalan-1"},
		{Op: "open", Path: "/kalan-2"},
	}
	j.flush()

	j.mu.Lock()
	got := append([]store.SessionFile(nil), j.buf...)
	dropped := j.dropped
	j.mu.Unlock()

	if dropped != 1 {
		t.Errorf("atılan satır = %d, 1 bekleniyordu", dropped)
	}
	if len(got) != 2 {
		t.Fatalf("geri konan satırlar: %d, 2 bekleniyordu (%+v)", len(got), got)
	}
	if got[0].Path != "/kalan-1" || got[1].Path != "/kalan-2" {
		t.Errorf("sıra bozuldu: %q, %q", got[0].Path, got[1].Path)
	}
}

func contains(all []string, want string) bool {
	for _, s := range all {
		if s == want {
			return true
		}
	}
	return false
}

/*
 * ⚠️ RET KAYDINI DÜŞÜREN İSTEMCİ.
 *
 * postern'in kendi reddi de session_files'a yazılıyor ve `op` sütununa
 * SSH İSTEK TİPİ giriyor. İstek tipi tel üzerinde ham bayt dizisi:
 * geçersiz UTF-8 gönderen bir istemci satırı yazılamaz kılıyor, yani
 * KENDİ RET KAYDINI sildirebiliyordu. Ret uygulanmaya devam ediyordu ama
 * "kim denedi" sorusunun cevabı defterden çıkıyordu — bu satırın var
 * olma sebebi tam olarak o soru.
 */
func TestADenialRowSurvivesAHostileRequestType(t *testing.T) {
	row := denialRow("id-1", "sess-1", "sftp\xff\xfe", "sftp is disabled", time.Now())

	if !strings.HasPrefix(row.Op, "denied.") {
		t.Fatalf("ret satırının işlemi bozuldu: %q", row.Op)
	}
	if !utf8.ValidString(row.Op) || strings.ContainsRune(row.Op, 0) {
		t.Fatalf("RET SATIRI DEFTERE YAZILAMAZ: op = %q — PostgreSQL bunu "+
			"SQLSTATE 22021 ile reddeder ve deneme kaydı kaybolur", row.Op)
	}
	if !utf8.ValidString(row.Detail) {
		t.Errorf("ret gerekçesi yazılamaz: %q", row.Detail)
	}
	if row.OK {
		t.Error("ret satırı ok=true")
	}
}
