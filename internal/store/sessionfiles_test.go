package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
)

// startFileSession, dosya olayları bağlanacak bir oturum açar.
func startFileSession(t *testing.T, s *Store, id string) {
	t.Helper()
	ctx := context.Background()
	seedSession(t, s)
	if err := s.StartSession(ctx, SessionStart{
		ID: id, Username: "yigit", TargetName: "web01",
		OSUser: "yigit", SrcIP: "10.0.0.1", StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSessionFilesRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-files-1")

	now := time.Now().Truncate(time.Second)
	in := []SessionFile{
		{At: now, Op: "open", Path: "/etc/shadow", Flags: "read", OK: true},
		{At: now.Add(time.Second), Op: "transfer", Path: "/etc/shadow",
			Flags: "read", Read: 4196, OK: true},
		{At: now.Add(2 * time.Second), Op: "remove", Path: "/etc/passwd",
			OK: false, Detail: "permission denied"},
	}
	if err := s.AddSessionFiles(ctx, "sess-files-1", in); err != nil {
		t.Fatalf("AddSessionFiles: %v", err)
	}

	got, err := s.SessionFiles(ctx, "sess-files-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("satır sayısı = %d: %+v", len(got), got)
	}
	// Zaman sırası korunmalı: denetim satırlarını karışık göstermek,
	// olayların sırasını okunamaz kılar.
	if got[0].Op != "open" || got[1].Op != "transfer" || got[2].Op != "remove" {
		t.Errorf("sıra bozuk: %+v", got)
	}
	if got[1].Read != 4196 {
		t.Errorf("Read = %d", got[1].Read)
	}
	/*
	 * ⚠️ BAŞARISIZ SATIR SAKLANIYOR.
	 *
	 * İzinsizlikten dönen bir silme denemesi engelin çalıştığının
	 * kanıtı. Yalnızca başarılıları saklayan bir tablo, "kimse
	 * denemedi" ile "denediler ama giremediler"i aynı gösterirdi.
	 */
	if got[2].OK {
		t.Error("başarısız işlem OK=true saklandı")
	}
	if got[2].Detail != "permission denied" {
		t.Errorf("sebep kayboldu: %q", got[2].Detail)
	}
}

/*
 * ⚠️ SORUŞTURMA DOSYAYI BİLİR, OTURUMU BİLMEZ.
 *
 * "/etc/shadow'u kim aldı" sorusu, oturumdan dosyaya bakan bir arayüzle
 * cevaplanamaz: denetçinin elinde yol vardır, oturum kimliği değil.
 */
func TestFileHistoryFindsEverySessionThatTouchedAPath(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-a")

	if err := s.StartSession(ctx, SessionStart{
		ID: "sess-b", Username: "yigit", TargetName: "web01",
		OSUser: "yigit", SrcIP: "10.0.0.2", StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().Truncate(time.Second)
	if err := s.AddSessionFiles(ctx, "sess-a", []SessionFile{
		{At: now, Op: "transfer", Path: "/etc/shadow", Read: 100, OK: true},
		{At: now, Op: "transfer", Path: "/tmp/other", Read: 5, OK: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSessionFiles(ctx, "sess-b", []SessionFile{
		{At: now.Add(time.Minute), Op: "transfer", Path: "/etc/shadow", Read: 200, OK: true},
	}); err != nil {
		t.Fatal(err)
	}

	hist, err := s.FileHistory(ctx, FileQuery{Path: "/etc/shadow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("geçmiş = %d satır, 2 bekleniyordu: %+v", len(hist), hist)
	}
	seen := map[string]bool{}
	for _, h := range hist {
		seen[h.SessionID] = true
		if h.Path != "/etc/shadow" {
			t.Errorf("başka yol karıştı: %q", h.Path)
		}
	}
	if !seen["sess-a"] || !seen["sess-b"] {
		t.Errorf("iki oturum da bulunmadı: %+v", hist)
	}
	// En yeni başta: soruşturma en son ne olduğuna bakar.
	if hist[0].SessionID != "sess-b" {
		t.Errorf("sıra en yeniden eskiye değil: %+v", hist)
	}
}

/*
 * ⚠️ YA HEPSİ YA HİÇBİRİ.
 *
 * Yarım yazılmış bir grup, "dosya açıldı ama hiç kapanmadı" gibi
 * görünen uydurma bir denetim satırı bırakırdı.
 */
func TestSessionFilesBatchIsAllOrNothing(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-atomic")

	now := time.Now()
	err := s.AddSessionFiles(ctx, "sess-atomic", []SessionFile{
		{At: now, Op: "open", Path: "/a", OK: true},
		// ⚠️ İkinci satır CHECK'i deviriyor (op boş olamaz).
		{At: now, Op: "", Path: "/b", OK: true},
	})
	if err == nil {
		t.Fatal("geçersiz satır kabul edildi")
	}

	got, err := s.SessionFiles(ctx, "sess-atomic")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("grup başarısızken %d satır yazılmış: %+v — yarım yazım "+
			"uydurma bir denetim satırı bırakır", len(got), got)
	}
}

// Olayları olmayan oturum boş liste dönmeli (nil değil): JSON'da "null"
// ile "[]" farkı, panelde "bilinmiyor" ile "yok" farkına dönüşür.
func TestSessionFilesEmptyIsAList(t *testing.T) {
	s := newTestStore(t)
	startFileSession(t, s, "sess-empty")

	got, err := s.SessionFiles(context.Background(), "sess-empty")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("nil dilim döndü — JSON'da null olur ve panelde 'bilinmiyor' okunur")
	}
	if len(got) != 0 {
		t.Fatalf("beklenmeyen satır: %+v", got)
	}
}

/*
 * ⚠️ CEVAP BİR UUID DEĞİL, BİR KİŞİ.
 *
 * "Kim aldı" sorusuna oturum kimliğiyle cevap vermek, denetçiyi her
 * satır için ayrı bir sorguya mecbur bırakır — ve pratikte soruyu
 * cevapsız bırakır.
 */
func TestFileHistoryNamesThePerson(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-who")

	now := time.Now().Truncate(time.Second)
	if err := s.AddSessionFiles(ctx, "sess-who", []SessionFile{
		{At: now, Op: "transfer", Path: "/etc/shadow", Read: 100, OK: true},
	}); err != nil {
		t.Fatal(err)
	}

	hist, err := s.FileHistory(ctx, FileQuery{Path: "/etc/shadow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 {
		t.Fatalf("geçmiş = %d satır, 1 bekleniyordu", len(hist))
	}
	if hist[0].User != "yigit" {
		t.Errorf("kullanıcı = %q, \"yigit\" bekleniyordu", hist[0].User)
	}
	if hist[0].Target != "web01" {
		t.Errorf("hedef = %q, \"web01\" bekleniyordu", hist[0].Target)
	}
	if hist[0].OSUser != "yigit" || hist[0].SrcIP != "10.0.0.1" {
		t.Errorf("oturum üstverisi eksik: %+v", hist[0])
	}
}

/*
 * ⚠️ DOSYA ORAYA BİR RENAME İLE GELMİŞ OLABİLİR.
 *
 * "/tmp/exfil buraya nereden geldi" sorusunda aranan yol satırın
 * `path`inde değil `new_path`inde durur. Yalnızca `path`e bakan bir
 * arama "hiç dokunulmamış" derdi — dosyayı oraya taşıyan satır
 * elimizdeyken. Sızdırmanın en ucuz biçimini görünmez yapardı.
 */
func TestFileHistoryFindsTheDestinationOfARename(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-rename")

	now := time.Now().Truncate(time.Second)
	if err := s.AddSessionFiles(ctx, "sess-rename", []SessionFile{
		{At: now, Op: "rename", Path: "/etc/shadow",
			NewPath: "/tmp/exfil", OK: true},
	}); err != nil {
		t.Fatal(err)
	}

	hist, err := s.FileHistory(ctx, FileQuery{Path: "/tmp/exfil"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 {
		t.Fatalf("hedef yol üzerinden bulunamadı: %d satır", len(hist))
	}
	if hist[0].Op != "rename" || hist[0].Path != "/etc/shadow" {
		t.Errorf("beklenen rename satırı değil: %+v", hist[0])
	}
}

/*
 * ⚠️ BOŞ ARAMA REDDEDİLİYOR.
 *
 * Satırların çoğunda new_path boş. Koşulun ikinci yarısı korumasız
 * kalsaydı, boş bir arama tabloda ne varsa döner ve denetçiye aradığı
 * dosyanın geçmişi diye rastgele bir liste gösterirdi — yanlış cevabın
 * en pahalı biçimi, çünkü dolu bir ekran "bulundu" gibi okunur.
 */
func TestFileHistoryRefusesAnEmptyQuery(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-empty")

	now := time.Now().Truncate(time.Second)
	if err := s.AddSessionFiles(ctx, "sess-empty", []SessionFile{
		{At: now, Op: "transfer", Path: "/etc/shadow", Read: 1, OK: true},
	}); err != nil {
		t.Fatal(err)
	}

	hist, err := s.FileHistory(ctx, FileQuery{})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("ölçütsüz arama kabul edildi: err=%v, %d satır döndü", err, len(hist))
	}
}

// seedTouch, verilen oturuma tek bir dosya olayı yazar.
func seedTouch(t *testing.T, s *Store, session string, f SessionFile) {
	t.Helper()
	if f.At.IsZero() {
		f.At = time.Now().Truncate(time.Second)
	}
	if f.Op == "" {
		f.Op = "transfer"
	}
	if err := s.AddSessionFiles(context.Background(), session, []SessionFile{f}); err != nil {
		t.Fatal(err)
	}
}

// twoUserStore, iki farklı kişinin iki farklı hedefte oturumu.
func twoUserStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-yigit") // yigit @ web01

	if _, err := s.CreateUser(ctx, "ayse", "", "ayse"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTarget(ctx, model.Target{
		Name: "db01", Host: "10.0.0.9", Port: 22, HostKey: testHostKey,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.StartSession(ctx, SessionStart{
		ID: "sess-ayse", Username: "ayse", TargetName: "db01",
		OSUser: "ayse", SrcIP: "10.0.0.2", StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

/*
 * ⚠️ SÜZGEÇ SUNUCUDA OLMALI, TABLODA DEĞİL.
 *
 * Panel gelen satırları istemcide süzüyor ve sunucu en fazla 200 satır
 * dönüyor. "ayse" yazan denetçi, ayse'nin 500 olayı varken BOŞ sonuç
 * görebilirdi — ve boş sonucu "ayse dokunmamış" diye okurdu. Süzgecin
 * sorguya inmesinin sebebi kolaylık değil, bu.
 */
func TestFileHistoryFiltersByUser(t *testing.T) {
	ctx := context.Background()
	s := twoUserStore(t)

	seedTouch(t, s, "sess-yigit", SessionFile{Path: "/srv/ortak.txt", OK: true})
	seedTouch(t, s, "sess-ayse", SessionFile{Path: "/srv/ortak.txt", OK: true})

	hist, err := s.FileHistory(ctx, FileQuery{Path: "/srv/ortak.txt", User: "ayse"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0].User != "ayse" {
		t.Fatalf("kullanıcı süzgeci tutmadı: %+v", hist)
	}
}

/*
 * ⚠️ KULLANICI ADLARI HARF DUYARSIZ EŞLEŞİYOR.
 *
 * users.username dialect.go'daki ciColumns'ta ve 009'da lower() indeksi
 * var: dizin "Ayse" ile "ayse"yi aynı kişi sayıyor. Düz "=" kullanan
 * bir süzgeç, "Ayse" yazan denetçiye boş sonuç gösterirdi — yani
 * yazımı yüzünden "hiç dokunmamış" derdi.
 */
func TestFileHistoryUserFilterIgnoresCase(t *testing.T) {
	ctx := context.Background()
	s := twoUserStore(t)
	seedTouch(t, s, "sess-ayse", SessionFile{Path: "/srv/ortak.txt", OK: true})

	hist, err := s.FileHistory(ctx, FileQuery{Path: "/srv/ortak.txt", User: "AySe"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 {
		t.Fatalf("harf duyarsız eşleşme tutmadı: %d satır", len(hist))
	}
}

// Hedef süzgeci de aynı sözleşmede.
func TestFileHistoryFiltersByTarget(t *testing.T) {
	ctx := context.Background()
	s := twoUserStore(t)
	seedTouch(t, s, "sess-yigit", SessionFile{Path: "/srv/ortak.txt", OK: true})
	seedTouch(t, s, "sess-ayse", SessionFile{Path: "/srv/ortak.txt", OK: true})

	hist, err := s.FileHistory(ctx, FileQuery{Path: "/srv/ortak.txt", Target: "DB01"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0].Target != "db01" {
		t.Fatalf("hedef süzgeci tutmadı: %+v", hist)
	}
}

/*
 * ⚠️ YOL ZORUNLU DEĞİL: "ayse ne aldı" kendi başına bir soru.
 *
 * Soruşturmanın ikinci sorusu bu ve bir yol aramasının süzgeci olarak
 * sorulamaz — hangi dosyaya baktığını bilmiyorsun, zaten onu arıyorsun.
 */
func TestFileHistoryFindsEverythingOnePersonTouched(t *testing.T) {
	ctx := context.Background()
	s := twoUserStore(t)
	seedTouch(t, s, "sess-ayse", SessionFile{Path: "/srv/bir.txt", OK: true})
	seedTouch(t, s, "sess-ayse", SessionFile{Path: "/srv/iki.txt", OK: true})
	seedTouch(t, s, "sess-yigit", SessionFile{Path: "/srv/uc.txt", OK: true})

	hist, err := s.FileHistory(ctx, FileQuery{User: "ayse"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("kişinin tüm olayları = %d satır, 2 bekleniyordu: %+v", len(hist), hist)
	}
}

/*
 * ⚠️ "BU DİZİNİN ALTINDA NE OLDU" — soruşturmanın en sık sorduğu.
 *
 * Tam eşleşmeyle sorulamaz: ağacın altındaki her dosyanın adını
 * önceden bilmek gerekirdi.
 *
 * ⚠️ DİZİNİN KENDİSİ DE GELİYOR. `opendir /etc` satırının path'i tam
 * olarak "/etc"; yalnızca "/etc/%" arayan bir sorgu, dizinin
 * açıldığını gösteren satırı atlardı.
 */
func TestFileHistoryUnderFindsTheWholeTree(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-tree")

	seedTouch(t, s, "sess-tree", SessionFile{Op: "opendir", Path: "/etc", OK: true})
	seedTouch(t, s, "sess-tree", SessionFile{Path: "/etc/shadow", OK: true})
	seedTouch(t, s, "sess-tree", SessionFile{Path: "/etc/ssh/sshd_config", OK: true})
	// ⚠️ KOMŞU AĞAÇ: "/etc" öneki "/etcetera"yı da yakalasaydı,
	// soruşturmaya ilgisiz bir ağacı aradığı ağaç diye gösterirdik.
	seedTouch(t, s, "sess-tree", SessionFile{Path: "/etcetera/baska.txt", OK: true})

	hist, err := s.FileHistory(ctx, FileQuery{Path: "/etc", Under: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 3 {
		t.Fatalf("ağaç = %d satır, 3 bekleniyordu: %+v", len(hist), paths(hist))
	}
	for _, h := range hist {
		if h.Path == "/etcetera/baska.txt" {
			t.Error("komşu ağaç sonuca karıştı: /etcetera")
		}
	}
}

/*
 * ⚠️ LIKE JOKERLERİ KAÇIRILIYOR.
 *
 * "_" LIKE'ta "herhangi bir karakter" demek. Kaçırılmasaydı
 * "/var/log_1" ağacını arayan biri "/var/logX1"i de alırdı — sorgu
 * parametreli olduğu için bu bir enjeksiyon değil, sessizce YANLIŞ
 * SONUÇ; denetimde farkı yok.
 */
func TestFileHistoryUnderEscapesLikeWildcards(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-glob")

	seedTouch(t, s, "sess-glob", SessionFile{Path: "/var/log_1/a.txt", OK: true})
	seedTouch(t, s, "sess-glob", SessionFile{Path: "/var/logX1/a.txt", OK: true})

	hist, err := s.FileHistory(ctx, FileQuery{Path: "/var/log_1", Under: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0].Path != "/var/log_1/a.txt" {
		t.Fatalf("joker kaçırılmadı: %+v", paths(hist))
	}
}

// Under, yol olmadan anlamsız: sessizce "her şey"e düşmek en kötü yorum.
func TestFileHistoryRefusesUnderWithoutAPath(t *testing.T) {
	s := newTestStore(t)
	_, err := s.FileHistory(context.Background(), FileQuery{Under: true, User: "ayse"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("yolsuz 'under' kabul edildi: %v", err)
	}
}

/*
 * ⚠️ SUNUCU TARAFI ZAMAN SINIRI GERÇEKTEN UYGULANIYOR.
 *
 * Havuz 25 bağlantı ve onu SSH kimlik doğrulaması paylaşıyor
 * (auth.go: UserByPublicKey, AccountState). Sınırsız bir arama, bir
 * bağlantıyı bitene kadar tutup insanların bastion'a girmesini
 * geciktirirdi. Bu testi yazmasaydık koruma yalnızca yorumda kalırdı.
 */
func TestSearchStopsAtTheServerSideTimeout(t *testing.T) {
	s := newTestStore(t)
	s.SetSearchTimeoutForTest(150 * time.Millisecond)

	start := time.Now()
	err := s.searchRows(context.Background(), "test.sleep",
		"SELECT pg_sleep(5);", nil, func(*sql.Rows) error { return nil })
	elapsed := time.Since(start)

	if !errors.Is(err, ErrTooSlow) {
		t.Fatalf("sorgu durdurulmadı: %v", err)
	}

	/*
	 * ⚠️ SÜRE DE ÖLÇÜLÜYOR — VE BU DÜZELTME BİR İNCELEMEDEN GELDİ.
	 *
	 * Test önce yalnızca ErrTooSlow'a bakıyordu. translateSearchErr
	 * hem sunucu tarafı 57014'ü hem istemci tarafı süreyi aynı
	 * sentinel'e çevirdiği için, SET LOCAL tamamen silinse bile
	 * istemci sayacı (limit+clientGrace) devreye girip AYNI hatayı
	 * üretiyordu: test geçmeye devam ediyordu. Mutasyonla doğrulandı.
	 *
	 * Sunucu tarafı sınır 150 ms; istemci payı 3 saniye. Bir saniyelik
	 * tavan ikisini kesin ayırıyor — hangi sayacın durdurduğunu
	 * ölçülebilir hâle getiren tek şey bu.
	 */
	if elapsed > time.Second {
		t.Fatalf("sorgu %s sonra durdu: sunucu tarafı sınır değil, "+
			"istemci payı devreye girmiş olmalı", elapsed.Round(time.Millisecond))
	}
}

/*
 * ⚠️ SONDAKİ EĞİK ÇİZGİ, "DOKUNULMAMIŞ" DEMEK DEĞİL.
 *
 * "/etc/" düz birleştirmeyle "/etc//%" desenine dönüyordu ve o desen
 * hiçbir şeyle eşleşmiyor. Sorgu başarıyla bitip sıfır satır dönüyordu:
 * ekran "Nothing found" yazıyor, denetçi bunu "bu ağaca dokunulmamış"
 * diye okuyordu. Kabuk tamamlaması dizin adlarının sonuna eğik çizgi
 * ekliyor — olağan girdi.
 */
func TestFileHistoryUnderToleratesATrailingSlash(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-slash")

	seedTouch(t, s, "sess-slash", SessionFile{Op: "opendir", Path: "/etc", OK: true})
	seedTouch(t, s, "sess-slash", SessionFile{Path: "/etc/shadow", OK: true})

	for _, in := range []string{"/etc", "/etc/", "/etc//"} {
		hist, err := s.FileHistory(ctx, FileQuery{Path: in, Under: true})
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if len(hist) != 2 {
			t.Errorf("%q → %d satır, 2 bekleniyordu: %+v", in, len(hist), paths(hist))
		}
	}
}

/*
 * ⚠️ KÖK DİZİN DE ARANABİLMELİ.
 *
 * "/" için desen "//%" oluyordu ve hiçbir şeyle eşleşmiyordu — yani
 * "bu bastion'da SFTP ile ne oldu" sorusu boş cevap alıyordu.
 */
func TestFileHistoryUnderRootFindsEverything(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-root")

	seedTouch(t, s, "sess-root", SessionFile{Path: "/etc/shadow", OK: true})
	seedTouch(t, s, "sess-root", SessionFile{Path: "/srv/a.txt", OK: true})

	hist, err := s.FileHistory(ctx, FileQuery{Path: "/", Under: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("kök ağacı = %d satır, 2 bekleniyordu: %+v", len(hist), paths(hist))
	}
}

// CleanSearchPath, ucun yankıladığı değeri de üretiyor: normalleştirme
// yalnızca sorguda kalırsa panel neyin arandığını yanlış gösterir.
func TestCleanSearchPath(t *testing.T) {
	for in, want := range map[string]string{
		"/etc/":  "/etc",
		"/etc//": "/etc",
		"/etc":   "/etc",
		"/":      "/",
		"//":     "/",
		"etc/":   "etc",
		"":       "",
	} {
		if got := CleanSearchPath(in); got != want {
			t.Errorf("CleanSearchPath(%q) = %q, %q bekleniyordu", in, got, want)
		}
	}
}

func paths(hist []FileTouch) []string {
	out := make([]string, 0, len(hist))
	for _, h := range hist {
		out = append(out, h.Path)
	}
	return out
}
