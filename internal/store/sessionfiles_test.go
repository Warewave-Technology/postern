package store

import (
	"context"
	"errors"
	"testing"
	"time"
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

	hist, err := s.FileHistory(ctx, "/etc/shadow", 0)
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

	hist, err := s.FileHistory(ctx, "/etc/shadow", 0)
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

	hist, err := s.FileHistory(ctx, "/tmp/exfil", 0)
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
func TestFileHistoryRefusesAnEmptyPath(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-empty")

	now := time.Now().Truncate(time.Second)
	if err := s.AddSessionFiles(ctx, "sess-empty", []SessionFile{
		{At: now, Op: "transfer", Path: "/etc/shadow", Read: 1, OK: true},
	}); err != nil {
		t.Fatal(err)
	}

	hist, err := s.FileHistory(ctx, "", 0)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("boş yol kabul edildi: err=%v, %d satır döndü", err, len(hist))
	}
}
