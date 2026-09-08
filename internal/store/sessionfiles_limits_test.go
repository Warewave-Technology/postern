package store

// Defterin GERÇEKTEN kabul ettiği satır.
//
// ⚠️ BU DOSYA BİR SAYIYI ÇİVİLİYOR. sftpaudit'in yol sınırı buradaki
// ölçüme dayanıyor ve o sayı yanlışsa arıza sessiz: satır düşer, grup tek
// transaction olduğu için oturumun bütün dosya olayları onunla gider.
// Sınır kaynak koddan okunamadığı için gerçek sunucuya soruyoruz.
//
// Zincirin tamamı (sftpaudit → günlükçü → defter) proxy tarafında
// ölçülüyor: TestSFTPEventsWithHostilePathsStillLandInTheLedger.

import (
	"context"
	"encoding/hex"
	"errors"
	"math/rand"
	"strings"
	"testing"
)

/*
 * incompressiblePath, SIKIŞMAYAN bir yol üretir.
 *
 * ⚠️ TEKRARLI BİR DİZE SINIRI GİZLİYOR. PostgreSQL indeks girdisini
 * gerekirse sıkıştırıyor: strings.Repeat("a", 9000) ile kurulan bir yol
 * sorunsuz yazılıyor ve "sınır yokmuş" izlenimi veriyor. Sınır veriye
 * bağlı; güvenli olan en kötü hâl, yani sıkışmayan veri.
 */
func incompressiblePath(n int) string {
	r := rand.New(rand.NewSource(int64(n)))
	raw := make([]byte, n)
	r.Read(raw)
	return ("/" + hex.EncodeToString(raw))[:n]
}

/*
 * ⚠️ SINIRIN ÖLÇÜMÜ. Gerekçe yorumlarındaki 2692 sayısı buradan geliyor:
 *
 *	index row size 2712 exceeds btree version 4 maximum 2704
 *	for index "session_files_path_idx"  (SQLSTATE 54000)
 *
 * Reddin ErrInvalid olarak SINIFLANDIĞI da burada duruyor: günlükçünün
 * "tekrar deneme, bu satır asla yazılamaz" kararı ona dayanıyor.
 */
func TestBtreeRejectsAPathOverTheIndexLimit(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-limit")

	const measured = 2692 // postgres:17-alpine, btree version 4

	if err := s.AddSessionFiles(ctx, "sess-limit", []SessionFile{
		{Op: "open", Path: incompressiblePath(measured), OK: true},
		// new_path'in de indeksi var (göç 030 ve 031); tek yolu ölçüp
		// diğerini varsaymak aynı arızayı rename satırlarında bırakırdı.
		{Op: "rename", Path: "/a", NewPath: incompressiblePath(measured), OK: true},
	}); err != nil {
		t.Fatalf("%d bayt reddedildi; sınır sanılandan DAHA DAR: %v", measured, err)
	}

	err := s.AddSessionFiles(ctx, "sess-limit", []SessionFile{
		{Op: "open", Path: incompressiblePath(measured + 1), OK: true},
	})
	if err == nil {
		t.Fatalf("%d bayt kabul edildi; sınır genişlemiş olabilir — "+
			"sftpaudit'in yol sınırı gereksiz yere dar kalmış demektir", measured+1)
	}
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("uzun yol reddi ErrInvalid olarak sınıflanmadı: %v\n"+
			"günlükçü bunu GEÇİCİ arıza sanıp satırı sonsuza kadar "+
			"yeniden dener ve defteri tıkar", err)
	}
}

/*
 * ⚠️ UZUN YOLDAN DAHA KOLAY ULAŞILAN RET: GEÇERSİZ UTF-8 VE NUL.
 *
 * SFTP dosya adı ham bayt dizisi. Latin-1 adlandırılmış tek bir dosya
 * satırı yazılamaz kılıyor — iç içe dizin açmayı bile gerektirmeden.
 */
func TestUnstorableBytesAreRejectedAsInvalid(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-limit")

	cases := map[string]SessionFile{
		"latin-1 dosya adı": {Op: "open", Path: "/home/ali/rapor-\xe7\xf6\xfc.txt"},
		"yolda NUL":         {Op: "open", Path: "/tmp/a\x00b"},
		"gerekçede latin-1": {Op: "open", Path: "/tmp/a", Detail: "izin yok \xff"},
		"hedef yolda":       {Op: "rename", Path: "/tmp/a", NewPath: "/tmp/\xfe"},
	}
	for name, f := range cases {
		err := s.AddSessionFiles(ctx, "sess-limit", []SessionFile{f})
		if err == nil {
			t.Errorf("%s: kabul edildi — sürücü sessizce temizliyor olabilir", name)
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: ErrInvalid olarak sınıflanmadı: %v", name, err)
		}
	}
}

/*
 * ⚠️ SINIFLANDIRMA "HER HATA KALICI"YA KAYMAMALI.
 *
 * Günlükçü kalıcı reddi ayıklayıp atıyor; geçici arızada ise satırları
 * geri koyuyor. Ayrım yanlış tarafa kaysaydı bir veritabanı kesintisi,
 * bekleyen bütün denetim satırlarının atılması demek olurdu. Kapalı bir
 * havuz, bağlantı arızasının elimizdeki en yakın taklidi.
 */
func TestAConnectionFailureIsNotClassifiedAsPermanent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-limit")
	s.Close()

	err := s.AddSessionFiles(ctx, "sess-limit", []SessionFile{{Op: "open", Path: "/a"}})
	if err == nil {
		t.Fatal("kapalı havuza yazma başarılı görünüyor")
	}
	if errors.Is(err, ErrInvalid) {
		t.Fatalf("bağlantı arızası KALICI RET olarak sınıflandı: %v\n"+
			"günlükçü bu hâlde bütün tamponu 'yazılamaz' diye atardı", err)
	}
}

/*
 * Kesilmiş yol ARANABİLİR kalıyor.
 *
 * Sınır aşıldığında yolu atmak yerine kesmenin sebebi bu: önek üzerinden
 * ağaç araması (göç 031) çalışmaya devam ediyor, "bu dizinin altında ne
 * oldu" cevapsız kalmıyor. İndeksi hash'e / md5(path) ifadesine çevirmek
 * tam da bunu kaybettirirdi.
 */
func TestATruncatedPathIsStillFoundUnderItsParent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-limit")

	const parent = "/veri/derin"
	truncated := parent + "/" + strings.Repeat("k/", 1200) + " (truncated)"
	if err := s.AddSessionFiles(ctx, "sess-limit", []SessionFile{
		{Op: "open", Path: truncated, OK: true},
	}); err != nil {
		t.Fatalf("AddSessionFiles: %v", err)
	}

	got, err := s.FileHistory(ctx, FileQuery{Path: parent, Under: true})
	if err != nil {
		t.Fatalf("FileHistory: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("kesilmiş yol üst dizininden bulunamadı: %d satır", len(got))
	}
}
