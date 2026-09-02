package record

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// write, verilen yaşta bir kayıt dosyası bırakır.
func write(t *testing.T, dir, day, name string, age time.Duration, size int) string {
	t.Helper()
	d := filepath.Join(dir, day)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, name)
	if err := os.WriteFile(p, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatal(err)
	}
	return p
}

/*
 * ⚠️ BUDAMA DEĞİŞTİRİLME ZAMANINA BAKIYOR, DİZİN ADINA DEĞİL.
 *
 * Dizin adı kaydın AÇILDIĞI günü söylüyor; uzun süren bir oturum
 * ertesi güne sarkabiliyor ve hâlâ YAZILIYOR olabilir. Ada bakan bir
 * budayıcı, o dosyayı yazılırken silerdi — yani tam da tutulmakta olan
 * kaydı.
 */
func TestPruneUsesModTimeNotDirectoryName(t *testing.T) {
	dir := t.TempDir()

	// Eski adlı dizinde YENİ yazılmış bir dosya: kalmalı.
	fresh := write(t, dir, "2020-01-01", "acik.cast", time.Minute, 10)
	// Aynı dizinde gerçekten eski bir dosya: gitmeli.
	old := write(t, dir, "2020-01-01", "eski.cast", 200*24*time.Hour, 100)

	res, err := Prune(context.Background(), dir, 90*24*time.Hour, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 1 || res.Bytes != 100 {
		t.Fatalf("sonuç = %+v", res)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("hâlâ yazılıyor olabilecek dosya silindi — " +
			"dizin adına bakan bir budayıcı tam da tutulan kaydı siler")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("eski dosya silinmedi")
	}
}

/*
 * ⚠️ SIFIR SÜRE HİÇBİR ŞEY SİLMİYOR.
 *
 * Bu fonksiyonun yanlış çağrılması bütün denetim kaydını silmek demek;
 * "ayar verilmemiş" hâlinin "hepsini sil" olarak okunması, olabilecek
 * en pahalı sıfır değeri olurdu.
 */
func TestPruneWithZeroKeepsEverything(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "2020-01-01", "a.cast", 10000*time.Hour, 10)

	for _, d := range []time.Duration{0, -time.Hour} {
		res, err := Prune(context.Background(), dir, d, time.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Files != 0 {
			t.Fatalf("keepFor=%v ile %d dosya silindi", d, res.Files)
		}
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("sıfır süreyle dosya silinmiş")
	}
}

// Boşalan gün dizini kaldırılıyor; boşalmayan DURUYOR. RemoveAll
// kullansaydık, silemediğimiz bir dosyayı da götürürdü.
func TestPruneRemovesOnlyEmptiedDays(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "2020-01-01", "a.cast", 200*24*time.Hour, 1)
	write(t, dir, "2020-01-02", "a.cast", 200*24*time.Hour, 1)
	write(t, dir, "2020-01-02", "b.cast", time.Minute, 1)

	res, err := Prune(context.Background(), dir, 90*24*time.Hour, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Dirs != 1 {
		t.Fatalf("kaldırılan dizin = %d, 1 bekleniyordu", res.Dirs)
	}
	if _, err := os.Stat(filepath.Join(dir, "2020-01-01")); !os.IsNotExist(err) {
		t.Error("boşalan gün dizini kaldırılmadı")
	}
	if _, err := os.Stat(filepath.Join(dir, "2020-01-02", "b.cast")); err != nil {
		t.Error("dolu gün dizinindeki yeni dosya silinmiş")
	}
}

/*
 * ⚠️ EŞİK: SIFIR "KAPALI" DEMEK, "her zaman reddet" DEĞİL.
 * Ayarın yokluğu bir kapıyı kapatmamalı.
 */
func TestCheckSpace(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.CheckSpace(0); err != nil {
		t.Fatalf("kapalı eşik reddetti: %v", err)
	}
	// Makul bir eşik geçmeli (test diskinde 1 bayt boş yer var).
	if err := s.CheckSpace(1); err != nil {
		t.Fatalf("1 baytlık eşik reddetti: %v", err)
	}
	// Absürt bir eşik reddetmeli — ve sebebi ErrDiskLow olmalı ki
	// çağıran "kayıt dosyası açılamadı"dan ayırabilsin.
	huge := uint64(1) << 62
	err = s.CheckSpace(huge)
	if err == nil {
		t.Fatal("absürt eşik geçti")
	}
	if !errorIs(err, ErrDiskLow) {
		t.Fatalf("hata ErrDiskLow değil: %v", err)
	}
}

func errorIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// Kullanım sayısı: operatör ne kadar yer kapladığını göremeden bir
// saklama süresi seçemez.
func TestUsage(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "2020-01-01", "a.cast", time.Hour, 100)
	write(t, dir, "2020-01-02", "b.cast", time.Hour, 250)

	files, bytes, skipped, err := Usage(dir)
	if err != nil {
		t.Fatal(err)
	}
	if files != 2 || bytes != 350 {
		t.Fatalf("kullanım = %d dosya %d bayt", files, bytes)
	}
	// Okunabilir bir ağaçta atlanan giriş olmamalı: sayaç yalnızca
	// gerçek bir eksikliği bildirmeli, yoksa uyarı gürültüye döner.
	if skipped != 0 {
		t.Errorf("sağlam dizinde %d giriş atlandı", skipped)
	}
}

/*
 * ⚠️ BUDAYICI KAPALIYKEN nil ve Start onu SESSİZCE geçiyor.
 *
 * Çağıranın ayrıca "açık mı" diye sorması gerekseydi, aynı kararı iki
 * yerde tutardık ve biri geride kalırdı.
 */
func TestNewPrunerIsNilWhenOff(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	for _, d := range []time.Duration{0, -time.Hour} {
		if p := NewPruner(t.TempDir(), d, logger); p != nil {
			t.Errorf("keepFor=%v ile budayıcı kuruldu", d)
		}
	}
	// nil budayıcı üzerinde Start panik etmemeli.
	var p *Pruner
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.Start(ctx)
}

/*
 * ⚠️ KISMİ TOPLAM, TAM TOPLAM GİBİ DÖNMEMELİ.
 *
 * Usage okunamayan alt ağaçları atlayıp devam ediyor — kasıtlı, çünkü
 * eksik bir sayı hiç sayı olmamasından iyi. Ama eskiden bunu söylemenin
 * yolu yoktu: `err == nil` dönüyordu ve çağıran eksik toplamı tam
 * sanıyordu. Disk raporu "5 GB" derken gerçekte 40 GB olabilir, ve
 * saklama süresi o rapora bakılarak seçiliyor.
 */
func TestUsageReportsWhatItCouldNotRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.cast"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "kilitli")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "b.cast"), []byte("gizli"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Okuma izni kaldırılınca WalkDir bu alt ağaca giremiyor.
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	files, _, skipped, err := Usage(dir)
	if err != nil {
		t.Fatalf("okunamayan alt ağaç bütün ölçümü düşürdü: %v", err)
	}
	if files != 1 {
		t.Errorf("okunabilen dosya = %d, 1 bekleniyordu", files)
	}
	if skipped == 0 {
		t.Error("okunamayan alt ağaç sessizce yutuldu: toplam eksik ama 'tam' diye dönüyor")
	}
}
