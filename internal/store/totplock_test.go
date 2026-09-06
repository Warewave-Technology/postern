package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/secret"
)

/*
 * withTOTP, doğrulanmış bir doğrulayıcısı olan hesap kurar.
 *
 * ⚠️ KUTU BURADA KURULUYOR, ORTAK YARDIMCIDA DEĞİL. BeginTOTP mühürleme
 * anahtarı olmadan reddediyor (göç 033), ama kutuyu paylaşılan
 * newTestStore'a koymak onu İSTEMEYEN testlerin de davranışını sessizce
 * değiştirir — daha önce tam olarak bu ölçüldü.
 */
func withTOTP(t *testing.T, s *Store, name string) {
	t.Helper()
	ctx := context.Background()

	box, err := secret.Init(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	s.UseSecretBox(box)

	if _, err := s.CreateUser(ctx, name, name+"@warewave.io", name); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginTOTP(ctx, name, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmTOTP(ctx, name, 1); err != nil {
		t.Fatal(err)
	}
}

/*
 * Sayaç artıyor ve eşikte kilit KURULUYOR.
 *
 * ⚠️ SAYMA VE KİLİTLEME TEK İFADEDE olmak zorunda: iki adıma bölseydik
 * paralel denemeler aynı sayıyı okur, aynı değeri yazar ve eşik hiç
 * geçilmeyebilirdi. Saldırganın yapabileceği en kolay şey paralel denemek.
 */
func TestTOTPFailuresLockAtTheThreshold(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	withTOTP(t, s, "ayse")

	for i := 1; i <= 2; i++ {
		l, err := s.TOTPFailure(ctx, "ayse", 3, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if l.Failures != i {
			t.Fatalf("%d. denemede sayaç %d", i, l.Failures)
		}
		if l.Locked(time.Now()) {
			t.Fatalf("%d. denemede kilitlendi; eşik 3", i)
		}
	}

	l, err := s.TOTPFailure(ctx, "ayse", 3, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Locked(time.Now()) {
		t.Fatal("eşiğe ulaşıldı ama kilit kurulmadı")
	}
}

// Kilit SÜRELİ: süresi geçmiş bir kilit artık kilit değil.
func TestExpiredLockIsNotALock(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	withTOTP(t, s, "ayse")

	// Negatif süre: kilit geçmişte bitiyor.
	if _, err := s.TOTPFailure(ctx, "ayse", 1, -time.Minute); err != nil {
		t.Fatal(err)
	}

	l, err := s.TOTPLockState(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if l.Locked(time.Now()) {
		t.Fatal("süresi dolmuş kilit hâlâ kilitliyor")
	}
	if l.Failures != 1 {
		t.Errorf("sayaç %d", l.Failures)
	}
}

/*
 * Başarılı giriş sayacı sıfırlıyor ve ÖNCEKİ değeri döndürüyor.
 *
 * ⚠️ ÖNCEKİ DEĞER OLMADAN kullanıcıya "son girişinizden bu yana N
 * başarısız deneme" diyemezdik — istenen bilgi tam olarak bu.
 */
func TestClearReturnsWhatItCleared(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	withTOTP(t, s, "ayse")

	for range 3 {
		if _, err := s.TOTPFailure(ctx, "ayse", 0, 0); err != nil {
			t.Fatal(err)
		}
	}

	prev, err := s.ClearTOTPFailures(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if prev != 3 {
		t.Fatalf("önceki sayaç %d, 3 bekleniyordu — kullanıcıya yanlış sayı gösterilir", prev)
	}

	l, err := s.TOTPLockState(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if l.Failures != 0 || l.Locked(time.Now()) {
		t.Fatalf("sıfırlanmadı: %+v", l)
	}
}

/*
 * ⚠️ KİLİT KAPATILABİLİR OLMALI ama sayaç yine tutulmalı.
 *
 * max <= 0 "kilit yok" demek; operatör kilidi kapattığında sayacı da
 * kaybetseydi "kaç deneme oldu" sorusu cevapsız kalırdı.
 */
func TestCountingWorksWithLockingOff(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	withTOTP(t, s, "ayse")

	for range 10 {
		if _, err := s.TOTPFailure(ctx, "ayse", 0, time.Hour); err != nil {
			t.Fatal(err)
		}
	}

	l, err := s.TOTPLockState(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if l.Locked(time.Now()) {
		t.Fatal("kilit kapalıyken kilitlendi")
	}
	if l.Failures != 10 {
		t.Errorf("sayaç %d, 10 bekleniyordu", l.Failures)
	}
}

/*
 * Yönetici kilidi açtığında SAYAÇ DA sıfırlanıyor.
 *
 * ⚠️ Yalnızca kilidi açmak, kullanıcının bir sonraki hatasında anında
 * yeniden kilitlenmesi demekti — müdahale neredeyse hiçbir şey
 * değiştirmezdi.
 */
func TestAdminUnlockAlsoClearsTheCounter(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	withTOTP(t, s, "ayse")

	for range 5 {
		if _, err := s.TOTPFailure(ctx, "ayse", 5, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UnlockTOTP(ctx, "ayse"); err != nil {
		t.Fatal(err)
	}

	l, err := s.TOTPLockState(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if l.Locked(time.Now()) || l.Failures != 0 {
		t.Fatalf("açılmadı: %+v", l)
	}
}

func TestUnlockOnAMissingAuthenticatorFails(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.UnlockTOTP(ctx, "yok"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("hata = %v, ErrNotFound bekleniyordu", err)
	}
}
