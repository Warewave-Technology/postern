package hostacct

import (
	"context"
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * ⚠️ NUMARA İZİN İÇİNDE OLMAK ZORUNDA.
 *
 * Dizin bir kişiye numara vermeye yeni başladığında istenen durum
 * gerçekten değişiyor. İz bunu görmezse hızlı şerit hedefe hiç uğramaz ve
 * kişi o makinede sonsuza dek eski numarasıyla kalır — yani numarayı
 * düzeltmenin hiçbir yolu kalmaz.
 */
func TestTheNumberIsPartOfTheFingerprint(t *testing.T) {
	without := Compute(testUser, testTarget, nil, Account{})
	with := Compute(testUser, testTarget, nil, Account{UID: 60001})
	other := Compute(testUser, testTarget, nil, Account{UID: 60002})

	if without.Fingerprint == with.Fingerprint {
		t.Error("numara verilmesi izi değiştirmedi")
	}
	if with.Fingerprint == other.Fingerprint {
		t.Error("farklı numaralar aynı izi verdi")
	}
	if with.UID != 60001 {
		t.Errorf("Want.UID = %d", with.UID)
	}
}

/*
 * ⚠️ ÇAKIŞMA SESSİZ KALMIYOR.
 *
 * Numara hedefte başka bir hesabın üstündeyse hesap hedefin kendi
 * numarasıyla açılıyor — doğru karar, ama kişi o makinede filo
 * numarasını taşımıyor demek. "Neden bu makinede numarası farklı"
 * sorusunun cevabı başka hiçbir yerde yok; deftere yazılmazsa kaybolur.
 */
func TestAUIDConflictIsWrittenToTheLedger(t *testing.T) {
	dialed := 0
	d := baseDeps(&dialed, nil)
	d.UID = func(context.Context, model.User) (int, error) { return 60001, nil }
	d.Connect = func(context.Context, model.Target, string) (Runner, error) {
		dialed++

		return &fakeRunner{answers: map[string]string{
			"getent passwd 60001": "backup:x:60001:60001::/var/backups:/bin/sh\n",
		}}, nil
	}
	var details []string
	d.Audit = func(_ context.Context, _, detail string) error {
		details = append(details, detail)

		return nil
	}

	if out := Ensure(t.Context(), d, testUser, testTarget); out.Reason != "" {
		t.Fatalf("hazırlama başarısız: %+v", out)
	}

	found := ""
	for _, s := range details {
		if strings.Contains(s, "uid conflict") {
			found = s
		}
	}
	if found == "" {
		t.Fatalf("çakışma deftere yazılmadı: %v", details)
	}
	for _, must := range []string{"ayse", "60001", "backup"} {
		if !strings.Contains(found, must) {
			t.Errorf("satırda %q yok: %q", must, found)
		}
	}
}

// Numara boşken çakışma satırı yazılmıyor — defter gürültüyle dolmamalı.
func TestAFreeNumberWritesNoConflictLine(t *testing.T) {
	dialed := 0
	d := baseDeps(&dialed, nil)
	d.UID = func(context.Context, model.User) (int, error) { return 60001, nil }
	var details []string
	d.Audit = func(_ context.Context, _, detail string) error {
		details = append(details, detail)

		return nil
	}

	if out := Ensure(t.Context(), d, testUser, testTarget); out.Reason != "" {
		t.Fatalf("hazırlama başarısız: %+v", out)
	}
	for _, s := range details {
		if strings.Contains(s, "uid conflict") {
			t.Fatalf("boş numarada çakışma yazıldı: %q", s)
		}
	}
}

/*
 * ⚠️ NUMARA ALINAMAZSA OTURUM DURMUYOR.
 *
 * Havuz dolduğunda ya da veritabanı cevap vermediğinde hesabın hiç
 * açılmaması, postern'i girişin önündeki tek hata noktasına çevirirdi
 * (K6). Numarasız hesap, kapalı kapıdan iyi.
 */
func TestAccountsAreStillOpenedWhenNoNumberCanBeTaken(t *testing.T) {
	dialed := 0
	var saved store.HostAccount
	d := baseDeps(&dialed, &saved)
	d.UID = func(context.Context, model.User) (int, error) {
		return 0, store.ErrConflict
	}

	out := Ensure(t.Context(), d, testUser, testTarget)
	if out.Reason != "" {
		t.Fatalf("numara alınamayınca hazırlama durdu: %+v", out)
	}
	if saved.State != store.HostAccountActive {
		t.Errorf("satır durumu = %q", saved.State)
	}
}
