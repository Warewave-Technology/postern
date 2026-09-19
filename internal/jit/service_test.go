package jit

/*
 * Hedefe dokunmadan ölçülebilen kısımlar: doğrulama, denetim-önce kuralı ve
 * yeniden deneme aralıkları. Makineye giden yol test/integration/jit_test.go'da,
 * gerçek OpenSSH ve sudo üzerinde.
 */

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/ca"
	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/store"
	"github.com/Warewave-Technology/postern/v2/internal/testdb"
)

func testService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, testdb.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Init(t.TempDir() + "/ca")
	if err != nil {
		t.Fatal(err)
	}

	return New(db, authority, nil, slog.New(slog.NewTextHandler(io.Discard, nil))), db
}

/*
 * ⚠️ SÜRE SINIRLARI HEDEFE GİTMEDEN UYGULANIYOR. Bir dakikalık hak
 * uygulanmadan geri alınmaya başlar; otuz günden uzun hak "geçici"
 * değildir. İkisi de bağlantı açılmadan, deftere yazılmadan reddedilmeli —
 * defterde "granting" satırı olup arkasında hiçbir şey olmaması, hiç
 * denenmemiş bir hakkı denenmiş gösterirdi.
 */
func TestDurationLimitsAreCheckedBeforeAnythingIsTouched(t *testing.T) {
	svc, db := testService(t)
	ctx := context.Background()
	if _, err := db.CreateUser(ctx, "ayse", "", "ayse"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateTarget(ctx, model.Target{Name: "web01", Host: "127.0.0.1", Port: 1, HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMadSMEuPd6MwEOm1DvZUp9vfPWQOA4RKAen8D8Trxnf"}); err != nil {
		t.Fatal(err)
	}

	for _, d := range []time.Duration{time.Minute, MinDuration - time.Second, MaxDuration + time.Second, 0, -time.Hour} {
		_, err := svc.Grant(ctx, Request{Username: "ayse", Target: "web01", Duration: d}, "ops")
		if !errors.Is(err, store.ErrInvalid) {
			t.Errorf("süre %s: err = %v, ErrInvalid bekleniyordu", d, err)
		}
	}

	logs, err := db.AdminLog(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range logs {
		if e.Action == "jit.grant" || e.Action == "jit.grant.failed" {
			t.Errorf("reddedilen istek deftere yazıldı: %+v", e)
		}
	}
}

// Bilinmeyen kullanıcı ya da hedef: hedefe gidilmiyor, sebep söyleniyor.
func TestUnknownUserOrTargetIsRefusedUpFront(t *testing.T) {
	svc, db := testService(t)
	ctx := context.Background()
	if _, err := db.CreateUser(ctx, "ayse", "", "ayse"); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Grant(ctx, Request{Username: "yok", Target: "web01", Duration: time.Hour}, "ops"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bilinmeyen kullanıcı: err = %v", err)
	}
	if _, err := svc.Grant(ctx, Request{Username: "ayse", Target: "yok", Duration: time.Hour}, "ops"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bilinmeyen hedef: err = %v", err)
	}
}

// Kapalı bastion'da hizmet hiçbir şeye dokunmuyor.
func TestServiceWithoutACAIsDisabled(t *testing.T) {
	var svc *Service
	if _, err := svc.Grant(context.Background(), Request{}, "ops"); !errors.Is(err, ErrNotEnabled) {
		t.Errorf("nil hizmet: err = %v", err)
	}
	if _, err := (&Service{}).Revoke(context.Background(), "x", "ops", "web"); !errors.Is(err, ErrNotEnabled) {
		t.Errorf("CA'sız hizmet: err = %v", err)
	}
}

/*
 * ⚠️ ÜST SINIR BİR SAAT. Süresi dolmuş bir root hesabı için "yarın dene"
 * kabul edilebilir bir cevap değil; her dakika denemek de kapalı bir
 * makineye karşı anlamsız. Aralık artıyor ve bir saatte duruyor.
 */
func TestRetryIntervalGrowsAndStopsAtAnHour(t *testing.T) {
	prev := time.Duration(0)
	for attempts := 0; attempts < 6; attempts++ {
		got := backoff(attempts)
		if got < prev {
			t.Errorf("deneme %d: aralık küçüldü (%s < %s)", attempts, got, prev)
		}
		if got > time.Hour {
			t.Errorf("deneme %d: aralık bir saati aşıyor: %s", attempts, got)
		}
		prev = got
	}
	if backoff(0) < sweepEvery {
		t.Errorf("ilk yeniden deneme süpürücünün turundan kısa: %s", backoff(0))
	}
}
