package store

import (
	"context"
	"testing"
)

/*
 * ⚠️ KUYRUK KİMLİKLE ANAHTARLI, ADLA DEĞİL — ve RED YAPIŞKAN.
 *
 * Adla anahtarlansaydı reddedilen kişi dizinde adını değiştirip yeniden
 * başvururdu; red 'waiting'e dönseydi tekrar tekrar deneyerek yöneticiyi
 * aynı kararı vermeye zorlardı. İkisi de "tekrar tekrar kaydı engelleme"
 * ihtiyacının ta kendisi.
 */
func TestPendingIsKeyedByIdentityAndRejectionSticks(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const subject = "f74a3e90-373a-1041-92eb-dbd441920715"

	state, err := s.RecordPending(ctx, PendingUser{
		Subject: subject, Source: "dir", Username: "ayse.yilmaz",
		Email: "ayse@warewave.io", SeenGroups: []string{"hr"},
	})
	if err != nil || state != PendingWaiting {
		t.Fatalf("ilk kayıt = %q, %v", state, err)
	}

	// Aynı kimlik, BAŞKA ad: yeni satır AÇILMAMALI.
	if _, err := s.RecordPending(ctx, PendingUser{
		Subject: subject, Source: "dir", Username: "ayse.kaya",
		SeenGroups: []string{"hr", "dbteam"},
	}); err != nil {
		t.Fatal(err)
	}
	all, err := s.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("satır sayısı = %d; ad değişince ikinci başvuru açıldı", len(all))
	}
	if all[0].Username != "ayse.kaya" {
		t.Fatalf("gösterilen ad tazelenmedi: %q", all[0].Username)
	}

	// Reddet, sonra yeniden başvur: 'waiting'e DÖNMEMELİ.
	if err := s.RejectPending(ctx, all[0].ID, "ayrılan taşeron", "ops"); err != nil {
		t.Fatal(err)
	}
	state, err = s.RecordPending(ctx, PendingUser{
		Subject: subject, Source: "dir", Username: "ayse.kaya",
	})
	if err != nil {
		t.Fatal(err)
	}
	if state != PendingRejected {
		t.Fatalf("red sonrası yeniden başvuru = %q; red yapışkan değil", state)
	}

	all, _ = s.ListPending(ctx)
	if all[0].Reason != "ayrılan taşeron" || all[0].DecidedBy != "ops" {
		t.Fatalf("red gerekçesi kaybolmuş: %+v", all[0])
	}
}

/*
 * Onay hesabı açar VE kimliği AYNI işlemde bağlar.
 *
 * ⚠️ Bağlanmamış bir hesap, adla devralınabilir bir hesaptır — arada
 * kalan bir hata tam da kapatmaya çalıştığımız kapıyı açık bırakırdı.
 */
func TestApprovePendingCreatesAndBinds(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const subject = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	if _, err := s.RecordPending(ctx, PendingUser{
		Subject: subject, Source: "dir", Username: "mehmet",
		Email: "mehmet@warewave.io", SeenGroups: []string{"dbteam"},
	}); err != nil {
		t.Fatal(err)
	}
	all, _ := s.ListPending(ctx)

	if _, err := s.ApprovePending(ctx, all[0].ID, "", "ops"); err != nil {
		t.Fatalf("ApprovePending: %v", err)
	}

	u, err := s.User(ctx, "mehmet")
	if err != nil {
		t.Fatalf("hesap açılmadı: %v", err)
	}
	if !u.DirBound {
		t.Fatal("hesap açıldı ama kimliğe BAĞLANMADI — adla devralınabilir")
	}
	if got, _ := s.DirSubjectOf(ctx, "mehmet"); got != subject {
		t.Fatalf("bağlanan kimlik = %q", got)
	}

	// ⚠️ ROL VERİLMEMELİ: roller bir sonraki girişte canlı kaynaktan.
	if len(u.Roles) != 0 {
		t.Fatalf("onay rol yazdı: %v — yetki bayat bir fotoğrafa bağlanmış", u.Roles)
	}

	// Kuyruktan düşmeli: iki doğruluk kaynağı olmasın.
	if left, _ := s.ListPending(ctx); len(left) != 0 {
		t.Fatalf("onaylanan satır kuyrukta kaldı: %d", len(left))
	}
}

// Yanlışlıkla reddedilen biri bir daha hiç başvuramamalı DEĞİL:
// unutma yolu olmazsa red kalıcı bir kilit olurdu.
func TestForgetPendingUndoesRejection(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const subject = "11111111-2222-3333-4444-555555555555"

	if _, err := s.RecordPending(ctx, PendingUser{
		Subject: subject, Source: "oidc", Username: "suheda",
	}); err != nil {
		t.Fatal(err)
	}
	all, _ := s.ListPending(ctx)
	if err := s.RejectPending(ctx, all[0].ID, "yanlışlıkla", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetPending(ctx, all[0].ID); err != nil {
		t.Fatal(err)
	}
	state, err := s.RecordPending(ctx, PendingUser{
		Subject: subject, Source: "oidc", Username: "suheda",
	})
	if err != nil || state != PendingWaiting {
		t.Fatalf("unutulduktan sonra = %q, %v", state, err)
	}
}

// Rozet sayacı yalnızca BEKLEYENLERİ saymalı: reddedilenleri de sayan
// bir rozet asla sıfırlanmaz ve okunmaz hâle gelir.
func TestPendingWaitingCountIgnoresRejected(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for i, subj := range []string{"aaaa-1", "bbbb-2"} {
		if _, err := s.RecordPending(ctx, PendingUser{
			Subject: subj, Source: "dir", Username: string(rune('a'+i)) + "kisi",
		}); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := s.ListPending(ctx)
	if err := s.RejectPending(ctx, all[0].ID, "hayır", "ops"); err != nil {
		t.Fatal(err)
	}
	n, err := s.PendingWaitingCount(ctx)
	if err != nil || n != 1 {
		t.Fatalf("bekleyen sayısı = %d, %v", n, err)
	}
}
