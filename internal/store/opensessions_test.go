package store

import (
	"context"
	"testing"
	"time"
)

/*
 * ⚠️ AÇILIŞTA SAHİPSİZ SATIRLAR KAPANMALI.
 *
 * ÖLÇÜLEN ARIZA: postern SIGKILL alınca (çökme, güç kesintisi) açık
 * oturumların ended_at'i sonsuza dek NULL kalıyordu. Demoda ölçüldü:
 * oturum açıkken süreç öldürülüp yeniden başlatıldı, satır hâlâ açıktı.
 * Panel onu süresiz "çalışıyor" gösteriyor; kesme düğmesi bunu pasif
 * bir görüntü hatasından, var olmayan bir oturumu kapatmaya çalışan
 * aktif bir yalana çevirirdi.
 */
func TestCloseOrphanSessions(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedSession(t, s)
	startAt(t, s, "sess-acik", time.Now().Add(-2*time.Hour))
	startAt(t, s, "sess-kapali", time.Now().Add(-3*time.Hour))
	if err := s.EndSession(ctx, "sess-kapali", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	open, err := s.OpenSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].ID != "sess-acik" {
		t.Fatalf("açık oturumlar = %+v", open)
	}

	at := time.Now()
	n, err := s.CloseOrphanSessions(ctx, at)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("kapanan satır = %d, 1 bekleniyordu", n)
	}

	// ⚠️ KAPANMIŞ SATIRA DOKUNULMAMALI: ikinci kez damgalamak, gerçek
	// bitiş zamanını silip denetim kaydını bozardı.
	closed, err := s.Session(ctx, "sess-kapali")
	if err != nil {
		t.Fatal(err)
	}
	if closed.EndedAt.Unix() == at.Unix() {
		t.Error("zaten kapalı satırın bitiş zamanı üzerine yazıldı")
	}

	// İkinci çağrı hiçbir şey yapmamalı.
	if n2, err := s.CloseOrphanSessions(ctx, at); err != nil || n2 != 0 {
		t.Errorf("ikinci çağrı = %d, %v", n2, err)
	}
	if again, _ := s.OpenSessions(ctx); len(again) != 0 {
		t.Errorf("hâlâ açık satır var: %+v", again)
	}
}

/*
 * ⚠️ AÇIK OTURUM, GEÇMİŞİN İLK 200'ÜNE BAKARAK BULUNAMAZ.
 *
 * Panel "Active sessions" kartını Sessions(...200) çekip istemcide
 * süzerek kuruyordu. Sabahtan beri açık bir oturumun üstüne 200 yeni
 * oturum bindiğinde o oturum karttan düşüyor — ve görünmeyen oturum
 * kesilemiyor. Bu test tam o durumu kuruyor.
 */
func TestOpenSessionsFindsSessionsPastTheHistoryWindow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	seedSession(t, s)

	// En eski satır: hâlâ açık.
	startAt(t, s, "sess-sabahtan", time.Now().Add(-9*time.Hour))

	// Üstüne 250 kapanmış oturum.
	for i := range 250 {
		id := "sess-yeni-" + itoa(i)
		startAt(t, s, id, time.Now().Add(-time.Duration(250-i)*time.Minute))
		if err := s.EndSession(ctx, id, time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	recent, err := s.Sessions(ctx, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	var inWindow bool
	for _, r := range recent {
		if r.ID == "sess-sabahtan" {
			inWindow = true
		}
	}
	if inWindow {
		t.Skip("eski oturum hâlâ ilk 200'de — test kendi konusunu ölçemiyor")
	}

	open, err := s.OpenSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, o := range open {
		if o.ID == "sess-sabahtan" {
			found = true
		}
	}
	if !found {
		t.Error("geçmiş penceresinin dışındaki açık oturum bulunamadı — " +
			"panel onu gösteremez, dolayısıyla kapatılamaz da")
	}
}

// startAt, belirli bir başlangıç zamanıyla oturum satırı açar.
func startAt(t *testing.T, s *Store, id string, at time.Time) {
	t.Helper()
	if err := s.StartSession(context.Background(), SessionStart{
		ID: id, Username: "yigit", TargetName: "web01",
		OSUser: "yigit", SrcIP: "10.0.0.1", StartedAt: at,
	}); err != nil {
		t.Fatal(err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
