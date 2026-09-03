package main

import (
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * ⚠️ KESİLDİYSE SÖYLE.
 *
 * İki kardeşi de söylüyordu: `postern log` "(showing N; there are older
 * entries)" basıyor, panel de listenin sınıra dayandığını yazıyor. Bu
 * komut tam --limit satır basıp susuyordu — ve susan bir denetim aracı
 * "hepsi bu" diye okunur.
 */
func TestSessionListSaysWhenItTruncated(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if _, err := e.db.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.CreateTarget(ctx, model.Target{
		Name: "web01", Host: "127.0.0.1", Port: 22,
		HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIcLUQM0UcoZdJVh2EokribDvFZyyNyAVURM/LrCugFM",
	}); err != nil {
		t.Fatal(err)
	}

	for i := range 6 {
		if err := e.db.StartSession(ctx, store.SessionStart{
			ID:       "sess-trunc-" + string(rune('a'+i)),
			Username: "yigit", TargetName: "web01", OSUser: "yigit",
			SrcIP: "10.0.0.1", StartedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	out, err := e.run(t, newRootCmd(), "session", "list", "--limit", "3")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "may be older sessions") {
		t.Errorf("kesildiği söylenmiyor:\n%s", out)
	}

	// Sınıra dayanmayan liste sessiz kalmalı: her listeye uyarı
	// basmak, uyarıyı okunmaz hâle getirir.
	full, err := e.run(t, newRootCmd(), "session", "list", "--limit", "50")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(full, "may be older sessions") {
		t.Errorf("sınıra dayanmayan listede uyarı çıktı:\n%s", full)
	}
}
