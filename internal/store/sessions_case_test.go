package store

import (
	"context"
	"testing"
	"time"
)

/*
 * ⚠️ "Ayse" ARAYAN, ayse'NİN OTURUMLARINI GÖRMELİ.
 *
 * Filtre düz "=" kullanıyordu, oysa users.username harf duyarsız bir
 * sütun (dialect.go ciColumns, 009/019'daki lower() indeksleri) ve
 * deponun başka her sorgusu ciEq kullanıyor. Sonuç, bu deponun en
 * bilinen tuzağı: `postern session list --user Ayse` boş dönüyor ve
 * denetçi bunu "hiç bağlanmamış" diye okuyor — oysa yalnızca yazım
 * farklı.
 */
func TestSessionsFilterIgnoresUsernameCase(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedSession(t, s)

	if err := s.StartSession(ctx, SessionStart{
		ID: "sess-case", Username: "yigit", TargetName: "web01",
		OSUser: "yigit", SrcIP: "10.0.0.1", StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	for _, q := range []string{"yigit", "Yigit", "YIGIT"} {
		got, err := s.Sessions(ctx, q, 10)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if len(got) != 1 {
			t.Errorf("--user %q → %d oturum, 1 bekleniyordu", q, len(got))
		}
	}

	// Gerçekten var olmayan bir kullanıcı yine boş dönmeli: harf
	// duyarsızlık, süzgeci gevşetmek değil.
	if got, err := s.Sessions(ctx, "baskasi", 10); err != nil || len(got) != 0 {
		t.Errorf("olmayan kullanıcı → %d oturum (err=%v)", len(got), err)
	}
}
