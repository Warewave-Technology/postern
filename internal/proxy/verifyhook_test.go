package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/upstream"
)

/*
 * ⚠️ OTURUM DOĞRULAMAYI BEKLEMİYOR, VE OTURUM BİTİNCE DOĞRULAMA
 * ÖLMÜYOR.
 *
 * İkisi de ölçülmesi gereken şeyler: beklemek, tek bir komutun (ve
 * gerekirse bir hazırlama koşusunun) süresini her kabuğun açılış
 * gecikmesine eklerdi — yoklamanın yanındaki gerekçenin aynısı. Bağlamı
 * ayırmamak ise tersi: kısa bir oturum, hedefte yarıda kalmış bir
 * onarım bırakırdı.
 */
func TestTheSessionDoesNotWaitForTheCheckAndDoesNotKillIt(t *testing.T) {
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	deps := Deps{VerifyAccount: func(ctx context.Context, _ *upstream.Conn,
		_ model.User, _ model.Target,
	) {
		started <- ctx
		<-release
	}}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		maybeVerifyAccount(ctx, deps, nil, model.User{Name: "ayse"}, model.Target{Name: "db01"})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("oturum yolu doğrulamayı bekledi")
	}

	var inner context.Context
	select {
	case inner = <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("doğrulama hiç koşmadı")
	}

	// Oturum bitti: ayrılmış bağlam hâlâ canlı olmalı.
	cancel()
	if err := inner.Err(); err != nil {
		t.Errorf("oturum kapanınca doğrulamanın bağlamı da iptal oldu: %v", err)
	}
	close(release)
}

/*
 * ⚠️ KANCA KURULU DEĞİLSE HİÇ KOŞMUYOR. Hesapların kaynağı postern
 * değilse (manage.propagate_accounts kapalı) ölçülecek bir iddia da yok
 * — ve kapalı bir özellik, kullanıcının bağlantısında komut çalıştırmaz.
 */
func TestNoCheckRunsWhenTheHookIsNotWired(t *testing.T) {
	// nil kanca: panik etmeden, hiçbir şey yapmadan dönmeli.
	maybeVerifyAccount(t.Context(), Deps{}, nil,
		model.User{Name: "ayse"}, model.Target{Name: "db01"})
}
