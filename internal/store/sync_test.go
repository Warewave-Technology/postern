package store

import (
	"context"
	"testing"
)

/*
 * ⚠️ DİZİNE BAĞLI HERKES SENKRONİZASYONA GİRER — sso_only olmasa da.
 *
 * Eskiden kapsam yalnızca sso_only = TRUE idi ve bu, freshen'da
 * düzeltilen hatanın buradaki eşiydi: yetkisi dizinden gelen bir
 * kullanıcı (dir_subject dolu, sso_only false) hiç senkronize
 * edilmiyordu. Dizinden silinse bile, bir daha giriş yapmadığı sürece
 * rollerini süresiz koruyordu — ve döngünün var olma sebebi tam olarak
 * o kişi.
 */
func TestSyncCandidatesIncludeDirectoryBoundUsers(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// Dizine bağlı ama sso_only DEĞİL: demo'daki gerçek durum.
	if _, err := s.CreateUser(ctx, "yigit.basalma", "y@warewave.io", "yigit"); err != nil {
		t.Fatal(err)
	}
	if err := s.BindDirIdentity(ctx, "yigit.basalma",
		"f74a3e90-373a-1041-92eb-dbd441920715"); err != nil {
		t.Fatal(err)
	}

	// Servis hesabı: ne sso_only ne dizin kimliği. DIŞARIDA kalmalı —
	// dizinde bulunamaması normal ve döngü ona dokunmamalı.
	if _, err := s.CreateUser(ctx, "ci-bot", "", "ci"); err != nil {
		t.Fatal(err)
	}

	cands, err := s.SyncCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, c := range cands {
		names[c.Username] = c.DirSubject
	}

	subject, ok := names["yigit.basalma"]
	if !ok {
		t.Fatal("dizine bağlı kullanıcı senkronizasyon kapsamı dışında — " +
			"dizinden silinse bile rollerini süresiz korurdu")
	}
	if subject == "" {
		t.Fatal("aday kimliği taşımıyor — döngü onu ADLA arar ve " +
			"yeniden adlandırılan kişiyi silinmiş sanar")
	}
	if _, present := names["ci-bot"]; present {
		t.Fatal("servis hesabı kapsama girdi — dizinde olmaması normal " +
			"ve döngü onun rollerini silerdi")
	}
}
