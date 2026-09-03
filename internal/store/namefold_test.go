package store

import (
	"context"
	"errors"
	"testing"
)

/*
 * ⚠️ ADIN HARF YAZIMI, HANGİ YOLDAN SORULDUĞUNA GÖRE DEĞİŞMEMELİ.
 *
 * Göç 019 kullanıcı adını harf duyarsız BENZERSİZ yaptı ve gerekçesi
 * şuydu: "kod bu ikisini AYIRT ETMEYEN yollarla arıyor ... ikisi de
 * yönetici yetkisi kararlarında kullanılıyor". Dizinler de böyle
 * davranıyor (uid ve sAMAccountName caseIgnoreMatch).
 *
 * Ama okuma yollarının bir kısmı duyarlı kalmıştı: aynı hesap
 * UserByNameFold ile bulunuyor, store.User ile "yok" diyordu. Aynı
 * isteğin iki farklı katmanı aynı hesap hakkında iki farklı cevap
 * veriyorsa, sonuç ya sessiz bir kilitlenme ya da atlanmış bir kontrol.
 *
 * Bu test o yolları birlikte ölçüyor: bir tanesi duyarlı kalırsa
 * düşüyor.
 */
func TestLookupsAgreeOnLetterCase(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := s.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}

	// Dizinin yollayabileceği yazımlar.
	for _, name := range []string{"ayse", "Ayse", "AYSE", "aYsE"} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.User(ctx, name); err != nil {
				t.Errorf("store.User(%q): %v — aynı hesap UserByNameFold "+
					"ile bulunuyor, buradan \"yok\" görünüyor", name, err)
			}

			// Hesap durumu: yetki kararının girdisi. "Bulamadım" ile
			// "pasif" karışırsa kontrol atlanır ya da kişi kilitlenir.
			if _, _, err := s.AccountState(ctx, name); err != nil {
				t.Errorf("AccountState(%q): %v", name, err)
			}

			// idp_subject: kimliğin (iss,sub) ile bağlanmasının okuma
			// tarafı. Yanlış cevap, bağlı bir kimliği BAĞSIZ göstermek —
			// yani ilk girişin hesabı sahiplenmesine izin vermek.
			if _, err := s.hasIdPIdentity(ctx, name); err != nil {
				t.Errorf("hasIdPIdentity(%q): %v", name, err)
			}
		})
	}

	// Var olmayan bir hesap hâlâ bulunmamalı: düzeltme "her adı kabul et"
	// olmamalı.
	if _, err := s.User(ctx, "bora"); !errors.Is(err, ErrNotFound) {
		t.Errorf("olmayan hesap için hata = %v, ErrNotFound bekleniyordu", err)
	}
}
