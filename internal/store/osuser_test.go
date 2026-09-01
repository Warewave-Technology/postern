package store

import (
	"context"
	"errors"
	"testing"
)

/*
 * ⚠️ HEDEFLERDEKİ HESAP ADI, YAZILMADAN ÖNCE ELENMELİ.
 *
 * ÖLÇÜLEN ARIZA: kural yalnızca politika kapısındaydı. Hesap açılıyor,
 * roller veriliyor, panelde hedef kartları görünüyor — ve her bağlantı
 * "access denied" ile düşüyordu. Sebebi söyleyen tek cümle bastion'ın
 * log'undaydı.
 *
 * Entra ID satırı bu testin var olma sebebi: preferred_username orada
 * UPN ve JIT sağlama os_user'ı ondan birebir alıyor.
 */
func TestRefuseBadOSUser(t *testing.T) {
	kabul := []string{"yigit", "deploy", "_svc", "ops-01", "a.b-c_d", "u"}
	ret := []string{
		"",               // boş
		"Yigit",          // büyük harf: çoğu sistemde AYRI hesap
		"yigit@corp.com", // Entra ID / Azure AD UPN
		"şüheda.celik",   // Türkçe harf
		"1yigit",         // rakamla başlıyor
		"root ",          // sondaki boşluk
		"ops/admin",      // yol ayracı
		"yigit_basalma_ops_team_0123456789012345", // 32'den uzun
	}

	for _, name := range kabul {
		if err := refuseBadOSUser("test", name); err != nil {
			t.Errorf("%q reddedildi, kabul bekleniyordu: %v", name, err)
		}
	}
	for _, name := range ret {
		err := refuseBadOSUser("test", name)
		if err == nil {
			t.Errorf("%q kabul edildi, ret bekleniyordu", name)
			continue
		}
		// ⚠️ TÜRÜ DE DOĞRU OLMALI: httpapi bunu 400'e eşliyor. Sarmalama
		// bozulursa operatör yine "internal error" görür.
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%q için hata ErrInvalid değil: %v", name, err)
		}
		// Mesaj, DÜZELTİLECEK DEĞERİ içermeli; "invalid value" tek
		// başına operatöre hangi alanı düzelteceğini söylemez.
		if name != "" && !contains(err.Error(), name) {
			t.Errorf("%q için mesaj değeri içermiyor: %v", name, err)
		}
	}
}

func contains(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) &&
		(func() bool {
			for i := 0; i+len(needle) <= len(hay); i++ {
				if hay[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		})()
}

/*
 * ⚠️ KURAL YAZMA YOLUNA BAĞLI OLMALI — kuralın VAR OLMASI yetmiyor.
 *
 * Arızanın dersi tam olarak buydu: doğrulayıcı vardı, çağıran yoktu.
 * Yukarıdaki test refuseBadOSUser'ı doğrudan çağırıyor ve bağlantı
 * koparsa yine geçer. Bu test tabloya yazan yolu deniyor.
 */
func TestCreateUserRefusesBadOSUser(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// Entra ID'nin preferred_username'i: JIT sağlamanın os_user'a
	// birebir koyduğu değer.
	if _, err := s.CreateUser(ctx, "yigit", "", "yigit@corp.com"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("CreateUser bozuk os_user'ı kabul etti (err=%v)", err)
	}

	// Hesap GERÇEKTEN açılmamış olmalı: yarım bir satır kalsaydı
	// yönetici "zaten var" duvarına toslardı.
	if _, err := s.User(ctx, "yigit"); !errors.Is(err, ErrNotFound) {
		t.Errorf("reddedilen hesaptan geriye kayıt kalmış: %v", err)
	}

	// Geçerli olan aynı yoldan geçmeli.
	if _, err := s.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatalf("geçerli os_user reddedildi: %v", err)
	}

	// Değiştirme yolu da elemeli.
	if err := s.SetUserOSUser(ctx, "yigit", "Yigit"); !errors.Is(err, ErrInvalid) {
		t.Errorf("SetUserOSUser bozuk değeri kabul etti: %v", err)
	}
}
