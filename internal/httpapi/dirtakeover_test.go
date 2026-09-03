package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/ldap"
	"github.com/Warewave-Technology/postern/internal/ldap/ldaptest"
)

/*
 * ⚠️ ACİL DURUM YÖNETİCİSİ, DİZİNE O ADLA BİND EDEBİLEN HERKESE
 * AÇILIYORDU.
 *
 * resolveDirectoryUser iki adımlı: önce kararlı kimlik (objectGUID /
 * entryUUID), yoksa ada göre eşleşme. Yönetici devralma koruması ada
 * göre eşleşmenin ALTINDA duruyordu, ama arasında bir erken dönüş
 * vardı: "kimlik yoksa ada göre bulunan hesapla devam et". Yani dizin
 * kararlı bir kimlik VERMEDİĞİNDE — servis hesabının objectGUID
 * okuyamaması yaygın bir kısıtlama — koruma HİÇ koşmuyordu.
 *
 * Sonucu tam yetki devri: `postern admin bootstrap` varsayılan olarak
 * "admin" adında bir hesap açıyor ve o hesap dizine geçilince de
 * duruyor. Dizine `uid=admin` olarak bind edebilen herkes onu alıyor;
 * denetim satırı da olayı ACİL DURUM HESABININ adına yazdığı için
 * defter saldırıyı yanlış kişiye atfediyor.
 *
 * OIDC/e-posta yolu (store.claimExistingAccount) aynı korumayı
 * KOŞULSUZ uyguluyor. İki kapının aynı soruya farklı cevap vermesi
 * sıkılaştırma değil, tutarsızlıktı.
 */
func TestDirectoryDoorCannotClaimAnAdminAccountByNameAlone(t *testing.T) {
	ctx := context.Background()
	db := migratedStore(t)

	const dn = "cn=admin,ou=people,dc=test"

	// ⚠️ DİZİN KARARLI KİMLİK VERMİYOR: girdide objectGUID/entryUUID yok.
	// Ölçülen arızanın ön koşulu tam olarak bu.
	srv, err := ldaptest.New(func(base, filter string, attrs []string) ldaptest.Response {
		if strings.Contains(strings.ToLower(filter), "cn=admin") {
			return ldaptest.Response{Entries: []ldaptest.Entry{
				{DN: dn, Attrs: map[string][]string{}},
			}}
		}
		return ldaptest.Response{}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	set := func(k, v string) {
		if serr := db.SetSetting(ctx, k, v, false, "test"); serr != nil {
			t.Fatal(serr)
		}
	}
	set(auth.KeyLoginSource, "ldap")
	set(ldap.KeyURL, srv.URL())
	set(ldap.KeyBindDN, "cn=okuyucu,dc=test")
	set(ldap.KeyBindPassword, "s")
	set(ldap.KeyUserBase, "ou=people,dc=test")
	set(ldap.KeyUserFilter, "(cn=%s)")
	set(ldap.KeyGroupBase, "ou=groups,dc=test")
	set(ldap.KeyGroupFilter, "(member=%s)")
	// Yönetici grubu tanımlı ve saldırgan onun ÜYESİ DEĞİL: sahte dizin
	// hiçbir grup döndürmüyor.
	set(auth.KeyAdminGroup, "postern-admins")

	// `postern admin bootstrap`ın açtığı hesap: yerel, yönetici.
	if _, cerr := db.CreateUser(ctx, "admin", "admin@warewave.io", "admin"); cerr != nil {
		t.Fatal(cerr)
	}
	if aerr := db.SetUserAdmin(ctx, "admin", true); aerr != nil {
		t.Fatal(aerr)
	}

	s := New(auth.NewOIDCHolder(), auth.NewLogins(auth.NewOIDCHolder()), db,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Saldırgan yalnızca KENDİ kurumsal parolasını biliyor; sahte dizin
	// bind'i kabul ediyor, yani parola doğru.
	r := httptest.NewRequest(http.MethodPost, "/auth/local", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	w := httptest.NewRecorder()
	s.directoryLogin(w, r, s.logger, "admin", "saldirganin-kendi-parolasi")

	if w.Code == http.StatusOK {
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		t.Fatalf("dizin kapısı, acil durum YÖNETİCİ hesabını yalnızca ad "+
			"eşleşmesiyle verdi (HTTP %d, gövde %v) — dizine o adla bind "+
			"edebilen herkes postern'in tam yetkisini alıyor", w.Code, body)
	}

	// Ve oturum kurulmamış olmalı: reddetmek, sessizce yetkisiz bir
	// oturum açmaktan farklı bir şey.
	if len(w.Result().Cookies()) > 0 {
		t.Errorf("ret sırasında oturum çerezi verildi: %v", w.Result().Cookies())
	}
}

/*
 * ⚠️ KARŞI TARAF: yönetici OLMAYAN hesap bu yoldan geçmeye DEVAM
 * ETMELİ. Düzeltme "her şeyi reddet" olmamalı — kimliksiz dizin için
 * ada göre eşleşme belgelenmiş ve kasıtlı bir davranış.
 */
func TestDirectoryDoorStillResolvesAnOrdinaryAccountWithoutAStableIdentity(t *testing.T) {
	ctx := context.Background()
	db := migratedStore(t)

	const dn = "cn=ayse,ou=people,dc=test"
	srv, err := ldaptest.New(func(base, filter string, attrs []string) ldaptest.Response {
		if strings.Contains(strings.ToLower(filter), "cn=ayse") {
			return ldaptest.Response{Entries: []ldaptest.Entry{
				{DN: dn, Attrs: map[string][]string{}},
			}}
		}
		return ldaptest.Response{}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	set := func(k, v string) {
		if serr := db.SetSetting(ctx, k, v, false, "test"); serr != nil {
			t.Fatal(serr)
		}
	}
	set(auth.KeyLoginSource, "ldap")
	set(ldap.KeyURL, srv.URL())
	set(ldap.KeyBindDN, "cn=okuyucu,dc=test")
	set(ldap.KeyBindPassword, "s")
	set(ldap.KeyUserBase, "ou=people,dc=test")
	set(ldap.KeyUserFilter, "(cn=%s)")
	set(ldap.KeyGroupBase, "ou=groups,dc=test")
	set(ldap.KeyGroupFilter, "(member=%s)")

	if _, cerr := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); cerr != nil {
		t.Fatal(cerr)
	}

	s := New(auth.NewOIDCHolder(), auth.NewLogins(auth.NewOIDCHolder()), db,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	r := httptest.NewRequest(http.MethodPost, "/auth/local", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	w := httptest.NewRecorder()
	s.directoryLogin(w, r, s.logger, "ayse", "parola")

	if w.Code != http.StatusOK {
		t.Errorf("sıradan kullanıcı kimliksiz dizinde giremedi: HTTP %d %s — "+
			"düzeltme belgelenmiş geri düşüşü de kapatmış", w.Code, w.Body.String())
	}
}
