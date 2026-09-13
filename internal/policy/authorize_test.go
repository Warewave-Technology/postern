package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
)

// --- test verisi ---
//
// Plan S2.4 tablosundaki kurulum: "ops" rolü web01'e, "readonly" rolü
// yalnızca web01'e erişebiliyor; db01'e kimsenin yetkisi yok.

func opsUser() model.User {
	return model.User{
		Name:   "yigit",
		OSUser: "yigit",
		Roles:  []model.Role{{Name: "ops", Targets: []string{"web01", "web02"}}},
	}
}

func readonlyUser() model.User {
	return model.User{
		Name:   "ayse",
		OSUser: "ayse",
		Roles:  []model.Role{{Name: "readonly", Targets: []string{"web01"}}},
	}
}

func rolelessUser() model.User {
	return model.User{Name: "mehmet", OSUser: "mehmet"}
}

func target(name string) model.Target { return model.Target{Name: name} }

// --- plan S2.4 tablosu ---

func TestAuthorizeTable(t *testing.T) {
	cases := []struct {
		name      string
		user      model.User
		target    model.Target
		requested string

		wantAllowed bool
		wantOSUser  string
	}{
		{
			name:        "ops web01, istek yok → varsayilan hesap",
			user:        opsUser(),
			target:      target("web01"),
			requested:   "",
			wantAllowed: true,
			wantOSUser:  "yigit",
		},
		{
			name:        "ops web01, root istendi → red",
			user:        opsUser(),
			target:      target("web01"),
			requested:   "root",
			wantAllowed: false,
		},
		{
			name:        "readonly web01, kendi hesabi → izin",
			user:        readonlyUser(),
			target:      target("web01"),
			requested:   "ayse",
			wantAllowed: true,
			wantOSUser:  "ayse",
		},
		{
			name:        "readonly db01 → red (hedef yetkisi yok)",
			user:        readonlyUser(),
			target:      target("db01"),
			requested:   "ayse",
			wantAllowed: false,
		},
		{
			name:        "rolsuz kullanici → red",
			user:        rolelessUser(),
			target:      target("web01"),
			requested:   "mehmet",
			wantAllowed: false,
		},
		{
			name:        "ops web01, ../etc istendi → red (gecersiz ad)",
			user:        opsUser(),
			target:      target("web01"),
			requested:   "../etc",
			wantAllowed: false,
		},
		{
			name:        "baskasinin hesabi istendi → red",
			user:        opsUser(),
			target:      target("web01"),
			requested:   "ayse",
			wantAllowed: false,
		},
		{
			name:        "rolun kapsamadigi ikinci hedef → izin",
			user:        opsUser(),
			target:      target("web02"),
			requested:   "",
			wantAllowed: true,
			wantOSUser:  "yigit",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Authorize(tc.user, tc.target, tc.requested)

			if got.Allowed != tc.wantAllowed {
				t.Fatalf("Allowed = %v, beklenen %v (Reason: %q)", got.Allowed, tc.wantAllowed, got.Reason)
			}

			if tc.wantAllowed {
				if got.OSUser != tc.wantOSUser {
					t.Errorf("OSUser = %q, beklenen %q", got.OSUser, tc.wantOSUser)
				}
				return
			}

			// Reddedilen kararların sözleşmesi.
			if got.Reason == "" {
				t.Error("Reason boş — audit'te 'neden reddedildi' cevapsız kalır")
			}
			if got.OSUser != "" {
				t.Errorf("reddedilen kararda OSUser dolu (%q) — çağıran Allowed'ı unutursa kullanılabilir bir principal ele geçer", got.OSUser)
			}
		})
	}
}

// ⚠️ Planın en kritik satırı: principal'a giden değer hiçbir zaman doğrudan
// kullanıcı girdisinden gelmemeli.
//
// Bu değer iki yere birden gidiyor: sertifikanın ValidPrincipals'ına ve SSH
// bağlantısının kullanıcı adına. Doğrulanmazsa yol kaçışı, bayrak enjeksiyonu
// ve AuthorizedPrincipalsFile eşleşmesinin bozulması mümkün.
func TestAuthorizeRejectsUnsafeUsernames(t *testing.T) {
	unsafe := []struct {
		name  string
		value string
	}{
		{"yol kacisi", "../etc"},
		{"alt dizin", "web/../root"},
		{"egik cizgi", "a/b"},
		{"bayrak gibi", "-oProxyCommand=x"},
		{"bosluk", "yigit root"},
		{"yeni satir", "yigit\nroot"},
		{"bos olmayan bosluk", "   "},
		{"nokta", "."},
		{"cift nokta", ".."},
		{"buyuk harf", "Yigit"},
		{"tirnak", "yigit'"},
		{"noktali virgul", "yigit;id"},
		{"cok uzun", strings.Repeat("a", 64)},
		{"rakamla baslayan", "1yigit"},
		{"tire ile baslayan", "-yigit"},
	}

	for _, tc := range unsafe {
		t.Run(tc.name, func(t *testing.T) {
			// Kullanıcının kendi hesabı olsa bile geçersiz ad kabul edilmemeli:
			// doğrulama, değerin nereden geldiğine değil, ne olduğuna bakar.
			u := model.User{
				Name:   "yigit",
				OSUser: tc.value,
				Roles:  []model.Role{{Name: "ops", Targets: []string{"web01"}}},
			}

			if got := Authorize(u, target("web01"), tc.value); got.Allowed {
				t.Fatalf("güvensiz OS kullanıcı adı kabul edildi: %q → OSUser=%q", tc.value, got.OSUser)
			}
		})
	}
}

// Geçerli adlar reddedilmemeli — kural fazla dar olursa gerçek kullanıcılar
// dışarıda kalır.
func TestAuthorizeAcceptsValidUsernames(t *testing.T) {
	for _, name := range []string{"yigit", "web_deploy", "svc-backup", "_internal", "a", "postgres"} {
		t.Run(name, func(t *testing.T) {
			u := model.User{
				Name:   "someone",
				OSUser: name,
				Roles:  []model.Role{{Name: "ops", Targets: []string{"web01"}}},
			}

			got := Authorize(u, target("web01"), "")
			if !got.Allowed {
				t.Fatalf("geçerli ad reddedildi: %q (Reason: %q)", name, got.Reason)
			}
			if got.OSUser != name {
				t.Errorf("OSUser = %q, beklenen %q", got.OSUser, name)
			}
		})
	}
}

// Varsayılan deny: sıfır değerli kullanıcı ve hedef hiçbir şeye erişemez.
func TestAuthorizeDefaultsToDeny(t *testing.T) {
	if got := Authorize(model.User{}, model.Target{}, ""); got.Allowed {
		t.Fatal("boş kullanıcı/hedef için izin verildi — varsayılan deny ihlali")
	}
}

// S5.2: IdP'den gelen kullanıcı adları "isim.soyisim" biçiminde.
// Nokta desteklenmeli; ASCII dışı ve büyük harf reddedilmeli.
func TestOSUserNameAcceptsDottedIdPNames(t *testing.T) {
	target := model.Target{Name: "web01"}
	roles := []model.Role{{Name: "ops", Targets: []string{"web01"}}}

	cases := []struct {
		osUser string
		allow  bool
		why    string
	}{
		{"yigit.basalma", true, "IdP'nin ürettiği tipik biçim"},
		{"ali", true, "tek parça ad"},
		{"deploy_bot", true, "servis hesabı"},
		{"a.b.c", true, "birden fazla nokta zararsız"},
		{"Yigit.Basalma", false, "büyük harf: normalize edilmeden gelmemeli"},
		{"şeyma.çelik", false, "ASCII dışı: hedefteki useradd reddeder"},
		{".gizli", false, "nokta ile başlayan ad"},
		{"-rf", false, "tire ile başlayan ad bayrak sanılabilir"},
		{"ali soyad", false, "boşluk"},
		{"ali;rm", false, "kabuk metakarakteri"},
		{"", false, "boş"},
	}

	for _, tc := range cases {
		t.Run(tc.osUser, func(t *testing.T) {
			u := model.User{Name: "x", OSUser: tc.osUser, Roles: roles}
			d := Authorize(u, target, "")
			if d.Allowed != tc.allow {
				t.Fatalf("Allowed = %v, beklenen %v (%s); reason: %s",
					d.Allowed, tc.allow, tc.why, d.Reason)
			}
		})
	}
}

/*
 * ⚠️ SÜRELİ HAK ROLÜ OLMAYANA KAPI AÇIYOR — ama yalnızca uygulanmış,
 * vadesi dolmamış ve kişinin bugünkü hesabına verilmişse; ve root/yönetim
 * hesabı/istek enjeksiyonu kontrolleri burada da duruyor. Rolü olan için
 * hak fazladan bir şey söylemiyor (Temporary=false).
 */
func TestTemporaryAccessOpensTheTargetForTheGrantOnly(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	live := model.TemporaryAccess{Target: "db01", OSUser: "mehmet", ExpiresAt: now.Add(time.Hour), Applied: true}

	cases := []struct {
		name      string
		user      model.User
		target    string
		requested string
		temp      []model.TemporaryAccess
		allowed   bool
		temporary bool
	}{
		{"rolsüz + canlı hak → izin, geçici", rolelessUser(), "db01", "", []model.TemporaryAccess{live}, true, true},
		{"rolsüz + canlı hak, kendi hesabı istendi → izin", rolelessUser(), "db01", "mehmet", []model.TemporaryAccess{live}, true, true},
		{"rolsüz + canlı hak, başka hesap istendi → red", rolelessUser(), "db01", "root", []model.TemporaryAccess{live}, false, false},
		{"rolsüz, hak başka hedefe → red", rolelessUser(), "web01", "", []model.TemporaryAccess{live}, false, false},
		{"vadesi dolmuş hak → red", rolelessUser(), "db01", "", []model.TemporaryAccess{{Target: "db01", OSUser: "mehmet", ExpiresAt: now.Add(-time.Second), Applied: true}}, false, false},
		{"tam vade anı → red (kapalı aralık değil)", rolelessUser(), "db01", "", []model.TemporaryAccess{{Target: "db01", OSUser: "mehmet", ExpiresAt: now, Applied: true}}, false, false},
		{"uygulanmamış hak → red", rolelessUser(), "db01", "", []model.TemporaryAccess{{Target: "db01", OSUser: "mehmet", ExpiresAt: now.Add(time.Hour)}}, false, false},
		{"hesap adı değişmiş → red", model.User{Name: "mehmet", OSUser: "mehmet2"}, "db01", "", []model.TemporaryAccess{live}, false, false},
		{"hak root hesabına → red", model.User{Name: "r", OSUser: "root"}, "db01", "", []model.TemporaryAccess{{Target: "db01", OSUser: "root", ExpiresAt: now.Add(time.Hour), Applied: true}}, false, false},
		{"hak yönetim hesabına → red", model.User{Name: "p", OSUser: model.ManagementAccount}, "db01", "", []model.TemporaryAccess{{Target: "db01", OSUser: model.ManagementAccount, ExpiresAt: now.Add(time.Hour), Applied: true}}, false, false},
		{"rolü olan + hak → izin, geçici DEĞİL", opsUser(), "web01", "", []model.TemporaryAccess{{Target: "web01", OSUser: "yigit", ExpiresAt: now.Add(time.Hour), Applied: true}}, true, false},
		{"hak yok → rol kararı (red)", rolelessUser(), "db01", "", nil, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := AuthorizeWithTemporary(c.user, target(c.target), c.requested, c.temp, now)
			if d.Allowed != c.allowed || d.Temporary != c.temporary {
				t.Fatalf("allowed=%v temporary=%v (reason %q); beklenen allowed=%v temporary=%v",
					d.Allowed, d.Temporary, d.Reason, c.allowed, c.temporary)
			}
			if d.Allowed && d.OSUser != c.user.OSUser {
				t.Errorf("os user = %q, beklenen %q", d.OSUser, c.user.OSUser)
			}
		})
	}
}
