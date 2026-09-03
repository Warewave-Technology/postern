package httpapi

import (
	"testing"

	"github.com/warewave/postern/internal/ldap"

	"github.com/warewave/postern/internal/archive"
	"github.com/warewave/postern/internal/auth"

	"github.com/warewave/postern/internal/store"
)

/*
 * Onay, GÖRÜLEN LİSTEYE bağlı — ve karşılaştırma iki yönde de yanlış
 * olamaz.
 *
 * Gevşek olsaydı onay tiyatroya dönerdi: başka bir kümeyi onaylayıp
 * başka bir kümeye yetki vermek mümkün olurdu. Fazla katı olsaydı —
 * sıraya ya da harf yazımına duyarlı — dizinin "Ayse", panelin "ayse"
 * dediği her kurulumda gerçek bir onay sahte bir farkla reddedilir ve
 * ekran hiç kaydedilemez hâle gelirdi.
 */
func TestSameNameSet(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want bool
	}{
		{"aynı küme", []string{"ayse", "ops"}, []string{"ayse", "ops"}, true},
		{"sıra fark etmez", []string{"ops", "ayse"}, []string{"ayse", "ops"}, true},
		{"harf yazımı fark etmez", []string{"Ayse"}, []string{"ayse"}, true},
		{"boşluk kırpılır", []string{" ayse "}, []string{"ayse"}, true},
		{"ikisi de boş", []string{}, []string{}, true},
		{"nil ve boş aynı", nil, []string{}, true},

		// ⚠️ Asıl korunan şey bunlar.
		{"eksik onay", []string{"ayse"}, []string{"ayse", "ops"}, false},
		{"fazladan onay", []string{"ayse", "ops"}, []string{"ayse"}, false},
		{"başka kişi", []string{"mallory"}, []string{"ayse"}, false},
		{"boş onay, dolu küme", []string{}, []string{"ayse"}, false},
		{"dolu onay, boş küme", []string{"ayse"}, []string{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sameNameSet(c.a, c.b); got != c.want {
				t.Fatalf("sameNameSet(%v, %v) = %v, %v bekleniyordu", c.a, c.b, got, c.want)
			}
		})
	}
}

/*
 * Yinelenen ad, KÜMEYİ BÜYÜTMEMELİ.
 *
 * Kümeye çevirmek yerine uzunluk saysaydık, ["ayse","ayse"] onayı
 * ["ayse","ops"] kümesiyle aynı boyda görünürdü. Dizin aynı kişiyi iki
 * kez döndürebiliyor (member ve memberUid birlikte), yani bu kurgusal
 * bir girdi değil.
 */
func TestSameNameSetIgnoresDuplicates(t *testing.T) {
	if !sameNameSet([]string{"ayse", "AYSE", "ayse"}, []string{"ayse"}) {
		t.Fatal("aynı adın tekrarı ayrı kişi sayıldı")
	}
	if sameNameSet([]string{"ayse", "ayse"}, []string{"ayse", "ops"}) {
		t.Fatal("iki kişilik bir kümeye, tek kişilik bir onay yetti")
	}
}

/*
 * ⚠️ SON YÖNETİCİ KORUMASI.
 *
 * İki yönde de yanlış olabilir ve ikisi de pahalı:
 *
 *   - Fazla gevşek: grubu temizlemek bütün yöneticileri düşürür,
 *     postern yönetici olmadan kalır ve tek çıkış ürünün bütün amacını
 *     bozmaktır (host'a girip `postern admin issue`).
 *   - Fazla katı: elinde CLI yöneticisi olan bir kurulum grubunu
 *     değiştiremez hâle gelir — hiçbir tehlike yokken.
 */
func TestWouldLeaveNoAdmin(t *testing.T) {
	cli := []store.AdminHolder{{Username: "ops", Via: "cli"}}
	grp := []store.AdminHolder{{Username: "ayse", Via: "group"}}
	both := []store.AdminHolder{{Username: "ops", Via: "cli"}, {Username: "ayse", Via: "group"}}
	// 017 öncesinden kalma, kaynağı yazılmamış kayıt: grup mantığı ona
	// dokunmadığı için o da hayatta kalanlardan sayılmalı.
	legacy := []store.AdminHolder{{Username: "eski", Via: ""}}

	cases := []struct {
		name    string
		holders []store.AdminHolder
		want    []string
		leaves  bool
	}{
		{"CLI yöneticisi varken grup boşaltılabilir", cli, nil, false},
		{"CLI ve grup varken grup boşaltılabilir", both, nil, false},
		{"kaynaksız eski kayıt da sayılır", legacy, nil, false},

		{"yalnızca grup yöneticisi varken boşaltmak son yöneticiyi siler", grp, nil, true},
		{"yalnızca grup yöneticisi varken hesapsız gruba geçmek de siler", grp, []string{}, true},

		// Yeni grupta hesabı OLAN biri varsa yönetici kalıyor demektir.
		{"yeni grupta hesaplı üye varsa sorun yok", grp, []string{"mehmet"}, false},

		// Hiç yönetici yokken (bootstrap öncesi) bu mantık bir şey
		// kaybettirmiyor: kaybedilecek yönetici yok.
		{"hiç yönetici yokken hesaplı üye yeterli", nil, []string{"mehmet"}, false},
		{"hiç yönetici yokken hesapsız grup boş bırakır", nil, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := wouldLeaveNoAdmin(c.holders, c.want); got != c.leaves {
				t.Fatalf("wouldLeaveNoAdmin(%v, %v) = %v, %v bekleniyordu",
					c.holders, c.want, got, c.leaves)
			}
		})
	}
}

/*
 * ⚠️ PANELİN YAZDIĞI HER AYAR YA İZİNLİ YA DA AÇIKÇA REDDEDİLMİŞ OLMALI.
 *
 * ÖLÇÜLEN ARIZA: sihirbazın "hesaplar kendiliğinden açılsın mı"
 * anahtarı (auth.auto_create) knownSettingKeys'e eklenmemişti. Ekran
 * çiziliyordu, düğme çalışıyordu, ve tıklayınca "unknown setting key"
 * dönüyordu — yani sihirbaz kendi ayarını yazamıyordu.
 *
 * ⚠️ KAPSAM, AŞAĞIDAKİ `all` HARİTASIYLA SINIRLI — VE BU ELLE
 * TUTULUYOR. Test, burada SAYILAN her anahtarın sınıflandırıldığını
 * doğruluyor; yeni bir ayar sabiti eklenip bu haritaya EKLENMEZSE onu
 * yakalayamaz. Yani "hata sınıfını tamamen kapatıyor" demek fazla
 * iddialı olurdu: hatırlatıcı bir bekçi, mekanik bir kanıt değil.
 *
 * Mekanik hâli her settings paketinin sabitlerini dışa vermesini ve
 * her birinin kendi testinde eksiksizliğini doğrulamasını gerektirir;
 * bu ayrımın taşıdığı ağırlığa değecek bir iş değil. Yeni bir ayar
 * ekleyen, onu `all`'a da eklemeli.
 */
func TestEverySettingKeyIsClassified(t *testing.T) {
	/*
	 * Genel uçtan YAZILAMAYAN ayarlar ve sebepleri. Hepsinin kendi ucu
	 * var, çünkü hepsi postern'in KİME GÜVENDİĞİNİ belirliyor ve yanlış
	 * bir değer kimsenin giremediği bir panel bırakıyor.
	 */
	deniedOnPurpose := map[string]string{
		auth.KeyLoginSource:      "own endpoint: proves the destination can let someone in",
		auth.KeyAdminGroup:       "own endpoint: shows who it makes an administrator first",
		auth.KeyOIDCIssuer:       "own endpoint: drops the client secret when the target changes",
		auth.KeyOIDCClientID:     "own endpoint: same transaction as the issuer",
		auth.KeyOIDCClientSecret: "own endpoint: write-only, never read back",
		auth.KeyOIDCManaged:      "written by the server, not by an operator",
		auth.KeySetupCompleted:   "written by the server when setup finishes",
		/*
		 * ⚠️ ARŞİV KİMLİĞİ GENEL AYARLAR YOLUNDAN GEÇEMEZ.
		 *
		 * Oradaki sınıflandırma fail-open: haritada olmayan anahtar
		 * sessizce "sır değil" sayılıp DÜZ METİN saklanıyor
		 * (federation.go:210). Yükleme sırrının mühürlenmesi bir
		 * harita girdisinin varlığına bağlı olamaz — kendi ucu var ve
		 * orada encrypted=true zorunlu.
		 */
		archive.KeyAccessKeyID:     "own endpoint: lives with the sealed half",
		archive.KeySecretAccessKey: "own endpoint: sealed, never read back",
	}

	all := map[string]string{
		"auth.KeyLoginSource":        auth.KeyLoginSource,
		"auth.KeyAdminGroup":         auth.KeyAdminGroup,
		"auth.KeyAutoCreate":         auth.KeyAutoCreate,
		"auth.KeyConfirmTTL":         auth.KeyConfirmTTL,
		"auth.KeyDeleteTTL":          auth.KeyDeleteTTL,
		"auth.KeySetupCompleted":     auth.KeySetupCompleted,
		"auth.KeyOIDCIssuer":         auth.KeyOIDCIssuer,
		"auth.KeyOIDCClientID":       auth.KeyOIDCClientID,
		"auth.KeyOIDCClientSecret":   auth.KeyOIDCClientSecret,
		"auth.KeyOIDCManaged":        auth.KeyOIDCManaged,
		"ldap.KeyURL":                ldap.KeyURL,
		"ldap.KeyBindDN":             ldap.KeyBindDN,
		"ldap.KeyBindPassword":       ldap.KeyBindPassword,
		"ldap.KeyUserBase":           ldap.KeyUserBase,
		"ldap.KeyUserFilter":         ldap.KeyUserFilter,
		"ldap.KeyGroupAttribute":     ldap.KeyGroupAttribute,
		"ldap.KeyGroupBase":          ldap.KeyGroupBase,
		"ldap.KeyGroupFilter":        ldap.KeyGroupFilter,
		"ldap.KeyGroupNameFrom":      ldap.KeyGroupNameFrom,
		"ldap.KeyGroupScope":         ldap.KeyGroupScope,
		"archive.KeyAccessKeyID":     archive.KeyAccessKeyID,
		"archive.KeySecretAccessKey": archive.KeySecretAccessKey,
	}

	for name, key := range all {
		_, allowed := knownSettingKeys[key]
		_, denied := deniedOnPurpose[key]
		switch {
		case allowed && denied:
			t.Errorf("%s (%q) hem izinli hem reddedilmiş — karar belirsiz", name, key)
		case !allowed && !denied:
			t.Errorf("%s (%q) sınıflandırılmamış: ya knownSettingKeys'e ekle, "+
				"ya da gerekçesiyle deniedOnPurpose'a. Sınıflandırılmayan bir "+
				"anahtar, panelde çalışan bir düğmenin \"unknown setting key\" "+
				"döndürmesi demek", name, key)
		}
	}
}
