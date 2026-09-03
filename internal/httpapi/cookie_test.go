package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/Warewave-Technology/postern/internal/proxy"
)

// Oturum çerezinin Secure bayrağı DIŞ ADRESİN şemasından türemeli,
// r.TLS'ten değil.
//
// Neden ayrı test: postern TLS'i sonlandıran bir ters vekilin arkasında
// çalıştığında r.TLS nil olur ama bağlantı HTTPS'tir. r.TLS'e bakan bir
// sürüm o kurulumda oturum çerezini Secure'suz yazar — yani çerez düz
// metin bir isteğe de iliştirilebilir hâle gelir. Sessizce yanlış olan,
// gürültülü kırılandan tehlikeli.
func TestSecureCookieFollowsExternalURLScheme(t *testing.T) {
	cases := []struct {
		externalURL string
		wantSecure  bool
	}{
		{"https://postern.sirket.local", true},
		{"https://postern.sirket.local:8443/", true},
		// Büyük/küçük harf şemayı değiştirmez.
		{"HTTPS://postern.sirket.local", true},

		// Düz HTTP kurulumu (localhost denemesi): Secure yazılamaz,
		// yoksa tarayıcı çerezi hiç göndermez ve giriş sessizce çalışmaz.
		{"http://localhost:8088", false},
		// Hiç ayarlanmamış: en güvenlisi değil ama en DÜRÜSTÜ davranış,
		// çünkü http kurulumunu kırmamak gerekiyor. r.TLS hâlâ yedek.
		{"", false},
	}

	for _, tc := range cases {
		t.Run(tc.externalURL, func(t *testing.T) {
			var s Server
			s.SetExternalURL(tc.externalURL)

			if s.secureCookies != tc.wantSecure {
				t.Errorf("secureCookies = %v, beklenen %v", s.secureCookies, tc.wantSecure)
			}

			// Silme çerezi de aynı bayrağı taşımalı: tarayıcılar
			// Secure'lu bir çerezi Secure'suz bir Set-Cookie ile
			// güvenilir biçimde silmez.
			w := httptest.NewRecorder()
			s.clearSessionCookie(w)

			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("%d çerez yazıldı, 1 bekleniyordu", len(cookies))
			}
			c := cookies[0]
			if c.Secure != tc.wantSecure {
				t.Errorf("silme çerezi Secure = %v, beklenen %v", c.Secure, tc.wantSecure)
			}
			if !c.HttpOnly {
				t.Error("silme çerezi HttpOnly değil")
			}
			if c.MaxAge >= 0 {
				t.Errorf("MaxAge = %d, negatif olmalı (silme)", c.MaxAge)
			}
		})
	}
}

// EnableTerminal, dış adresi SetExternalURL üzerinden geçirmeli —
// yoksa terminal açıkken çerez bayrağı ayarlanmadan kalır.
func TestEnableTerminalSetsSecureCookies(t *testing.T) {
	var s Server
	s.EnableTerminal(proxy.Deps{}, "https://postern.sirket.local")

	if !s.secureCookies {
		t.Error("EnableTerminal dış adresi SetExternalURL'e geçirmemiş")
	}
	if s.externalURL != "https://postern.sirket.local" {
		t.Errorf("externalURL = %q", s.externalURL)
	}
}
