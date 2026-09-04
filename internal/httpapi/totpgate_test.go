package httpapi

import (
	"strings"
	"testing"
)

/*
 * ⚠️ BU TESTİN KAPATTIĞI ŞEY, ZORUNLU KAYIT KISITININ TAMAMI.
 *
 * changePasswordAllowed için yazılmış olanın kardeşi ve aynı arızayı
 * kapatıyor: bir ÖNEK eşleşmesi ("/api/me ile başlayan her şey serbest")
 * POST /api/me/keys'i de açardı — ve o uç hesabın İLK anahtarını hiçbir
 * doğrulama istemeden ekliyor. Yani "ikinci faktörünü kurana kadar hiçbir
 * şey yapamazsın" kısıtı, tam olarak kalıcı SSH erişimi kurmanın önündeki
 * tek engeli kaldırırdı.
 */
func TestTOTPEnrolmentAllowlistIsMinimal(t *testing.T) {
	mustBeClosed := []string{
		// Kalıcılık kurmanın yolu. Listeye girerse kısıt anlamsız.
		"POST /api/me/keys",
		"GET /api/me/keys",
		"POST /api/me/keys/remove",

		/*
		 * ⚠️ KAYITTAN KAÇIŞ YOLU OLMAMALI. Zorunluluktan çıkışın yolu
		 * kaydı TAMAMLAMAK; kapatmak değil. Bugün disable zaten
		 * doğrulanmış bir kayıt istiyor ve buradaki kişinin öylesi yok,
		 * ama listeye koymamak o bağımlılığı kalıcı hâle getiriyor:
		 * yarın disable'ın ön koşulu gevşerse liste yine kaçış açmıyor.
		 */
		"POST /api/me/totp/disable",

		"GET /api/terminal/{target}",
		"GET /api/admin/users",
		"GET /api/admin/settings",
		"GET /api/targets",
	}
	for _, p := range mustBeClosed {
		if totpEnrolmentAllowed[p] {
			t.Errorf("%q kayıt kısıtına AÇIK — kısıt anlamını yitirir", p)
		}
	}

	// Kısıttan ÇIKIŞIN yolu açık kalmalı, yoksa kişi kalıcı olarak sıkışır
	// ve panelde yapabileceği hiçbir şey kalmaz.
	mustBeOpen := []string{
		"GET /api/me",
		"GET /api/me/totp",
		"POST /api/me/totp/begin",
		"POST /api/me/totp/confirm",
		// Sızdığını düşündüğü parolayı, yeni bir sır kurmadan ÖNCE
		// değiştirebilmeli. Uç mevcut parolayı istediği için kısıtı
		// zayıflatmıyor.
		"POST /api/me/password",
	}
	for _, p := range mustBeOpen {
		if !totpEnrolmentAllowed[p] {
			t.Errorf("%q kapalı — kişi ikinci faktörünü kuramaz ve sıkışır", p)
		}
	}

	// Liste KISA kalmalı. Büyüdüğü an, büyüten kişi bu testi görüp neden
	// büyüttüğünü yazmak zorunda.
	if len(totpEnrolmentAllowed) != 5 {
		t.Fatalf("izin listesi %d uç içeriyor, 5 bekleniyordu — "+
			"her yeni giriş kısıtın anlamını biraz daha azaltır",
			len(totpEnrolmentAllowed))
	}
}

/*
 * İki kapı aynı anda açık kalmamalı: parola kısıtındayken TOTP uçları da
 * açık olsaydı, kişi kendi seçmediği bir parolayla girmişken ikinci faktör
 * kurar ve o faktör ONU değil, ona o sırrı VEREN kişiyi korurdu.
 */
func TestPasswordGateDoesNotOpenTOTPEndpoints(t *testing.T) {
	for p := range totpEnrolmentAllowed {
		if !strings.Contains(p, "/totp") {
			// GET /api/me ve POST /api/me/password ikisinde de açık,
			// ikisi de gerekçeli (bkz. weblogin.go).
			continue
		}
		if changePasswordAllowed[p] {
			t.Errorf("%q parola kısıtında da açık — parola değişmeden "+
				"ikinci faktör kurulabilirdi", p)
		}
	}
}
