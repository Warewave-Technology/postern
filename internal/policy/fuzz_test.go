package policy

import (
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/model"
)

// refValidOSUserName is a hand-written model of the OS-user name rule.
//
// Bilerek regexp KULLANMIYOR: authorize.go'nun regex'ini burada tekrar
// çağırmak kodu kendisiyle karşılaştırmak olurdu ve regex'teki bir
// gevşemeyi (ör. sınıfa yeni bir karakter eklenmesi) test aynen onaylardı.
// Kural elle yazılınca ikisinin ayrışması hata olarak görünür.
func refValidOSUserName(s string) bool {
	// Sınır 32 BAYT: regex'teki {0,31} + ilk karakter. Bayt cinsinden
	// olması önemli, çünkü sertifika principal'ı da bayt taşır.
	if len(s) == 0 || len(s) > 32 {
		return false
	}

	if c := s[0]; !(c >= 'a' && c <= 'z') && c != '_' {
		return false
	}

	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '_', c == '.', c == '-':
		default:
			return false
		}
	}

	return true
}

// FuzzAuthorizeContract pins Authorize's full decision function, and the
// cross-package invariant that its output is safe to mint into a certificate.
//
// İkinci kısım asıl sebep. Zinciri okuyunca ortaya çıkıyor:
// policy.Decision.OSUser → proxy/lifecycle.go'da upstream.Identity.OSUser →
// upstream/dial.go'da ca.CertRequest.Principals ve ssh.ClientConfig.User.
// ca.Sign yalnızca "principal listesi boş mu" diye bakıyor, İÇERİĞİNE
// bakmıyor. Yani bir sertifika principal'ına (ve oradan hedefin auth.log'una)
// satır sonu girmesini engelleyen TEK şey, üç paket öteki bu regex.
// Bu bağ kodda hiçbir yerde yazılı değil; burada çalıştırılabilir hale
// geliyor ki regex gevşetildiğinde sessizce kırılmasın.
func FuzzAuthorizeContract(f *testing.F) {
	seeds := []struct {
		osUser, requested, targetName, roleTarget string
	}{
		{"yigit", "", "web01", "web01"},
		{"yigit", "yigit", "web01", "web01"},
		{"yigit", "ayse", "web01", "web01"},
		{"root", "", "web01", "web01"},
		{"root", "root", "web01", "web01"},
		{"yigit", "", "db01", "web01"},
		{"", "", "", ""},
		{"yigit.basalma", "yigit.basalma", "web01", "web01"},
		{"_internal", "", "web01", "web01"},

		// Satır sonu SONDA: Go regexp'te (?-m) modunda '$' metnin sonuna
		// bağlanır, PCRE'deki gibi son newline'dan ÖNCEsine değil. Bu
		// varsayım yanlış olsaydı principal'a newline girerdi — tohum
		// olarak duruyor ki varsayım her koşuda sınansın.
		{"yigit\n", "", "web01", "web01"},
		{"yigit\nroot", "", "web01", "web01"},
		{"yigit\x00", "", "web01", "web01"},
		{"Yigit", "", "web01", "web01"},
		{"şeyma.çelik", "", "web01", "web01"},
		{"-rf", "", "web01", "web01"},
		{".gizli", "", "web01", "web01"},
		{strings.Repeat("a", 32), "", "w", "w"},
		{strings.Repeat("a", 33), "", "w", "w"},
		{"a", "", "", ""},
		{"a", "a", "\n", "\n"},
	}
	for _, s := range seeds {
		f.Add(s.osUser, s.requested, s.targetName, s.roleTarget)
	}

	f.Fuzz(func(t *testing.T, osUser, requested, targetName, roleTarget string) {
		u := model.User{
			OSUser: osUser,
			Roles:  []model.Role{{Targets: []string{roleTarget}}},
		}
		target := model.Target{Name: targetName}

		d := Authorize(u, target, requested)

		// --- karar fonksiyonunun tamamı, elle modellenmiş ---
		//
		// Tek rol, tek hedef: eşleşme roleTarget == targetName demek.
		wantAllowed := roleTarget == targetName &&
			refValidOSUserName(osUser) &&
			osUser != "root" &&
			(requested == "" || requested == osUser)

		if d.Allowed != wantAllowed {
			t.Fatalf("Allowed = %v, model %v (osUser=%q requested=%q target=%q roleTarget=%q reason=%q)",
				d.Allowed, wantAllowed, osUser, requested, targetName, roleTarget, d.Reason)
		}

		if !d.Allowed {
			// Reddin denetim sözleşmesi: sebep yazılmazsa "neden
			// giremedim" sorusunun log'da cevabı kalmaz.
			if d.Reason == "" {
				t.Fatalf("reddedildi ama Reason boş (osUser=%q requested=%q)", osUser, requested)
			}
			// Reddedilen kararda principal dolu kalırsa, Allowed'ı
			// kontrol etmeyi unutan bir çağıran kullanılabilir bir
			// hesap adı ele geçirir.
			if d.OSUser != "" {
				t.Fatalf("reddedilen kararda OSUser dolu: %q", d.OSUser)
			}
			return
		}

		// İzin verilen kararın principal'ı kullanıcının hesabıdır; policy
		// onu türetmez, seçer.
		if d.OSUser != u.OSUser {
			t.Fatalf("OSUser = %q, beklenen %q", d.OSUser, u.OSUser)
		}
		if d.OSUser == "root" {
			t.Fatalf("root principal'ına izin verildi")
		}
		if roleTarget != targetName {
			t.Fatalf("rolün kapsamadığı hedefe izin: rol %q, hedef %q", roleTarget, targetName)
		}
		if requested != "" && requested != d.OSUser {
			t.Fatalf("başkasının hesabı istendi ama izin verildi: requested=%q, OSUser=%q", requested, d.OSUser)
		}

		// --- paketler arası bağ: sertifikaya gömülmeye uygunluk ---
		//
		// upstream/dial.go bu değeri doğrudan Principals'a koyuyor ve
		// ca.Sign içeriğe bakmıyor. Buradan geçen her şey hedefin
		// auth.log'una ve AuthorizedPrincipalsFile eşleşmesine gider.
		if len(d.OSUser) > 32 {
			t.Fatalf("principal 32 baytı aşıyor (%d): %q", len(d.OSUser), d.OSUser)
		}
		for i := 0; i < len(d.OSUser); i++ {
			c := d.OSUser[i]
			if c < 0x21 || c > 0x7e {
				t.Fatalf("principal'da ASCII dışı/kontrol baytı: %q (offset %d, byte %#x)", d.OSUser, i, c)
			}
		}
		if strings.ContainsAny(d.OSUser, "\n\r") {
			t.Fatalf("principal'da satır sonu: %q", d.OSUser)
		}
	})
}

// FuzzAuthorizeRolelessNeverAllowed pins the default-deny half separately.
//
// Rolsüz kullanıcı ayrı bir hedefte çünkü yukarıdaki hedef her zaman TEK
// rollü bir kullanıcı kuruyor: rolü hiç olmayan durum orada hiç denenmiyor
// ve "varsayılan deny" kolu fuzz'ın kör noktasında kalıyordu.
func FuzzAuthorizeRolelessNeverAllowed(f *testing.F) {
	f.Add("yigit", "", "web01")
	f.Add("yigit", "yigit", "web01")
	f.Add("", "", "")
	f.Add("root", "root", "web01")

	f.Fuzz(func(t *testing.T, osUser, requested, targetName string) {
		u := model.User{OSUser: osUser}

		d := Authorize(u, model.Target{Name: targetName}, requested)

		if d.Allowed {
			t.Fatalf("rolsüz kullanıcıya izin verildi: osUser=%q requested=%q target=%q → OSUser=%q",
				osUser, requested, targetName, d.OSUser)
		}
		if d.Reason == "" {
			t.Fatalf("rolsüz ret için Reason boş (osUser=%q)", osUser)
		}
		if d.OSUser != "" {
			t.Fatalf("rolsüz rette OSUser dolu: %q", d.OSUser)
		}
	})
}
