package provision

import (
	"strings"
	"testing"
)

// revokeSteps, planı üretir ve hata beklemez.
func revokeSteps(t *testing.T, r Revoke) []Step {
	t.Helper()
	s, err := RevokePlan(able(), r)
	if err != nil {
		t.Fatalf("plan üretilemedi: %v", err)
	}

	return s
}

// commands, adımların komutlarını tek metne toplar.
func commands(steps []Step) string {
	var b strings.Builder
	for _, s := range steps {
		b.WriteString(s.Command)
		b.WriteString("\n")
	}

	return b.String()
}

/*
 * ⚠️ SÜREÇLER HESAPTAN ÖNCE ÖLDÜRÜLMELİ.
 *
 * Hesap silindiğinde ad–UID eşlemesi kayboluyor; o andan sonra
 * "bu kullanıcının süreçleri" diye bir şey kalmıyor ve koşanlar
 * sahipsiz bir numarayla devam ediyor. Sıra ters olsaydı, süresi dolan
 * bir hakkın arkasında hâlâ çalışan bir süreç kalırdı — yani hak
 * bitmemiş olurdu.
 */
func TestProcessesDieBeforeTheAccount(t *testing.T) {
	steps := revokeSteps(t, Revoke{
		User: "jit-ayse", Mode: ModeDelete, UID: 1001, InJITGroup: true,
		Home: "/home/jit-ayse",
	})

	var kill, del int = -1, -1
	for i, s := range steps {
		switch s.Kind {
		case StepKill:
			kill = i
		case StepUserDel:
			del = i
		}
	}
	if kill < 0 || del < 0 {
		t.Fatalf("adımlar eksik: %v", kinds(steps))
	}
	if kill > del {
		t.Fatalf("HESAP SÜREÇLERDEN ÖNCE SİLİNİYOR: %v", kinds(steps))
	}
}

// ⚠️ Sudo kuralı en başta alınıyor: süreçler ölene kadar geçen sürede
// yeni bir yükseltme yapılamasın.
func TestSudoIsTakenAwayFirst(t *testing.T) {
	steps := revokeSteps(t, Revoke{
		User: "jit-ayse", Mode: ModeDelete, UID: 1001, InJITGroup: true,
		Home: "/home/jit-ayse", SudoFiles: []string{"/etc/sudoers.d/postern-jit-7f3a"},
	})

	if steps[0].Kind != StepSudoRemove {
		t.Fatalf("ilk adım %q, sudo kaldırma bekleniyordu (%v)", steps[0].Kind, kinds(steps))
	}
}

/*
 * ⚠️ BU DOSYADAKİ EN ÖNEMLİ TEST: POSTERN'İN AÇMADIĞI HESAP SİLİNMİYOR.
 *
 * Ada bakarak silmek, makinede postern'den önce var olan bir hesabı yok
 * edebilirdi ve geri dönüşü yok. Grup üyeliği "bunu ben açtım" demenin
 * makinedeki tek güvenilir hâli — göç 022'deki "kararlı kimlik"
 * dersinin aynısı.
 */
func TestAccountPosternDidNotCreateIsNeverDeleted(t *testing.T) {
	_, err := RevokePlan(able(), Revoke{
		User: "postgres", Mode: ModeDelete, UID: 1001, InJITGroup: false, Home: "/var/lib/postgresql",
	})
	if err == nil {
		t.Fatal("POSTERN'İN AÇMADIĞI HESAP İÇİN SİLME PLANI ÜRETİLDİ")
	}
	if !strings.Contains(err.Error(), JITGroup) {
		t.Errorf("sebep söylenmedi: %v", err)
	}
}

/*
 * ⚠️ KİLİTLEME HİÇBİR ŞEY SİLMİYOR. Kalıcı hesap dosya sahipliğinin
 * çıpası; sildiğimizde "bunu kim bıraktı" sorusunun altı ay sonraki
 * cevabı da gider.
 */
func TestLockDeletesNothing(t *testing.T) {
	steps := revokeSteps(t, Revoke{
		User: "ayse", Mode: ModeLock, UID: 1001, Home: "/home/ayse",
		Scratch: []string{"/srv/build/ayse"},
	})

	c := commands(steps)
	for _, bad := range []string{"rm -rf", "userdel"} {
		if strings.Contains(c, bad) {
			t.Errorf("KİLİTLEME SİLDİ (%q):\n%s", bad, c)
		}
	}
	if !strings.Contains(c, "-L") {
		t.Errorf("hesap kilitlenmiyor:\n%s", c)
	}
	// Kilitlenen hesabın dosyaları YÖNETİCİYE listeleniyor.
	if !strings.Contains(c, "find") {
		t.Errorf("kalan dosyalar listelenmiyor:\n%s", c)
	}
}

/*
 * ⚠️ BU TEST İLE ÜRETİM MAKİNESİ ARASINDA BAŞKA BİR ŞEY YOK.
 *
 * `rm -rf` kök, /home ya da boş bir değerle koşarsa geri dönüş yok.
 * Kapsam bildirilmiş yollarla sınırlı ve her biri ayrı ayrı
 * doğrulanıyor.
 */
func TestScratchPathsThatWouldDestroyTheMachineAreRefused(t *testing.T) {
	for _, p := range []string{
		"/", "/home", "/etc", "/var", "/usr", "/tmp", "/root", "",
		"relatif/yol", "/srv/../etc", "/srv/build; rm -rf /", "/srv/*",
		"/var", "/opt",
		/*
		 * ⚠️ YASAK LİSTESİNDE OLMAYAN TEPE DİZİNLER — VE BU SATIRLAR
		 * BİR MUTASYONUN HAYATTA KALMASIYLA EKLENDİ. Derinlik
		 * kontrolünü kaldırdığımda testler yeşil kalıyordu, çünkü
		 * listedeki yollar zaten başka bir kuralla yakalanıyordu.
		 * Oysa gerçek tehlike listede OLMAYAN bir bağlama noktası:
		 * `rm -rf /data` bir üretim makinesini bitirir ve /data
		 * hiçbir yasak listesinde yoktur.
		 */
		"/data", "/mnt", "/scratch", "/veri",
	} {
		_, err := RevokePlan(able(), Revoke{
			User: "jit-ayse", Mode: ModeDelete, UID: 1001, InJITGroup: true,
			Home: "/home/jit-ayse", Scratch: []string{p},
		})
		if err == nil {
			t.Errorf("TEHLİKELİ YOL KABUL EDİLDİ: %q", p)
		}
	}
}

// Geçerli bir çalışma alanı kabul ediliyor: kural yasak değil, sınır.
func TestADeclaredScratchPathIsAccepted(t *testing.T) {
	steps := revokeSteps(t, Revoke{
		User: "jit-ayse", Mode: ModeDelete, UID: 1001, InJITGroup: true,
		Home: "/home/jit-ayse", Scratch: []string{"/srv/build/jit-ayse"},
	})

	if !strings.Contains(commands(steps), "rm -rf /srv/build/jit-ayse") {
		t.Errorf("bildirilen yol silinmiyor:\n%s", commands(steps))
	}
}

/*
 * ⚠️ POSTERN YALNIZCA KENDİ YAZDIĞI SUDO DOSYASINI SİLİYOR. Başka bir
 * şeyin koyduğu kuralı kaldırmak, o makinenin yetkilerini kimsenin
 * beklemediği biçimde değiştirirdi.
 */
func TestOnlyPosternsOwnSudoFilesAreRemoved(t *testing.T) {
	for _, f := range []string{
		"/etc/sudoers.d/00-admins", "/etc/sudoers", "/etc/sudoers.d/../sudoers",
		"/etc/sudoers.d/postern-jit; rm -rf /",
	} {
		_, err := RevokePlan(able(), Revoke{
			User: "jit-ayse", Mode: ModeDelete, UID: 1001, InJITGroup: true,
			Home: "/home/jit-ayse", SudoFiles: []string{f},
		})
		if err == nil {
			t.Errorf("POSTERN'E AİT OLMAYAN DOSYA SİLİNECEKTİ: %q", f)
		}
	}
}

/*
 * ⚠️ KAPSAM DIŞI DOSYALAR SİLİNMİYOR, RAPORLANIYOR — ve arama kökten
 * değil. `find /` bir üretim makinesinde dakikalar sürer ve ağ dosya
 * sistemlerine dalar; daha kötüsü, silmeye bağlanırsa bir kez yanlış
 * kullanıcıda makineyi bitirir.
 */
func TestLeftoverFilesAreReportedNotDeleted(t *testing.T) {
	steps := revokeSteps(t, Revoke{
		User: "jit-ayse", Mode: ModeDelete, UID: 1001, InJITGroup: true, Home: "/home/jit-ayse",
	})

	var report string
	for _, s := range steps {
		if s.Kind == StepReportOwned {
			report = s.Command
		}
	}
	if report == "" {
		t.Fatal("kalan dosyalar hiç raporlanmıyor")
	}
	if strings.Contains(report, "-delete") || strings.Contains(report, "rm ") {
		t.Errorf("RAPOR ADIMI SİLİYOR: %q", report)
	}
	if strings.Contains(report, "find / ") {
		t.Errorf("kökten arama yapılıyor: %q", report)
	}
	if !strings.Contains(report, "-xdev") {
		t.Errorf("arama dosya sistemi sınırında durmuyor: %q", report)
	}
}

// Ad doğrulaması burada da: komut satırına giriyor ve root koşuyor.
func TestRevokeRefusesNamesThatWouldBecomeCommands(t *testing.T) {
	for _, name := range []string{"ayse; rm -rf /", "a b", "", "-rf"} {
		if _, err := RevokePlan(able(), Revoke{
			User: name, Mode: ModeLock, UID: 1001,
		}); err == nil {
			t.Errorf("%q kabul edildi", name)
		}
	}
}

/*
 * ⚠️ RAPOR, ADIN ÇÖZÜLMESİNE BAĞLI OLAMAZ — VE BU TEST BİR CANLI
 * KOŞUNUN BULDUĞU KUSURDAN DOĞDU.
 *
 * Rapor adımı `userdel`den SONRA koşuyor. `find -user suheda` o noktada
 * adı çözemiyor, hata veriyor ve çıktı boş dönüyor: kalan dosyaları
 * gösteren şey, tam da işe yarayacağı anda hiçbir şey göstermiyordu.
 * Gerçek makinede bilerek bırakılmış bir dosya vardı ve rapor onu
 * bulamadı.
 */
func TestLeftoverReportDoesNotDependOnTheNameStillResolving(t *testing.T) {
	steps := revokeSteps(t, Revoke{
		User: "jit-ayse", Mode: ModeDelete, UID: 1042, InJITGroup: true,
		Home: "/home/jit-ayse",
	})

	var report string
	for _, s := range steps {
		if s.Kind == StepReportOwned {
			report = s.Command
		}
	}
	if strings.Contains(report, "-user ") {
		t.Errorf("RAPOR ADI KULLANIYOR: %q — hesap silindikten sonra boş döner", report)
	}
	if !strings.Contains(report, "-uid 1042") {
		t.Errorf("rapor numarayla aramıyor: %q", report)
	}
}

/*
 * ⚠️ SİSTEM HESABI SÖKÜLMÜYOR. Bir yapılandırma hatası root'a ya da
 * dağıtımın kendi hesabına işaret ederse, plan makineyi bitirirdi.
 */
func TestSystemAccountsAreNeverRevoked(t *testing.T) {
	for _, uid := range []int{0, -1} {
		if _, err := RevokePlan(able(), Revoke{
			User: "root", Mode: ModeDelete, UID: uid, InJITGroup: true,
		}); err == nil {
			t.Errorf("uid %d için sökme planı üretildi", uid)
		}
	}
}
