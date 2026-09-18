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
		User: "jit-ayse", Mode: ModeDelete, UID: 1001, CreatedByPostern: true,
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
		User: "jit-ayse", Mode: ModeDelete, UID: 1001, CreatedByPostern: true,
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
		User: "postgres", Mode: ModeDelete, UID: 1001, CreatedByPostern: false, Home: "/var/lib/postgresql",
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
		/*
		 * ⚠️ NOKTALI VİRGÜL DIŞINDAKİ KABUK SÖZDİZİMİ — VE BU SATIRLAR BİR
		 * İNCELEMENİN BULDUĞU ENJEKSİYONLA EKLENDİ. Kontrol bir yasak
		 * listesiydi ve yalnızca ";|&$*?" ile boşlukları tanıyordu; ters
		 * tırnak, yönlendirme ve süslü parantez geçiyordu.
		 * "/srv/build/`sh</tmp/p`" hatasız bir `sudo -n rm -rf` satırı
		 * üretti: kabuk ters tırnağı rm'den ÖNCE açıyor. Yukarıdaki
		 * ";" örneği bu sınıfı hiç sınamıyordu — yasak listesinin kendi
		 * kör noktasını miras almıştı.
		 */
		"/srv/build/`sh</tmp/p`", "/srv/build/$(id)", "/srv/build/{a,b}",
		"/srv/build/a>b", "/srv/build/a<b", "/srv/build/'a'", "/srv/build/\"a\"",
		"/srv/build/a\\b", "/srv/build/(a)", "/srv/build/~x", "/srv/build/a!b",
		"/srv/build/ünite",
	} {
		_, err := RevokePlan(able(), Revoke{
			User: "jit-ayse", Mode: ModeDelete, UID: 1001, CreatedByPostern: true,
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
		User: "jit-ayse", Mode: ModeDelete, UID: 1001, CreatedByPostern: true,
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
		// Aynı sınıf, aynı kör nokta: ters tırnak ve yönlendirme.
		"/etc/sudoers.d/postern-x`{sudo,-n,id}>/tmp/pwn`",
		"/etc/sudoers.d/postern-$(id)", "/etc/sudoers.d/postern-a>b",
	} {
		_, err := RevokePlan(able(), Revoke{
			User: "jit-ayse", Mode: ModeDelete, UID: 1001, CreatedByPostern: true,
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
		User: "jit-ayse", Mode: ModeDelete, UID: 1001, CreatedByPostern: true, Home: "/home/jit-ayse",
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
		User: "jit-ayse", Mode: ModeDelete, UID: 1042, CreatedByPostern: true,
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
			User: "root", Mode: ModeDelete, UID: uid, CreatedByPostern: true,
		}); err == nil {
			t.Errorf("uid %d için sökme planı üretildi", uid)
		}
	}
}

/*
 * Hesabı gitmiş bir hakkın sudo dosyası da gitmeli — ve yalnızca
 * postern'in yazdığı dosya. Yol kontrolü sökme planınınkiyle aynı kapı:
 * gevşetilse buradan başka bir dosya silinebilirdi.
 */
func TestSudoFilesOfAGoneAccountAreRemovedThroughTheSameGate(t *testing.T) {
	steps, err := RemoveSudoFilesPlan([]string{UserSudoPath("jit-ayse")})
	if err != nil {
		t.Fatal(err)
	}
	if got := commands(steps); !strings.Contains(got, "rm -f "+UserSudoPath("jit-ayse")) {
		t.Errorf("dosya kaldırılmıyor:\n%s", got)
	}
	for _, f := range []string{"/etc/sudoers", "/etc/sudoers.d/00-admins", "/etc/sudoers.d/postern-x`id`"} {
		if _, err := RemoveSudoFilesPlan([]string{f}); err == nil {
			t.Errorf("%q kabul edildi", f)
		}
	}
	if steps, err := RemoveSudoFilesPlan(nil); err != nil || len(steps) != 0 {
		t.Errorf("boş liste: steps=%v err=%v", steps, err)
	}
}

/*
 * ⚠️ PRINCIPALS DOSYASI SÜREÇLERDEN ÖNCE GİDİYOR — kalan süreçler ölene
 * kadar yeni bir sertifika girişi olmasın — ve yalnızca hesabın KENDİ
 * dosyası gidiyor: başka bir adla biten yol reddediliyor.
 */
func TestRevokeRemovesThePrincipalsFileBeforeKillingProcesses(t *testing.T) {
	steps := revokeSteps(t, Revoke{
		User: "jit-ayse", Mode: ModeDelete, UID: 1001, CreatedByPostern: true,
		Home: "/home/jit-ayse", PrincipalsFile: "/etc/ssh/auth_principals/jit-ayse",
	})
	got := commandsOf(steps)
	if !strings.Contains(got, "rm -f /etc/ssh/auth_principals/jit-ayse") {
		t.Fatalf("principals dosyası kaldırılmıyor:\n%s", got)
	}
	if strings.Index(got, "rm -f /etc/ssh/auth_principals") > strings.Index(got, "pkill") {
		t.Errorf("dosya süreçlerden sonra kaldırılıyor:\n%s", got)
	}

	if _, err := RevokePlan(able(), Revoke{
		User: "jit-ayse", Mode: ModeDelete, UID: 1001, CreatedByPostern: true,
		Home: "/home/jit-ayse", PrincipalsFile: "/etc/ssh/auth_principals/veli",
	}); err == nil {
		t.Error("başka hesabın principals dosyasını silen plan kabul edildi")
	}
	for _, bad := range []string{"/etc/ssh/auth_principals", "etc/jit-ayse", "/etc/ssh/x;rm/jit-ayse"} {
		if _, err := PrincipalRemoveStep(bad, "jit-ayse"); err == nil {
			t.Errorf("%q kabul edildi", bad)
		}
	}
}

/*
 * ⚠️ GRUP HESAPTAN SONRA SİLİNİYOR ve yalnızca çağıranın ölçüp verdiği
 * gruplar; postern-jit kanıt grubu hiçbir koşulda silinmiyor. Silme
 * kipinde; kilitleme kipi grupları hiç ellemiyor.
 */
func TestRevokeDeletesTheGroupsPosternCreatedAfterTheAccount(t *testing.T) {
	steps := revokeSteps(t, Revoke{
		User: "jit-ayse", Mode: ModeDelete, UID: 1001, CreatedByPostern: true,
		Home: "/home/jit-ayse", DeleteGroups: []string{"gecici"},
	})
	got := commandsOf(steps)
	if !strings.Contains(got, "groupdel gecici") {
		t.Fatalf("grup silinmiyor:\n%s", got)
	}
	if strings.Index(got, "groupdel gecici") < strings.Index(got, "userdel") {
		t.Errorf("grup hesaptan önce siliniyor:\n%s", got)
	}
	if _, err := RevokePlan(able(), Revoke{
		User: "jit-ayse", Mode: ModeDelete, UID: 1001, CreatedByPostern: true,
		Home: "/home/jit-ayse", DeleteGroups: []string{JITGroup},
	}); err == nil {
		t.Error("postern-jit grubunu silen plan kabul edildi")
	}
	if _, err := GroupDeleteSteps(able(), []string{"a;b"}); err == nil {
		t.Error("kabuk karakterli grup adı kabul edildi")
	}
}

/*
 * ⚠️ KİLİT HESABIN SÜRESİNİ DOLDURUYOR, YALNIZCA PAROLAYI KİLİTLEMİYOR.
 *
 * ÖLÇÜLDÜ (gerçek bir container'da): `usermod -L -s /usr/sbin/nologin`
 * sonrası shadow satırı `acctayse:!*:20714::::::` — parola kilitli ama
 * expire alanı BOŞ. Sertifikayla giriş parolaya bakmıyor; nologin ise
 * kimlik doğrulamayı başarılı sayıp oturumu hemen kapatıyor, yani port
 * yönlendirme ve SFTP açık kalabiliyor. Süresi dolmuş hesabı sshd kimlik
 * doğrulama aşamasında reddediyor — kapatan tek şey bu.
 */
func TestLockingExpiresTheAccountAndNotJustItsPassword(t *testing.T) {
	steps := revokeSteps(t, Revoke{
		User: "ayse", Mode: ModeLock, UID: 1001, Home: "/home/ayse",
	})

	var lock string
	for _, s := range steps {
		if s.Kind == StepLock {
			lock = s.Command
		}
	}
	if lock == "" {
		t.Fatal("kilit adımı yok")
	}
	for _, want := range []string{"-L", "-e 1", "nologin"} {
		if !strings.Contains(lock, want) {
			t.Errorf("kilit %q taşımıyor: %q", want, lock)
		}
	}
	// Ve silme DEĞİL: kilit geri alınabilir olmak zorunda.
	for _, s := range steps {
		if s.Kind == StepUserDel {
			t.Errorf("kilit kipinde silme adımı: %q", s.Command)
		}
	}
}
