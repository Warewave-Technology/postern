package provision

import (
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/sudoers"
	"github.com/Warewave-Technology/postern/v2/internal/upstream"
)

// able, yönetilebilir bir hedefin yetenekleri.
func able() upstream.ManageCapabilities {
	return upstream.ManageCapabilities{
		Sudo: true, AddUser: "/usr/sbin/useradd", AddGroup: "/usr/sbin/groupadd",
		ModUser: "/usr/sbin/usermod", DelUser: "/usr/sbin/userdel",
		DelGroup: "/usr/sbin/groupdel", Visudo: "/usr/sbin/visudo",
		Family: "debian", Shell: "/bin/bash",
	}
}

// empty, hiçbir şeyin olmadığı bir hedef.
func empty() Observed {
	return Observed{
		Groups: map[string]bool{}, Users: map[string][]string{},
		PosternSudoers: map[string]string{},
	}
}

// kinds, adımların türlerini sırayla döner.
func kinds(steps []Step) []StepKind {
	out := make([]StepKind, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Kind)
	}

	return out
}

/*
 * ⚠️ SIRA, ADIMLARIN EN ÖNEMLİ ÖZELLİĞİ. Kullanıcıyı olmayan bir gruba
 * eklemek hedefte hata veriyor; sudo kuralını olmayan bir gruba yazmak
 * ise SESSİZCE etkisiz kalıyor — yani yanlış sıra, ikincisinde arıza
 * bile üretmiyor.
 */
func TestStepsComeInAnOrderTheTargetAccepts(t *testing.T) {
	steps, err := Plan(able(), Desired{
		Groups: []Group{{Name: "dba", Sudo: sudoers.Rule{
			Commands: []sudoers.Command{{Path: "/usr/bin/pg_ctl"}},
		}}},
		Users: []User{{Name: "ayse", Groups: []string{"dba"}}},
	}, empty())
	if err != nil {
		t.Fatal(err)
	}

	got := kinds(steps)
	// user.unlock hesabın hemen ardından: sshd parolasız hesabı kilitli
	// sayıyor (plan.go'daki ölçüm) ve üyelik/sudo bundan sonra geliyor.
	want := []StepKind{
		StepGroupAdd, StepUserAdd, StepUserUnlock, StepUserGroup,
		StepSudoStage, StepSudoCheck, StepSudoInstall,
	}
	if len(got) != len(want) {
		t.Fatalf("adımlar = %v, %v bekleniyordu", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("adım %d = %q, %q bekleniyordu (tamamı: %v)", i, got[i], want[i], got)
		}
	}
}

/*
 * ⚠️ İKİNCİ KOŞU HİÇBİR ŞEY YAPMAMALI. Yayılım idempotent değilse
 * "değişti mi" sorusu cevaplanamaz ve panel her koşuda bir şey
 * yapılmış gibi görünür — gerçekten bir şey değiştiği gün de öyle.
 */
func TestSecondRunDoesNothing(t *testing.T) {
	d := Desired{
		Groups: []Group{{Name: "dba", Sudo: sudoers.Rule{
			Commands: []sudoers.Command{{Path: "/usr/bin/pg_ctl"}},
		}}},
		Users: []User{{Name: "ayse", Groups: []string{"dba"}}},
	}

	content, err := sudoers.Render("%dba", d.Groups[0].Sudo, "group dba — written by postern")
	if err != nil {
		t.Fatal(err)
	}

	steps, err := Plan(able(), d, Observed{
		Groups: map[string]bool{"dba": true},
		Users:  map[string][]string{"ayse": {"dba"}},
		PosternSudoers: map[string]string{
			"/etc/sudoers.d/postern-dba": content,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 0 {
		t.Fatalf("İKİNCİ KOŞU İŞ ÜRETTİ: %v", kinds(steps))
	}
}

// Kural değişince yalnızca sudo adımları çıkıyor: hesap yeniden açılmaz.
func TestChangedRuleRewritesOnlyTheSudoFile(t *testing.T) {
	steps, err := Plan(able(), Desired{
		Groups: []Group{{Name: "dba", Sudo: sudoers.Rule{
			Commands: []sudoers.Command{{Path: "/usr/bin/pg_ctl"}},
		}}},
		Users: []User{{Name: "ayse", Groups: []string{"dba"}}},
	}, Observed{
		Groups:         map[string]bool{"dba": true},
		Users:          map[string][]string{"ayse": {"dba"}},
		PosternSudoers: map[string]string{"/etc/sudoers.d/postern-dba": "eski kural\n"},
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []StepKind{StepSudoStage, StepSudoCheck, StepSudoInstall}
	if got := kinds(steps); len(got) != 3 || got[0] != want[0] {
		t.Fatalf("adımlar = %v, yalnızca sudo adımları bekleniyordu", got)
	}
}

/*
 * ⚠️ BU DOSYADAKİ EN ÖNEMLİ TEST: YÖNETİLEMEYEN HEDEFE HİÇ
 * DOKUNULMUYOR.
 *
 * Yarısı uygulanmış bir makine, hiç dokunulmamış olandan kötü: panel
 * yeşil görünür, kimse bakmaz, ve eksik olan şey ancak birinin
 * giremediği gün ortaya çıkar.
 */
func TestUnmanageableTargetGetsNoStepsAtAll(t *testing.T) {
	caps := able()
	caps.Visudo = ""
	caps.Missing = []string{"visudo"}

	steps, err := Plan(caps, Desired{Groups: []Group{{Name: "dba"}}}, empty())
	if err == nil {
		t.Fatal("YÖNETİLEMEYEN HEDEFE PLAN ÜRETİLDİ")
	}
	if len(steps) != 0 {
		t.Errorf("adım üretildi: %v", kinds(steps))
	}
	if !strings.Contains(err.Error(), "visudo") {
		t.Errorf("sebep söylenmedi: %v", err)
	}
}

/*
 * ⚠️ SUDO DOSYASI ÜÇ ADIMDA YAZILIYOR VE ORTADAKİ ADIM HEDEFİN KENDİ
 * visudo'SU. Doğrudan yerine yazmak, geçersiz bir dosyanın o makinede
 * herkesin sudo'sunu götürmesi demek — postern'in kendi hesabı dahil,
 * yani makine kendini onaramaz.
 */
func TestSudoFileIsCheckedBeforeItIsInstalled(t *testing.T) {
	steps, _ := Plan(able(), Desired{
		Groups: []Group{{Name: "dba", Sudo: sudoers.Rule{
			Commands: []sudoers.Command{{Path: "/usr/bin/pg_ctl"}},
		}}},
	}, empty())

	var stage, check, install int
	for i, s := range steps {
		switch s.Kind {
		case StepSudoStage:
			stage = i
			if !strings.Contains(s.Command, ".staged") {
				t.Errorf("geçici dosyaya yazılmıyor: %q", s.Command)
			}
			// ⚠️ Kural metni komut satırında DEĞİL: stdin'den gidiyor.
			if strings.Contains(s.Command, "NOPASSWD") {
				t.Errorf("KURAL METNİ KOMUT SATIRINDA: %q", s.Command)
			}
			if !strings.Contains(s.Content, "NOPASSWD") {
				t.Errorf("kural stdin'e konmamış: %q", s.Content)
			}
		case StepSudoCheck:
			check = i
			if !strings.Contains(s.Command, "visudo -cf") {
				t.Errorf("doğrulama adımı visudo çağırmıyor: %q", s.Command)
			}
		case StepSudoInstall:
			install = i
		}
	}
	if !(stage < check && check < install) {
		t.Fatalf("SIRA YANLIŞ: stage=%d check=%d install=%d", stage, check, install)
	}
}

/*
 * ⚠️ AD, KOMUT SATIRINA GİRİYOR. Boşluk ya da noktalı virgül taşıyan
 * bir grup adı, hedefte root yetkisiyle çalışan İKİNCİ bir komut
 * olurdu.
 */
func TestNamesThatWouldBecomeCommandsAreRefused(t *testing.T) {
	for _, name := range []string{"dba; rm -rf /", "db a", "db$(id)", "", "DBA", "-rf"} {
		if _, err := Plan(able(), Desired{Groups: []Group{{Name: name}}}, empty()); err == nil {
			t.Errorf("%q grup adı kabul edildi", name)
		}
		if _, err := Plan(able(), Desired{Users: []User{{Name: name}}}, empty()); err == nil {
			t.Errorf("%q hesap adı kabul edildi", name)
		}
		/*
		 * ⚠️ ÜYELİK LİSTESİ AYRI BİR YOL — VE BU TEST ONU DENEMEDİĞİ İÇİN
		 * ENJEKSİYON YAŞADI. Grup d.Groups'ta tanımlı olmasa da kullanıcının
		 * Groups listesi usermod satırına giriyor. "dba;id>/tmp/pwn"
		 * verildiğinde plan hatasız
		 * `sudo -n /usr/sbin/usermod -a -G dba;id>/tmp/pwn ayse` üretti.
		 */
		steps, err := Plan(able(), Desired{Users: []User{{Name: "ayse", Groups: []string{name}}}}, empty())
		if err == nil {
			t.Errorf("%q üyelik listesinde kabul edildi: %v", name, commandsOf(steps))
		}
	}
}

// commandsOf, adımların komutlarını tek dizede verir: hata mesajında
// neyin hedefe gideceği görünsün.
func commandsOf(steps []Step) string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Command)
	}

	return strings.Join(out, " | ")
}

/*
 * ⚠️ YÖNETİM HESABI HİÇBİR PLANA GİRMİYOR — ne hesap, ne grup, ne üyelik.
 *
 * Rol "postern" hesabını ve aynı adlı grubu açıyor; o hesap hedefte
 * parolasız root tutuyor. Onu değiştiren bir plan, postern'in kendi
 * yönetim yetkisini bir insanla paylaşmasına (gruba üye eklemek) ya da
 * kendini makineden kilitlemesine yol açardı.
 */
func TestTheManagementAccountIsNeverPlanned(t *testing.T) {
	for _, name := range []string{"postern", "postern-manage"} {
		if _, err := Plan(able(), Desired{Groups: []Group{{Name: name}}}, empty()); err == nil {
			t.Errorf("%q grubu plana girdi", name)
		}
		if _, err := Plan(able(), Desired{Users: []User{{Name: name}}}, empty()); err == nil {
			t.Errorf("%q hesabı plana girdi", name)
		}
		if _, err := Plan(able(), Desired{Users: []User{{Name: "ayse", Groups: []string{name}}}}, empty()); err == nil {
			t.Errorf("bir kişi %q grubuna eklenebiliyor", name)
		}
		for _, mode := range []RevokeMode{ModeLock, ModeDelete} {
			if _, err := RevokePlan(able(), Revoke{
				User: name, Mode: mode, UID: 998, CreatedByPostern: true,
			}); err == nil {
				t.Errorf("%q için %v sökme planı üretildi — postern kendini kilitlerdi", name, mode)
			}
		}
	}
}

/*
 * ⚠️ KAÇIŞ VEREN KURAL PLANA GİREMİYOR. Doğrulayıcı panelde de koşuyor,
 * ama plana giden tek yol panel değil; yazma anına en yakın kontrol,
 * unutulamayan kontroldür.
 */
func TestRuleThatGrantsRootNeverReachesTheTarget(t *testing.T) {
	_, err := Plan(able(), Desired{
		Groups: []Group{{Name: "dba", Sudo: sudoers.Rule{
			Commands: []sudoers.Command{{Path: "/usr/bin/find", Args: []string{"/var/log", "*"}}},
		}}},
	}, empty())
	if err == nil {
		t.Fatal("ROOT VEREN KURAL PLANA GİRDİ")
	}
}

// Sudo kuralı olmayan grup geçerli: yalnızca üyelik için de grup açılır.
func TestGroupWithoutSudoWritesNoFile(t *testing.T) {
	steps, err := Plan(able(), Desired{Groups: []Group{{Name: "okuyucu"}}}, empty())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if strings.HasPrefix(string(s.Kind), "sudo.") {
			t.Errorf("sudosuz group dosya yazıldı: %v", kinds(steps))
		}
	}
}

/*
 * ⚠️ AYNI İSTEK, FARKLI SIRADA YAZILINCA AYNI PLANI ÜRETMELİ.
 *
 * İlk yazdığım test aynı dilimi tekrar veriyordu ve hiçbir şey
 * ölçmüyordu: sıralamayı kaldırdığımda yeşil kalıyordu. Asıl iddia
 * bu — planı kuran yol tek değil (panel, API, CLI) ve her biri
 * grupları başka sırada dizebilir. Sıra plana yansırsa "bu hedefte
 * bir şey değişti mi" sorusu, isteğin yazılış sırasına kalır.
 */
func TestSameRequestInAnyOrderGivesTheSamePlan(t *testing.T) {
	a := Desired{
		Groups: []Group{{Name: "alpha"}, {Name: "mu"}, {Name: "zeta"}},
		Users:  []User{{Name: "ayse"}, {Name: "veli"}},
	}
	b := Desired{
		Groups: []Group{{Name: "zeta"}, {Name: "alpha"}, {Name: "mu"}},
		Users:  []User{{Name: "veli"}, {Name: "ayse"}},
	}

	first, err := Plan(able(), a, empty())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Plan(able(), b, empty())
	if err != nil {
		t.Fatal(err)
	}

	if len(first) != len(second) {
		t.Fatalf("adım sayıları farklı: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Command != second[i].Command {
			t.Fatalf("PLAN İSTEĞİN SIRASINA BAĞLI: adım %d %q vs %q",
				i, first[i].Command, second[i].Command)
		}
	}
}

/*
 * ⚠️ HER ADIM GERÇEKTEN ROOT OLARAK KOŞMALI — VE BU TESTİN VAR OLMA
 * SEBEBİ, BİR KUSURUN TESTLERDEN KAÇMASI.
 *
 * Plan bir süre `cat > /etc/sudoers.d/…` üretti. O komut hedefte
 * `postern` hesabıyla koştuğunda çalışmaz: yönlendirme sudo'dan ÖNCE,
 * çağıran kabukta yapılıyor ve dosya YETKİSİZ kullanıcı olarak
 * açılmaya çalışılıyor. Canlı denemede farkında olmadan `sudo -n tee`
 * yazıp doğruladığım için de görünmedi — yani planın kendisini değil,
 * elle düzeltilmiş hâlini ölçmüşüm.
 *
 * İki şey sabitleniyor: komut sudo ile başlıyor, ve ayrıcalıklı bir
 * yola kabuk yönlendirmesiyle yazılmıyor.
 */
func TestEveryStepActuallyRunsAsRoot(t *testing.T) {
	steps, err := Plan(able(), Desired{
		Groups: []Group{{Name: "dba", Sudo: sudoers.Rule{
			Commands: []sudoers.Command{{Path: "/usr/bin/nginx", Args: []string{"-t"}}},
		}}},
		Users: []User{{Name: "ayse", Groups: []string{"dba"}}},
	}, empty())
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range steps {
		if !strings.HasPrefix(s.Command, "sudo -n ") {
			t.Errorf("%s adımı sudo'suz koşuyor: %q", s.Kind, s.Command)
		}

		/*
		 * ⚠️ Ayrıcalıklı yola yönlendirme, sudo'dan önce çalışır.
		 * ">/dev/null" zararsız (çıktıyı atıyor); "/etc" altına
		 * yönlendirme ise sessizce yetkisiz kalır.
		 */
		for _, bad := range []string{"> /etc", ">/etc", "> /var", ">/var"} {
			if strings.Contains(s.Command, bad) {
				t.Errorf("%s adımı ayrıcalıklı yola kabuk yönlendirmesiyle yazıyor: %q",
					s.Kind, s.Command)
			}
		}
	}
}

/*
 * ⚠️ GEÇİCİ HESAP postern-jit GRUBUNA GİRİYOR VE BU ÜYELİĞİ KURAN TEK
 * YER PLAN. Üyelik silmenin ön koşulu; kurulmasaydı süresi dolan hiçbir
 * hesap silinemezdi. Grup kimse istemese de plana giriyor, hesap
 * eklenmeden ÖNCE yaratılıyor, ve useradd'e yedek süre yazılıyor.
 */
func TestATemporaryAccountJoinsThePosternGroupWithABackstop(t *testing.T) {
	expires := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	steps, err := Plan(able(), Desired{
		Users:  []User{{Name: "jit-ayse", Groups: []string{"dba"}, JIT: true, ExpiresAt: expires}},
		Groups: []Group{{Name: "dba"}},
	}, empty())
	if err != nil {
		t.Fatal(err)
	}
	got := commandsOf(steps)

	if !strings.Contains(got, "groupadd "+JITGroup) {
		t.Errorf("postern-jit grubu yaratılmıyor:\n%s", got)
	}
	if strings.Index(got, "groupadd "+JITGroup) > strings.Index(got, "useradd") {
		t.Errorf("grup hesaptan sonra yaratılıyor:\n%s", got)
	}
	if !strings.Contains(got, "useradd -m -s /bin/bash -e 2026-09-14 jit-ayse") {
		t.Errorf("yedek süre yazılmıyor ya da yanlış:\n%s", got)
	}
	if !strings.Contains(got, "usermod -a -G dba,"+JITGroup+" jit-ayse") {
		t.Errorf("üyelik postern-jit'i içermiyor:\n%s", got)
	}
}

/*
 * ⚠️ POSTERN'İN AÇMADIĞI HESAP JIT YAPILMIYOR. Makinede aynı adla var olan
 * bir hesabı postern-jit'e almak, süresi dolunca onu SİLMEK demek — ve o
 * birinin kalıcı hesabı olabilir. Var olup grupta olan hesap ise önceki
 * bir hakkın hesabı: uzatılıyor, yeniden yaratılmıyor.
 */
func TestATemporaryAccountNeverTakesOverAnExistingOne(t *testing.T) {
	d := Desired{Users: []User{{Name: "ayse", JIT: true}}}

	foreign := empty()
	foreign.Users["ayse"] = []string{"ayse", "docker"}
	if _, err := Plan(able(), d, foreign); err == nil {
		t.Fatal("var olan hesap geçici hesaba ÇEVRİLDİ — süresi dolunca silinecekti")
	}

	ours := empty()
	ours.Users["ayse"] = []string{"ayse", JITGroup}
	ours.Groups[JITGroup] = true
	steps, err := Plan(able(), d, ours)
	if err != nil {
		t.Fatalf("postern'in kendi açtığı hesap reddedildi: %v", err)
	}
	if got := commandsOf(steps); strings.Contains(got, "useradd") {
		t.Errorf("var olan hesap yeniden yaratılıyor:\n%s", got)
	}
}

/*
 * ⚠️ YEDEK SÜRE ASIL SÜREDEN ÖNCE VURAMAZ. useradd -e hesabı verilen
 * günün BAŞINDA kapatıyor; aynı gün yazılsaydı öğleden sonra biten bir
 * hak sabah kesilirdi.
 */
func TestExpiryBackstopFallsOnTheDayAfter(t *testing.T) {
	for _, tc := range []struct{ at, want string }{
		{"2026-09-13T15:00:00Z", "2026-09-14"},
		{"2026-09-13T00:00:00Z", "2026-09-14"},
		{"2026-09-13T23:59:59Z", "2026-09-14"},
		{"2026-09-13T22:30:00-03:00", "2026-09-15"}, // UTC'de ertesi gün 01:30
	} {
		at, _ := time.Parse(time.RFC3339, tc.at)
		if got := expiryBackstop(at); got != tc.want {
			t.Errorf("%s → %s, %s bekleniyordu", tc.at, got, tc.want)
		}
	}
}

/*
 * ⚠️ KULLANICI KURALI AYRI DOSYAYA GİDİYOR VE SÖKME PLANI O DOSYAYI
 * KABUL EDİYOR. Grup dosyasıyla aynı ada düşseydi "dba" grubu ile "dba"
 * hesabı birbirinin kuralını ezerdi; sökme planının önek kontrolünden
 * geçmeseydi hak biterken kural makinede kalırdı.
 */
func TestAPerUserSudoRuleIsWrittenAndRemovable(t *testing.T) {
	rule := sudoers.Rule{Commands: []sudoers.Command{{Path: "/usr/bin/nginx", Args: []string{"-t"}}}}
	steps, err := Plan(able(), Desired{Users: []User{{Name: "jit-ayse", JIT: true, Sudo: &rule}}}, empty())
	if err != nil {
		t.Fatal(err)
	}
	got := commandsOf(steps)
	if !strings.Contains(got, "install -o root -g root -m 0440 "+UserSudoPath("jit-ayse")+".staged "+UserSudoPath("jit-ayse")) {
		t.Errorf("kullanıcı kuralı yazılmıyor:\n%s", got)
	}
	if strings.Contains(got, SudoPath("jit-ayse")) {
		t.Errorf("kullanıcı kuralı grup dosyasının yoluna gidiyor:\n%s", got)
	}
	for _, s := range steps {
		if s.Kind == StepSudoStage && !strings.Contains(s.Content, "jit-ayse ALL=(root) NOPASSWD: /usr/bin/nginx -t") {
			t.Errorf("içerik kullanıcının kuralı değil: %q", s.Content)
		}
	}

	if _, err := RevokePlan(able(), Revoke{
		User: "jit-ayse", Mode: ModeDelete, UID: 1001, CreatedByPostern: true,
		SudoFiles: []string{UserSudoPath("jit-ayse")},
	}); err != nil {
		t.Errorf("sökme planı kullanıcı dosyasını reddetti: %v", err)
	}

	// Aynı kural ikinci koşuda hiç iş üretmemeli.
	obs := empty()
	obs.Users["jit-ayse"] = []string{"jit-ayse", JITGroup}
	obs.Groups[JITGroup] = true
	obs.PosternSudoers[UserSudoPath("jit-ayse")] = steps[len(steps)-3].Content
	again, err := Plan(able(), Desired{Users: []User{{Name: "jit-ayse", JIT: true, Sudo: &rule}}}, obs)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Errorf("ikinci koşu iş üretti:\n%s", commandsOf(again))
	}
}

/*
 * ⚠️ SİSTEM GRUBUNA GEÇİCİ HESAP ALINMIYOR. docker grubuna üyelik root
 * eşdeğeri, shadow parola özetlerini okutur; hiçbiri sudo kuralı yazmadan
 * verilen bir yetki olmamalı. Sınır GID 1000 (login.defs GID_MIN) ve 1000'in
 * kendisi serbest; var olmayan grubu postern açıyor, o zaten üstünde.
 * postern-jit muaf: kanıt grubu, yetki grubu değil. Kalıcı hesaplara kural
 * uygulanmıyor — onların gruplarını yönetici bilerek seçiyor.
 */
func TestATemporaryAccountIsNotAddedToASystemGroup(t *testing.T) {
	d := Desired{
		Users:  []User{{Name: "jit-ayse", Groups: []string{"docker"}, JIT: true}},
		Groups: []Group{{Name: "docker"}},
	}
	withGID := func(gid int) Observed {
		o := empty()
		o.Groups["docker"] = true
		o.GIDs = map[string]int{"docker": gid}
		return o
	}

	if _, err := Plan(able(), d, withGID(998)); err == nil || !strings.Contains(err.Error(), "system group") {
		t.Fatalf("docker (gid 998) geçici hesaba açıldı: %v", err)
	}
	if _, err := Plan(able(), d, withGID(999)); err == nil {
		t.Fatal("gid 999 korunmuyor")
	}
	if _, err := Plan(able(), d, withGID(1000)); err != nil {
		t.Fatalf("gid 1000 (GID_MIN) reddedildi: %v", err)
	}
	if _, err := Plan(able(), d, withGID(1001)); err != nil {
		t.Fatalf("kullanıcı grubu reddedildi: %v", err)
	}
	// Olmayan grup: postern açacak, numarası bilinmiyor, ret yok.
	if _, err := Plan(able(), d, empty()); err != nil {
		t.Fatalf("henüz olmayan grup reddedildi: %v", err)
	}

	permanent := Desired{
		Users:  []User{{Name: "ops", Groups: []string{"docker"}}},
		Groups: []Group{{Name: "docker"}},
	}
	if _, err := Plan(able(), permanent, withGID(998)); err != nil {
		t.Fatalf("kalıcı hesap için sistem grubu reddedildi: %v", err)
	}

	marker := empty()
	marker.Groups[JITGroup] = true
	marker.GIDs = map[string]int{JITGroup: 999}
	if _, err := Plan(able(), Desired{Users: []User{{Name: "jit-ayse", JIT: true}}}, marker); err != nil {
		t.Fatalf("düşük numaralı postern-jit grubu geçici hesabı engelledi: %v", err)
	}
}

/*
 * ⚠️ %u ŞART, BAŞKA BELİRTEÇ YOK. %u'suz desen tek bir paylaşılan dosya:
 * ona yazmak herkesin principal listesini ezer. %h ev dizinini varsaymak
 * demek; reddetmek yanlış yere yazmaktan iyi. Sonuç kabuğa giriyor.
 */
func TestPrincipalsPathExpandsOnlyThePerAccountToken(t *testing.T) {
	cases := []struct {
		pattern, user, want string
		bad                 bool
	}{
		{"", "ayse", "", false},
		{"/etc/ssh/auth_principals/%u", "ayse", "/etc/ssh/auth_principals/ayse", false},
		// %% açılır ama sonuçta kalan '%' yol kontrolünden geçmez: kabuğa
		// giden yolda '%' yok (unsafePathByte). Reddedilmesi doğru.
		{"/etc/ssh/p/%%u/%u", "ayse", "", true},
		{"/etc/ssh/principals", "ayse", "", true},
		{"%h/.ssh/principals/%u", "ayse", "", true},
		{"/etc/ssh/auth_principals/%u%", "ayse", "", true},
		{"etc/%u", "ayse", "", true},
		{"/etc/ssh/%u\n", "ayse", "", true},
	}
	for _, c := range cases {
		got, err := PrincipalsPath(c.pattern, c.user)
		if c.bad {
			if err == nil {
				t.Errorf("%q kabul edildi: %q", c.pattern, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q → %q (%v), beklenen %q", c.pattern, got, err, c.want)
		}
	}
}

/*
 * ⚠️ HESAP AÇILDI AMA SERTİFİKA ONU AÇAMIYORDU — ölçüldü. Hedefin sshd'si
 * AuthorizedPrincipalsFile ile kuruluyken hesabın dosyası olmayınca
 * sertifika reddediliyor. Plan artık geçici hesabın dosyasını, içinde
 * principal (hesap adı) olacak biçimde yazıyor: yalnızca sshd bir desen
 * veriyorsa, yalnızca geçici hesaplara, ve dosya zaten doğruysa değil.
 */
func TestATemporaryAccountGetsAPrincipalsFileWhenSshdWantsOne(t *testing.T) {
	d := Desired{
		Users:          []User{{Name: "jitayse", JIT: true}},
		PrincipalsFile: "/etc/ssh/auth_principals/%u",
	}
	steps, err := Plan(able(), d, empty())
	if err != nil {
		t.Fatal(err)
	}
	var found *Step
	for i := range steps {
		if steps[i].Kind == StepPrincipal {
			found = &steps[i]
		}
	}
	if found == nil {
		t.Fatalf("principals adımı yok:\n%s", commandsOf(steps))
	}
	// ⚠️ İZİN KOMUTUN PARÇASI: dosyanın izni hedefin umask'ına
	// bırakılmıyor (bkz. plan.go'daki gerekçe).
	if found.Command != "sudo -n tee /etc/ssh/auth_principals/jitayse >/dev/null && "+
		"sudo -n chmod 0644 /etc/ssh/auth_principals/jitayse" || found.Content != "jitayse\n" {
		t.Errorf("adım yanlış: %q içerik %q", found.Command, found.Content)
	}
	if got := commandsOf(steps); strings.Index(got, "useradd") > strings.Index(got, "tee /etc/ssh") {
		t.Errorf("dosya hesaptan önce yazılıyor:\n%s", got)
	}

	// Desen yoksa (sshd "none" diyor) dosya da yok.
	steps, _ = Plan(able(), Desired{Users: d.Users}, empty())
	if strings.Contains(commandsOf(steps), "auth_principals") {
		t.Errorf("desensiz plan principals dosyası yazıyor:\n%s", commandsOf(steps))
	}
	// Kalıcı hesap da: postern'in açtığı her hesap sertifikayla giriyor.
	steps, _ = Plan(able(), Desired{Users: []User{{Name: "ops"}}, PrincipalsFile: d.PrincipalsFile}, empty())
	if !strings.Contains(commandsOf(steps), "tee /etc/ssh/auth_principals/ops") {
		t.Errorf("kalıcı hesap için principals dosyası yazılmıyor:\n%s", commandsOf(steps))
	}
	// Dosya zaten doğruysa yeniden yazılmıyor; yanlışsa yazılıyor.
	have := empty()
	have.Principals = map[string]string{"/etc/ssh/auth_principals/jitayse": "jitayse\n"}
	steps, _ = Plan(able(), d, have)
	if strings.Contains(commandsOf(steps), "tee /etc/ssh") {
		t.Errorf("doğru dosya yeniden yazılıyor:\n%s", commandsOf(steps))
	}
	have.Principals["/etc/ssh/auth_principals/jitayse"] = "someoneelse\n"
	steps, _ = Plan(able(), d, have)
	if !strings.Contains(commandsOf(steps), "tee /etc/ssh") {
		t.Errorf("yanlış içerikli dosya düzeltilmiyor:\n%s", commandsOf(steps))
	}
	// Reddedilen desen planı da düşürüyor: paylaşılan dosyaya yazılmaz.
	if _, err := Plan(able(), Desired{Users: d.Users, PrincipalsFile: "/etc/ssh/principals"}, empty()); err == nil {
		t.Error("paylaşılan principals dosyasına yazan plan kabul edildi")
	}
}

/*
 * ⚠️ YENİ HESAP sshd'YE GÖRE KİLİTLİ DOĞUYOR — ölçüldü: useradd shadow'a
 * "!" yazıyor ve OpenSSH "!" ile başlayan hesaba sertifikayla da
 * girdirmiyor. Plan hesabı açtıktan hemen sonra "*" yazıyor: parola
 * değil, kilit de değil. Var olan hesaba dokunulmuyor.
 */
func TestANewAccountIsNotLeftLockedForSshd(t *testing.T) {
	steps, err := Plan(able(), Desired{Users: []User{{Name: "jitayse", JIT: true}}}, empty())
	if err != nil {
		t.Fatal(err)
	}
	got := commandsOf(steps)
	if !strings.Contains(got, "usermod -p '*' jitayse") {
		t.Fatalf("kilit açılmıyor:\n%s", got)
	}
	if strings.Index(got, "usermod -p '*'") < strings.Index(got, "useradd") {
		t.Errorf("kilit hesap açılmadan önce açılıyor:\n%s", got)
	}
	// Kalıcı hesap da sertifikayla giriyor: aynı kural.
	steps, _ = Plan(able(), Desired{Users: []User{{Name: "ops"}}}, empty())
	if !strings.Contains(commandsOf(steps), "usermod -p '*' ops") {
		t.Errorf("kalıcı hesabın kilidi açılmıyor:\n%s", commandsOf(steps))
	}
	// Var olan hesabın parola alanına dokunulmuyor.
	have := empty()
	have.Users["ops"] = []string{"ops"}
	steps, _ = Plan(able(), Desired{Users: []User{{Name: "ops"}}}, have)
	if strings.Contains(commandsOf(steps), "-p '*'") {
		t.Errorf("var olan hesabın parola alanı yeniden yazılıyor:\n%s", commandsOf(steps))
	}
}
