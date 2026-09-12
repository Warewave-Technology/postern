package provision

import (
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/sudoers"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

// able, yönetilebilir bir hedefin yetenekleri.
func able() upstream.ManageCapabilities {
	return upstream.ManageCapabilities{
		Sudo: true, AddUser: "/usr/sbin/useradd", AddGroup: "/usr/sbin/groupadd",
		ModUser: "/usr/sbin/usermod", DelUser: "/usr/sbin/userdel",
		DelGroup: "/usr/sbin/groupdel", Visudo: "/usr/sbin/visudo",
		Family: "debian",
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
	want := []StepKind{
		StepGroupAdd, StepUserAdd, StepUserGroup,
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
			t.Errorf("sudosuz gruba dosya yazıldı: %v", kinds(steps))
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
