/*
 * Package provision, hedeflerde grup/kullanıcı/sudo durumunu kurar.
 *
 * ⚠️ PLAN İLE UYGULAMA AYRI — VE AYRILMALARI BU PAKETİN TEMEL KARARI.
 * Plan saf: gözlenen durum ile istenen durumu alıp adımları üretiyor,
 * hiçbir şeye bağlanmıyor ve tek başına ölçülebiliyor. Hatalar burada
 * yaşıyor: "zaten var mı", "hangi araç", "ne sırayla". Uygulama ince
 * bir katman ve gerçek makinede doğrulanıyor.
 *
 * ⚠️ BU PAKET HİÇBİR ŞEY SİLMİYOR. Silme ayrı ve yıkıcı bir yol;
 * yayılımın içine karıştırılsaydı, bir yapılandırma hatası "eksik"
 * diye okunup üretimde hesap kapatırdı.
 */
package provision

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/sudoers"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

// Group, hedefte bulunması istenen grup ve onun sudo kuralı.
type Group struct {
	Name string

	// Sudo, gruba yazılacak kural. Komutu yoksa sudo dosyası hiç
	// yazılmıyor — "sudosuz grup" geçerli bir istek.
	Sudo sudoers.Rule
}

// User, hedefte bulunması istenen hesap.
type User struct {
	Name   string
	Groups []string
}

// Desired, bir hedefte olması istenen durum.
type Desired struct {
	Groups []Group
	Users  []User
}

// Observed, hedefte ŞU AN olan durum.
type Observed struct {
	Groups map[string]bool
	// Users, hesabın üye olduğu gruplar.
	Users map[string][]string
	// PosternSudoers, postern'in yazdığı sudo dosyalarının içeriği.
	PosternSudoers map[string]string
}

// StepKind, adımın türü.
type StepKind string

const (
	StepGroupAdd    StepKind = "group.add"
	StepUserAdd     StepKind = "user.add"
	StepUserGroup   StepKind = "user.group"
	StepSudoStage   StepKind = "sudo.stage"
	StepSudoCheck   StepKind = "sudo.check"
	StepSudoInstall StepKind = "sudo.install"
)

/*
 * Step, hedefte çalıştırılacak tek bir iş.
 *
 * ⚠️ DEĞİŞKEN İÇERİK Command'A GİRMİYOR. sudoers metni Content'te
 * duruyor ve hedefe STDIN ile gidiyor; komut satırı sabit kalıyor.
 * Aksi hâlde bir grup adı ya da kural metni hedefin kabuğuna
 * yorumlanacak biçimde ulaşırdı — ve bu paket root yetkisiyle
 * çalışıyor.
 */
type Step struct {
	Kind    StepKind
	Command string
	// Content, varsa komutun stdin'ine verilecek metin.
	Content string
	// Why, panelde ve denetim satırında görünen cümle.
	Why string
}

// sudoPath, bir grup için postern'in yazdığı dosyanın yolu.
func sudoPath(group string) string { return "/etc/sudoers.d/postern-" + group }

// stagePath, doğrulanmadan önce yazıldığı geçici yol.
func stagePath(group string) string { return sudoPath(group) + ".staged" }

/*
 * Plan, gözlenen durumdan istenen duruma giden adımları üretir.
 *
 * ⚠️ YÖNETİLEMEYEN HEDEFE HİÇ ADIM ÜRETİLMİYOR. Yarısı uygulanmış bir
 * makine, hiç dokunulmamış olandan kötü: panel yeşil görünür ve kimse
 * bakmaz. Eksikler yoklamada zaten adlandırılmış durumda.
 */
func Plan(caps upstream.ManageCapabilities, d Desired, o Observed) ([]Step, error) {
	if !caps.Manageable() {
		return nil, fmt.Errorf("provision.Plan: %s", caps.Summary())
	}

	var steps []Step

	// ⚠️ SIRA ÖNEMLİ: grup, kullanıcı, üyelik, sudo. Kullanıcıyı
	// olmayan bir gruba eklemek hedefte hata veriyor; sudo kuralını
	// olmayan bir gruba yazmak ise sessizce etkisiz kalıyor.
	for _, g := range sortedGroups(d.Groups) {
		if bad := checkName(g.Name); bad != "" {
			return nil, fmt.Errorf("provision.Plan: group %q: %s", g.Name, bad)
		}
		if o.Groups[g.Name] {
			continue
		}
		steps = append(steps, Step{
			Kind:    StepGroupAdd,
			Command: caps.AddGroup + " " + g.Name,
			Why:     "group " + g.Name + " is missing",
		})
	}

	for _, u := range sortedUsers(d.Users) {
		if bad := checkName(u.Name); bad != "" {
			return nil, fmt.Errorf("provision.Plan: user %q: %s", u.Name, bad)
		}

		have, exists := o.Users[u.Name]
		if !exists {
			steps = append(steps, Step{
				Kind:    StepUserAdd,
				Command: caps.AddUser + " -m -s /bin/bash " + u.Name,
				Why:     "account " + u.Name + " is missing",
			})
		}

		missing := missingGroups(u.Groups, have)
		if len(missing) > 0 {
			steps = append(steps, Step{
				Kind:    StepUserGroup,
				Command: caps.ModUser + " -a -G " + strings.Join(missing, ",") + " " + u.Name,
				Why:     u.Name + " is not in " + strings.Join(missing, ", "),
			})
		}
	}

	for _, g := range sortedGroups(d.Groups) {
		if len(g.Sudo.Commands) == 0 {
			continue
		}

		/*
		 * ⚠️ KURAL BURADA DA DOĞRULANIYOR — VE BU İKİNCİ KONTROL
		 * KASITLI. Panel zaten doğruluyor; ama plana giden yol tek
		 * değil (API, CLI, ileride keşif kuralları) ve yazma anına
		 * en yakın kontrol, unutulamayan kontroldür.
		 */
		content, err := sudoers.Render("%"+g.Name, g.Sudo,
			"group "+g.Name+" — written by postern")
		if err != nil {
			return nil, fmt.Errorf("provision.Plan: group %q: %w", g.Name, err)
		}

		if o.PosternSudoers[sudoPath(g.Name)] == content {
			continue
		}

		/*
		 * ⚠️ ÜÇ ADIM, TEK ADIM DEĞİL: yaz → doğrula → yerine koy.
		 * Doğrudan hedef yola yazmak, geçersiz bir dosyanın o
		 * makinede HERKESİN sudo'sunu götürmesi demek — postern'in
		 * kendi hesabı dahil, yani makine kendini onaramaz hâle gelir.
		 * Doğrulama hedefte koşuyor, çünkü sözdizimi sudo sürümüne
		 * göre değişiyor ve bastion'da doğrulamak arkasını
		 * dolduramayacağımız bir iddia olurdu.
		 */
		steps = append(steps,
			Step{
				Kind:    StepSudoStage,
				Command: "cat > " + stagePath(g.Name),
				Content: content,
				Why:     "sudo rule for " + g.Name + " is missing or has changed",
			},
			Step{
				Kind:    StepSudoCheck,
				Command: caps.Visudo + " -cf " + stagePath(g.Name),
				Why:     "the target's own visudo must accept it before it is installed",
			},
			Step{
				Kind: StepSudoInstall,
				Command: "install -o root -g root -m 0440 " +
					stagePath(g.Name) + " " + sudoPath(g.Name) +
					" && rm -f " + stagePath(g.Name),
				Why: "install the checked rule",
			},
		)
	}

	return steps, nil
}

/*
 * checkName, hedefe gidecek adın güvenli olup olmadığını söyler.
 *
 * ⚠️ ADLAR KOMUT SATIRINA GİRİYOR. postern komutları hedefin kabuğuna
 * veriyor; bir grup adında boşluk ya da noktalı virgül olsaydı, o ad
 * ikinci bir komut olurdu — root yetkisiyle. Kural zaten elimizde:
 * hesap adları için kullanılan desen (model.ValidOSUserName) bu işi
 * ilk günden yapıyor.
 */
func checkName(name string) string {
	if name == "" {
		return "is empty"
	}
	if !model.ValidOSUserName(name) {
		return "is not a valid account or group name"
	}

	return ""
}

// missingGroups, hesabın henüz üye olmadığı grupları döner.
func missingGroups(want, have []string) []string {
	in := make(map[string]bool, len(have))
	for _, g := range have {
		in[g] = true
	}

	var out []string
	for _, g := range want {
		if !in[g] {
			out = append(out, g)
		}
	}
	sort.Strings(out)

	return out
}

// sortedGroups/sortedUsers, planı SIRALI yapıyor: aynı girdi her
// koşuda aynı adımları üretmeli, yoksa "değişti mi" sorusu
// cevaplanamaz.
func sortedGroups(in []Group) []Group {
	out := append([]Group(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out
}

func sortedUsers(in []User) []User {
	out := append([]User(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out
}
