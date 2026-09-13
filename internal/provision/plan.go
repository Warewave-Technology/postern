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
	"time"

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

	/*
	 * JIT true ise hesap GEÇİCİ: postern açıyor, süresi dolunca siliyor.
	 *
	 * ⚠️ ÜYELİK KANIT: JIT hesabı postern-jit grubuna giriyor ve sökme
	 * planı YALNIZCA o gruptaki hesabı siliyor. Bu üyeliği kuran tek yer
	 * burası; kurulmasaydı hiçbir hesap silinemez, ya da daha kötüsü,
	 * kanıt elle verilirdi (canlı test bir süre öyle yapıyordu).
	 */
	JIT bool

	/*
	 * ExpiresAt, JIT hesabının süresi — hedefe `useradd -e` ile de
	 * yazılıyor.
	 *
	 * ⚠️ YEDEK, ASIL MEKANİZMA DEĞİL. Sökmeyi postern yapıyor; bu tarih,
	 * postern ölürse ya da hedefe ulaşamazsa hesabın sonsuza dek açık
	 * kalmaması için. Gün çözünürlüğünde ve süre bitiminden SONRAKİ güne
	 * yuvarlanıyor: yedeğin asıl süreden önce vurması, geçerli bir hakkı
	 * ortasından kesmek olurdu.
	 */
	ExpiresAt time.Time

	/*
	 * Sudo, yalnızca bu hesaba yazılacak kural (grup kuralından ayrı).
	 * nil ise kullanıcı dosyası yazılmıyor. Dosya postern-user-<ad>
	 * adıyla gidiyor ve sökme planı onu adıyla kaldırıyor.
	 */
	Sudo *sudoers.Rule
}

// Desired, bir hedefte olması istenen durum.
type Desired struct {
	Groups []Group
	Users  []User
	/*
	 * PrincipalsFile, hedefin sshd'sinin AuthorizedPrincipalsFile deseni
	 * (upstream.ManageCapabilities.PrincipalsFile). Boş değilse geçici
	 * hesabın dosyası yazılıyor; boşsa sshd giriş adını sertifikanın
	 * principal'ında arıyor ve dosya gerekmiyor.
	 */
	PrincipalsFile string
}

// Observed, hedefte ŞU AN olan durum.
type Observed struct {
	Groups map[string]bool
	// GIDs, var olan grupların numaraları — sistem grubu ayrımı için.
	GIDs map[string]int
	// Users, hesabın üye olduğu gruplar.
	Users map[string][]string
	// PosternSudoers, postern'in yazdığı sudo dosyalarının içeriği.
	PosternSudoers map[string]string
	// Principals, geçici hesapların principals dosyalarının içeriği (yol → içerik).
	Principals map[string]string
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
	StepPrincipal   StepKind = "principal.write"
	StepUserUnlock  StepKind = "user.unlock"
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
	Kind StepKind

	/*
	 * Command, hedefte AYNEN çalıştırılacak komut — sudo dahil.
	 *
	 * ⚠️ SUDO PLANDA, UYGULAYICIDA DEĞİL. Plan operatöre gösterilen
	 * şey; "ne çalışacak" sorusunun cevabı burada eksiksiz durmalı.
	 * Uygulayıcı komutu değiştirirse, onaylanan ile koşan farklı olur.
	 */
	Command string
	// Content, varsa komutun stdin'ine verilecek metin.
	Content string
	// Why, panelde ve denetim satırında görünen cümle.
	Why string
}

// SudoPath, bir grup için postern'in yazdığı dosyanın yolu. Dışa açık:
// hedefin durumunu okuyan taraf (Observed.PosternSudoers) aynı yolu
// kullanmazsa plan dosyayı hiç "var" görmez ve her koşuda yeniden yazar.
func SudoPath(group string) string { return "/etc/sudoers.d/postern-" + group }

// UserSudoPath, bir hesap için postern'in yazdığı dosyanın yolu. Grup
// dosyalarından ayrı bir önek: "dba" adlı grup ile "dba" adlı hesabın
// kuralları aynı dosyaya düşmesin.
func UserSudoPath(user string) string { return "/etc/sudoers.d/postern-user-" + user }

/*
 * PrincipalsPath, sshd'nin AuthorizedPrincipalsFile desenini bir hesap
 * için yola çevirir. Boş desen → "" (dosya gerekmiyor).
 *
 * ⚠️ DESENDE %u ŞART. %u'suz bir desen tek bir PAYLAŞILAN dosya demek
 * ve ona yazmak makinedeki herkesin principal listesini ezmek olurdu.
 * %h (ev dizini) gibi öbür belirteçler desteklenmiyor: ev dizinini
 * varsaymak yerine reddetmek, yanlış yere dosya yazmaktan iyi. Sonuç
 * kabuk komutuna giriyor; yol karakter kontrolünden geçmek zorunda.
 */
func PrincipalsPath(pattern, user string) (string, error) {
	if pattern == "" {
		return "", nil
	}
	if !strings.Contains(pattern, "%u") {
		return "", fmt.Errorf("principals file %q is not per account (no %%u); refusing to write a shared file", pattern)
	}
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '%' {
			b.WriteByte(pattern[i])
			continue
		}
		if i+1 >= len(pattern) {
			return "", fmt.Errorf("principals file %q ends with a bare %%", pattern)
		}
		switch pattern[i+1] {
		case 'u':
			b.WriteString(user)
		case '%':
			b.WriteByte('%')
		default:
			return "", fmt.Errorf("principals file %q uses %%%c, which postern does not expand", pattern, pattern[i+1])
		}
		i++
	}
	path := b.String()
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("principals file %q is not an absolute path", path)
	}
	if bad := unsafePathByte(path); bad != "" {
		return "", fmt.Errorf("principals file %q: %s", path, bad)
	}
	return path, nil
}

// stagePath, doğrulanmadan önce yazıldığı geçici yol.
func stagePath(path string) string { return path + ".staged" }

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

	/*
	 * ⚠️ JIT HESAP VARSA postern-jit GRUBU PLANA GİRİYOR — kimse
	 * istemese de. Üyelik silmenin ön koşulu; grup yoksa üyelik de yok ve
	 * hesap bir daha silinemez.
	 */
	groups := sortedGroups(d.Groups)
	if anyJIT(d.Users) && !hasGroup(groups, JITGroup) {
		groups = sortedGroups(append(groups, Group{Name: JITGroup}))
	}

	// ⚠️ SIRA ÖNEMLİ: grup, kullanıcı, üyelik, sudo. Kullanıcıyı
	// olmayan bir gruba eklemek hedefte hata veriyor; sudo kuralını
	// olmayan bir gruba yazmak ise sessizce etkisiz kalıyor.
	for _, g := range groups {
		if bad := checkName(g.Name); bad != "" {
			return nil, fmt.Errorf("provision.Plan: group %q: %s", g.Name, bad)
		}
		if o.Groups[g.Name] {
			continue
		}
		steps = append(steps, Step{
			Kind:    StepGroupAdd,
			Command: "sudo -n " + caps.AddGroup + " " + g.Name,
			Why:     "group " + g.Name + " is missing",
		})
	}

	for _, u := range sortedUsers(d.Users) {
		if bad := checkName(u.Name); bad != "" {
			return nil, fmt.Errorf("provision.Plan: user %q: %s", u.Name, bad)
		}
		/*
		 * ⚠️ ÜYELİK LİSTESİNDEKİ HER GRUP DA DOĞRULANIYOR — VE BU SATIR
		 * ÖLÇÜLMÜŞ BİR ENJEKSİYONU KAPATIYOR. Grup adları yalnızca
		 * d.Groups'tan geçerken kontrol ediliyordu; kullanıcının Groups
		 * listesi hiç bakılmadan usermod satırına yapıştırılıyordu.
		 * "dba;id>/tmp/pwn" verildiğinde plan hatasız şunu üretti:
		 *
		 *   sudo -n /usr/sbin/usermod -a -G dba;id>/tmp/pwn ayse
		 *
		 * Bu satır parolasız root sudo tutan hesabın kabuğunda koşuyor;
		 * noktalı virgülden sonrası ikinci bir komut. O gün üretimde bu
		 * planı çağıran bir yol yoktu — panele bağlanmadan önce kapandı.
		 */
		for _, g := range u.Groups {
			if bad := checkName(g); bad != "" {
				return nil, fmt.Errorf("provision.Plan: user %q: group %q: %s", u.Name, g, bad)
			}
		}

		have, exists := o.Users[u.Name]
		want := u.Groups
		if u.JIT {
			want = append(append([]string(nil), u.Groups...), JITGroup)
			/*
			 * ⚠️ POSTERN'İN AÇMADIĞI BİR HESAP JIT YAPILMIYOR. Makinede
			 * aynı adla önceden var olan bir hesabı postern-jit grubuna
			 * almak, süresi dolunca onu SİLMEK demek — ve o hesap birinin
			 * kalıcı hesabı olabilir. Var olan ama grupta olan hesap ise
			 * önceki bir hakkın hesabı: uzatmak güvenli.
			 */
			if exists && !hasName(have, JITGroup) {
				return nil, fmt.Errorf("provision.Plan: account %q already exists on the target "+
					"and postern did not create it; refusing to take it over as a temporary account",
					u.Name)
			}
			/*
			 * ⚠️ SİSTEM GRUBUNA GEÇİCİ HESAP ALINMIYOR. Grup adı temiz ve
			 * grup var olabilir; ama numarası 1000'in altındaysa o bir
			 * sistem grubu (docker, wheel, shadow, adm…) ve üyeliği sudo
			 * kuralı yazmadan verilen bir yetki. Yalnızca hedefte VAR OLAN
			 * grup için soruluyor: olmayan grubu postern açıyor ve groupadd
			 * ona GID_MIN üstü bir numara veriyor. Döngü u.Groups üzerinde,
			 * `want` üzerinde DEĞİL: postern-jit oraya aşağıda ekleniyor ve
			 * o bir kanıt grubu, yetki grubu değil — numarası ne olursa
			 * olsun üyelik verilmeli (mutasyonla ölçüldü: muafiyet için
			 * ayrı bir koşul gerekmiyor, döngünün kapsamı yetiyor).
			 */
			for _, g := range u.Groups {
				if gid, known := o.GIDs[g]; known && gid < MinJITGID {
					return nil, fmt.Errorf("provision.Plan: group %q on the target is a system group "+
						"(gid %d, below %d); a temporary account is not added to protected groups",
						g, gid, MinJITGID)
				}
			}
		}
		if !exists {
			// Kabuk hedeften: bash yoksa /bin/sh (upstream.ManageCapabilities.Shell).
			cmd := "sudo -n " + caps.AddUser + " -m -s " + caps.Shell
			if u.JIT && !u.ExpiresAt.IsZero() {
				cmd += " -e " + expiryBackstop(u.ExpiresAt)
			}
			steps = append(steps, Step{
				Kind:    StepUserAdd,
				Command: cmd + " " + u.Name,
				Why:     "account " + u.Name + " is missing",
			})
			/*
			 * ⚠️ PAROLASIZ HESAP sshd İÇİN KİLİTLİ — ölçüldü: useradd
			 * shadow'a "!" yazıyor ve OpenSSH "!" ile başlayan hesaba
			 * sertifikayla da girdirmiyor ("account is locked"). Hesap
			 * açılmış, dosyası yazılmış, sertifika kabul edilmiş — ve
			 * kapı yine kapalı. "*" parola DEĞİL (hiçbir girdi eşleşmez)
			 * ama kilit de değil; sertifika girişi bununla açılıyor.
			 * Yalnızca yeni açılan hesapta: var olanı postern açtıysa
			 * zaten böyle, açmadıysa plana giremez.
			 */
			steps = append(steps, Step{
				Kind:    StepUserUnlock,
				Command: "sudo -n " + caps.ModUser + " -p '*' " + u.Name,
				Why:     "sshd refuses a passwordless (\"locked\") account even with a certificate; '*' is no password but no lock",
			})
		}

		missing := missingGroups(want, have)
		if len(missing) > 0 {
			steps = append(steps, Step{
				Kind: StepUserGroup,
				Command: "sudo -n " + caps.ModUser + " -a -G " +
					strings.Join(missing, ",") + " " + u.Name,
				Why: u.Name + " is not in " + strings.Join(missing, ", "),
			})
		}

		/*
		 * ⚠️ HESAP AÇILDI AMA SERTİFİKA ONU AÇAMIYOR — ölçüldü: hedefin
		 * sshd'si AuthorizedPrincipalsFile ile kuruluyken hesabın dosyası
		 * olmayınca sertifika reddediliyor (principal, giriş adında
		 * aranmıyor). Rol kalıcı hesapların dosyalarını yazıyor; geçici
		 * hesabınkini postern yazmak zorunda. İçerik sertifikanın
		 * principal'ı, yani hesabın adı (upstream/dial.go: Principals =
		 * OSUser). tee root'la, umask'la 0644 — sshd'nin StrictModes'u
		 * için yeterli.
		 */
		if u.JIT && d.PrincipalsFile != "" {
			path, err := PrincipalsPath(d.PrincipalsFile, u.Name)
			if err != nil {
				return nil, fmt.Errorf("provision.Plan: user %q: %w", u.Name, err)
			}
			if content := u.Name + "\n"; o.Principals[path] != content {
				steps = append(steps, Step{
					Kind:    StepPrincipal,
					Command: "sudo -n tee " + path + " >/dev/null",
					Content: content,
					Why:     "let the certificate for " + u.Name + " open this account",
				})
			}
		}
	}

	for _, u := range sortedUsers(d.Users) {
		if u.Sudo == nil {
			continue
		}
		// Kullanıcı kuralı grup kuralıyla aynı üç adımdan geçiyor.
		content, err := sudoers.Render(u.Name, *u.Sudo, "user "+u.Name+" — written by postern")
		if err != nil {
			return nil, fmt.Errorf("provision.Plan: user %q: %w", u.Name, err)
		}
		if o.PosternSudoers[UserSudoPath(u.Name)] == content {
			continue
		}
		steps = append(steps, sudoSteps(caps, UserSudoPath(u.Name), content,
			"sudo rule for "+u.Name+" is missing or has changed")...)
	}

	for _, g := range groups {
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

		if o.PosternSudoers[SudoPath(g.Name)] == content {
			continue
		}
		steps = append(steps, sudoSteps(caps, SudoPath(g.Name), content,
			"sudo rule for "+g.Name+" is missing or has changed")...)
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
	/*
	 * ⚠️ YÖNETİM HESABI VE GRUBU PLANA GİRMİYOR. Rol "postern" hesabını
	 * ve aynı adlı grubu sistem hesabı olarak açıyor. Bir plan onu
	 * değiştirebilseydi — üyeliğe bir insan eklemek, ya da sökme
	 * planında hesabı kilitlemek — postern ya kendi yönetim hesabını
	 * başkasıyla paylaşır ya da kendini makineden kilitlerdi; ikinci
	 * durumda makineyi onaracak bir yol da kalmazdı.
	 */
	if model.IsManagementName(name) {
		return "is postern's own management account; postern never plans changes to it"
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

/*
 * sudoSteps, bir sudoers dosyasını yazan üç adım: yaz → doğrula → yerine koy.
 * Grup ve kullanıcı dosyaları aynı yoldan geçiyor; iki kopya, birinde
 * düzeltilen bir şeyin öbüründe unutulması demekti.
 */
func sudoSteps(caps upstream.ManageCapabilities, path, content, why string) []Step {
	/*
	 * ⚠️ ÜÇ ADIM, TEK ADIM DEĞİL: yaz → doğrula → yerine koy.
	 * Doğrudan hedef yola yazmak, geçersiz bir dosyanın o
	 * makinede HERKESİN sudo'sunu götürmesi demek — postern'in
	 * kendi hesabı dahil, yani makine kendini onaramaz hâle gelir.
	 * Doğrulama hedefte koşuyor, çünkü sözdizimi sudo sürümüne
	 * göre değişiyor ve bastion'da doğrulamak arkasını
	 * dolduramayacağımız bir iddia olurdu.
	 */
	return []Step{
		{
			Kind: StepSudoStage,
			/*
			 * ⚠️ tee, `cat >` DEĞİL — VE FARK KOMUTU ÇALIŞTIRIYOR
			 * YA DA ÇALIŞTIRMIYOR. Yönlendirme sudo'dan ÖNCE,
			 * çağıran kabukta yapılıyor: `sudo -n cat > /etc/...`
			 * dosyayı YETKİSİZ kullanıcı olarak açmaya çalışır ve
			 * "permission denied" ile düşer. İlk yazdığım plan bu
			 * hatayı taşıyordu; canlı denemede farkında olmadan
			 * tee'ye çevirip doğruladığım için de görünmemişti.
			 */
			Command: "sudo -n tee " + stagePath(path) + " >/dev/null",
			Content: content,
			Why:     why,
		},
		{
			Kind:    StepSudoCheck,
			Command: "sudo -n " + caps.Visudo + " -cf " + stagePath(path),
			Why:     "the target's own visudo must accept it before it is installed",
		},
		{
			Kind: StepSudoInstall,
			Command: "sudo -n install -o root -g root -m 0440 " +
				stagePath(path) + " " + path +
				" && sudo -n rm -f " + stagePath(path),
			Why: "put the checked file in place and remove the staging copy",
		},
	}
}

// anyJIT, en az bir geçici hesap var mı.
func anyJIT(users []User) bool {
	for _, u := range users {
		if u.JIT {
			return true
		}
	}

	return false
}

func hasGroup(groups []Group, name string) bool {
	for _, g := range groups {
		if g.Name == name {
			return true
		}
	}

	return false
}

func hasName(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}

	return false
}

/*
 * expiryBackstop, useradd -e için tarih: sürenin bittiği günün ERTESİ.
 *
 * ⚠️ useradd -e gün çözünürlüğünde ve hesabı o günün BAŞINDA kapatıyor.
 * Aynı günü yazsaydık, öğleden sonra biten bir hak sabah kesilirdi.
 * Ertesi gün, yedeğin asıl süreden hiç önce vurmamasını garanti ediyor;
 * bedeli, postern ölmüşse hesabın en çok bir gün fazla açık kalması.
 */
func expiryBackstop(t time.Time) string {
	return t.UTC().Add(24 * time.Hour).Format("2006-01-02")
}
