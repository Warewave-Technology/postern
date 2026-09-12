/*
 * Package sudoers, postern'in yazacağı sudo kurallarını doğrular.
 *
 * ⚠️ NEDEN VAR: "dar bir sudo kuralı yazdım" cümlesi, kuralın dar
 * OLDUĞU anlamına gelmiyor ve aradaki fark genellikle root demek.
 *
 *   NOPASSWD: /usr/bin/vim        → vim içinden kabuk açılır, root.
 *   NOPASSWD: /usr/bin/less …     → less içinde "!/bin/sh", root.
 *   NOPASSWD: /usr/bin/systemctl  → `systemctl edit` editör açar, root.
 *   NOPASSWD: /usr/bin/find …     → find -exec, root.
 *
 * Yani operatör "yalnızca log okusun" diye yazdığı kuralla tam yetki
 * vermiş olabiliyor ve bunu hiçbir yerde göremiyor. Bu paket o farkı
 * ÖLÇÜLEBİLİR yapıyor: kural yazılmadan önce reddediliyor ya da
 * operatörün bilerek onayladığı kaydediliyor.
 *
 * ⚠️ BU, HEDEFTEKİ visudo'NUN YERİNE GEÇMİYOR. visudo sözdizimini
 * doğruluyor — dosyanın sudo'yu bozmamasını sağlıyor. Burası ANLAMI
 * doğruluyor: sözdizimi kusursuz bir kural pekâlâ root verebilir.
 * İkisi de gerekli ve ikisi ayrı soru.
 */
package sudoers

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

/*
 * escapeToRoot, izin verildiğinde kabuğa çıkabilen ikililer.
 *
 * ⚠️ LİSTE TAM DEĞİL VE OLAMAZ — bu yüzden tek savunma değil. GTFOBins
 * yüzlerce giriş taşıyor ve her dağıtım yenisini getiriyor. Buradaki
 * liste EN SIK yazılan kuralları yakalıyor; asıl savunma joker ve
 * göreli yol yasağı, çünkü onlar sınıfın tamamını kapatıyor.
 *
 * ⚠️ TAM YOL DEĞİL, TABAN AD KARŞILAŞTIRILIYOR: /usr/bin/vim ile
 * /bin/vim aynı tehlike, ve dağıtımlar ikisini de kullanıyor.
 */
var escapeToRoot = map[string]string{
	"sh": "is a shell", "bash": "is a shell", "dash": "is a shell",
	"zsh": "is a shell", "ksh": "is a shell", "csh": "is a shell",
	"su": "starts a shell as another user", "sudo": "re-enters sudo",
	"sudoedit": "runs an editor as root", "chroot": "runs a shell in a new root",

	"vi": "escapes to a shell", "vim": "escapes to a shell",
	"nvim": "escapes to a shell", "nano": "escapes to a shell",
	"ed": "escapes to a shell", "emacs": "escapes to a shell",
	"less": "escapes to a shell", "more": "escapes to a shell",
	"man": "escapes to a shell through its pager",

	"find": "runs commands with -exec", "awk": "runs commands",
	"gawk": "runs commands", "mawk": "runs commands",
	"sed": "runs commands with s///e", "xargs": "runs commands",
	"env": "runs commands", "nice": "runs commands",
	"timeout": "runs commands", "watch": "runs commands",

	"perl": "is an interpreter", "python": "is an interpreter",
	"python3": "is an interpreter", "ruby": "is an interpreter",
	"lua": "is an interpreter", "node": "is an interpreter",
	"php": "is an interpreter",

	"tar":   "runs commands through --checkpoint-action",
	"rsync": "runs commands through -e",
	"git":   "runs commands through hooks and pagers",
	"zip":   "runs commands", "gdb": "runs commands", "nmap": "runs commands",
	"make": "runs commands", "cpan": "runs commands", "pip": "runs commands",

	"systemctl":  "opens an editor with `systemctl edit`",
	"journalctl": "escapes through its pager",
	"service":    "runs arbitrary init scripts",
	"apt":        "runs commands through APT::Update hooks",
	"apt-get":    "runs commands through APT::Update hooks",
	"yum":        "runs commands through plugins", "dnf": "runs commands through plugins",
	"docker": "mounts the host filesystem as root",
	"mount":  "can mount over system paths",
	"dd":     "can overwrite any file", "tee": "can overwrite any file",
	"chmod": "can make any file setuid", "chown": "can take any file",
	"cp": "can overwrite any file", "mv": "can overwrite any file",
}

// Command, izin verilen tek bir komut.
type Command struct {
	// Path, MUTLAK yol. Çıplak ad kabul edilmiyor: PATH'e bağlı bir
	// kural, PATH'i etkileyebilen herkese o komutu seçtirir.
	Path string

	// Args, izin verilen SABİT argümanlar. Boşsa komut argümansız
	// çalıştırılabilir.
	Args []string
}

// String, sudoers satırındaki hâli.
func (c Command) String() string {
	if len(c.Args) == 0 {
		return c.Path
	}

	return c.Path + " " + strings.Join(c.Args, " ")
}

/*
 * Rule, bir gruba ya da bir JIT hakkına yazılacak sudo kuralı.
 */
type Rule struct {
	// RunAs, komutun hangi hesapla çalışacağı. Boşsa "root".
	RunAs string

	Commands []Command

	/*
	 * Acknowledged, operatörün kaçış riskini BİLEREK kabul ettiği.
	 *
	 * ⚠️ VARSAYILAN false VE ÖYLE KALMALI. Kaçış riski taşıyan bir
	 * kuralı sessizce yazmak, "dar yetki verdim" sanan operatöre root
	 * dağıttırırdı. Onay pozitif kanıt: birinin bunu görüp kabul
	 * ettiğini söylüyor ve denetim satırına da o şekilde giriyor.
	 */
	Acknowledged bool
}

// Finding, kuralda bulunan sorun.
type Finding struct {
	// Command, sorunun bulunduğu komut ("" ise kuralın kendisi).
	Command string

	// Reason, operatöre okunacak cümle.
	Reason string

	/*
	 * Escape true ise sorun "bu komut kabuğa çıkabiliyor" demek ve
	 * onayla geçilebiliyor. false ise kural YAPISAL olarak sınırsız
	 * ve onayla bile geçilmiyor.
	 */
	Escape bool
}

// Refused, bulgunun onayla bile geçilemeyeceği.
func (f Finding) Refused() bool { return !f.Escape }

/*
 * Validate, kuralı yazılmadan önce inceler.
 *
 * Dönen liste boşsa kural yazılabilir. Escape olmayan tek bir bulgu
 * bile kuralı reddediyor; Escape bulguları yalnızca Acknowledged ile
 * geçiyor.
 */
func Validate(r Rule) []Finding {
	var out []Finding

	if len(r.Commands) == 0 {
		return []Finding{{Reason: "the rule allows nothing; it would be written for no reason"}}
	}

	if bad := badName(r.RunAs); bad != "" {
		out = append(out, Finding{Reason: "run-as account " + bad})
	}

	for _, c := range r.Commands {
		out = append(out, checkCommand(c)...)
	}

	return out
}

// checkCommand, tek bir komutu inceler.
func checkCommand(c Command) []Finding {
	var out []Finding
	name := c.String()

	/*
	 * ⚠️ "ALL" SUDOERS'TA ÖZEL BİR SÖZCÜK: her komut demek. Bir kural
	 * listesinde görülmesi, listenin var olma sebebini ortadan
	 * kaldırıyor.
	 */
	if strings.TrimSpace(c.Path) == "ALL" {
		return []Finding{{Command: name, Reason: "ALL means every command"}}
	}

	if !strings.HasPrefix(c.Path, "/") {
		out = append(out, Finding{
			Command: name,
			Reason:  "is not an absolute path; which binary runs would depend on PATH",
		})
	}

	/*
	 * ⚠️ JOKER, SINIFIN TAMAMINI AÇIYOR. `/usr/bin/less /var/log/*` bir
	 * dosya adını sınırlıyor sanılıyor; oysa less'in kendi kaçışını
	 * sınırlamıyor. Daha kötüsü `/bin/*` gibi bir kalıp doğrudan her
	 * şeydir. Kaçış listesi eksik kalabilir; joker yasağı kalmaz.
	 */
	for _, part := range append([]string{c.Path}, c.Args...) {
		if strings.ContainsAny(part, "*?[]") {
			out = append(out, Finding{
				Command: name,
				Reason:  "contains a wildcard; a wildcard bounds the text, not what the command can do",
			})
			break
		}
	}

	/*
	 * ⚠️ OLUMSUZLAMA KURALLARI GÜVENİLİR DEĞİL. sudoers'ta "!" ile
	 * yasaklanan bir komuta, başka bir yol ya da sembolik bağ
	 * üzerinden ulaşılabiliyor; yasak listesi, izin listesinin yerini
	 * tutmuyor.
	 */
	if strings.HasPrefix(strings.TrimSpace(c.Path), "!") {
		out = append(out, Finding{
			Command: name,
			Reason:  "is a negation; sudo negations can be walked around with another path",
		})
	}

	/*
	 * ⚠️ SETENV ve benzeri etiketler ortam değişkeni geçirtiyor —
	 * LD_PRELOAD ile her komut root kabuğuna dönüşüyor.
	 */
	for _, tag := range []string{"SETENV:", "NOEXEC:", "EXEC:"} {
		if strings.Contains(strings.ToUpper(name), tag) {
			out = append(out, Finding{
				Command: name,
				Reason:  "carries a sudoers tag; tags change what the command may do",
			})
			break
		}
	}

	/*
	 * ⚠️ SATIR SONU VE DENETİM KARAKTERİ, DOSYAYA YENİ KURAL YAZAR.
	 * Bir komut alanına satır sonu sızarsa, sudoers dosyasına ikinci
	 * bir satır eklenmiş olur — ve o satırı kimse gözden geçirmedi.
	 */
	if strings.ContainsAny(name, "\n\r\x00") || strings.ContainsAny(name, "\t") {
		out = append(out, Finding{
			Command: name,
			Reason:  "contains a line break or control character; that writes a second rule nobody reviewed",
		})
	}

	if why, ok := escapeToRoot[path.Base(c.Path)]; ok {
		out = append(out, Finding{
			Command: name,
			Reason:  why + ", so this grant is root",
			Escape:  true,
		})
	}

	return out
}

// badName, hesap adının neden kabul edilmediğini söyler ("" ise sorun yok).
func badName(name string) string {
	if name == "" {
		// Boş: varsayılan root kullanılacak.
		return ""
	}
	if name == "ALL" {
		return "ALL means any account"
	}
	if strings.ContainsAny(name, " \t\n\r,()!*?") {
		return "contains characters sudoers reads as syntax"
	}

	return ""
}

/*
 * Refuses, doğrulamanın kuralı reddedip reddetmediği.
 *
 * ⚠️ ONAY YALNIZCA KAÇIŞ BULGULARINI GEÇİYOR. Yapısal sorunlar —
 * joker, göreli yol, ALL — onayla da geçmiyor: onlar "riski
 * biliyorum" denebilecek şeyler değil, kuralın hiçbir sınır
 * taşımadığı anlamına geliyorlar.
 */
func Refuses(findings []Finding, acknowledged bool) bool {
	for _, f := range findings {
		if f.Refused() || !acknowledged {
			return true
		}
	}

	return false
}

/*
 * Render, kuralı sudoers dosyası olarak yazar.
 *
 * ⚠️ DOĞRULAMADAN GEÇMEDEN YAZMIYOR. Ayrı bir fonksiyon olsaydı
 * çağıranın birini unutması mümkün olurdu; burada unutulamıyor.
 */
func Render(user string, r Rule, header string) (string, error) {
	if bad := badName(user); bad != "" || user == "" {
		return "", fmt.Errorf("sudoers.Render: user name %q: %s", user, bad+"is empty")
	}

	findings := Validate(r)
	if Refuses(findings, r.Acknowledged) {
		return "", fmt.Errorf("sudoers.Render: %s", Describe(findings))
	}

	runAs := r.RunAs
	if runAs == "" {
		runAs = "root"
	}

	cmds := make([]string, 0, len(r.Commands))
	for _, c := range r.Commands {
		cmds = append(cmds, c.String())
	}

	var b strings.Builder
	b.WriteString("# postern — generated, do not edit.\n")
	if header != "" {
		b.WriteString("# " + header + "\n")
	}
	fmt.Fprintf(&b, "%s ALL=(%s) NOPASSWD: %s\n", user, runAs, strings.Join(cmds, ", "))

	return b.String(), nil
}

// Describe, bulguları tek bir cümlede toplar.
func Describe(findings []Finding) string {
	if len(findings) == 0 {
		return "no findings"
	}

	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Command == "" {
			lines = append(lines, f.Reason)
			continue
		}
		lines = append(lines, f.Command+" "+f.Reason)
	}
	sort.Strings(lines)

	return strings.Join(lines, "; ")
}
