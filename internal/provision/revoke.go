package provision

// Hakkın geri alınması: kilitleme ve JIT hesabının sökülmesi.

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/Warewave-Technology/postern/internal/upstream"
)

// RevokeMode, hakkın nasıl geri alınacağı.
type RevokeMode string

const (
	/*
	 * ModeLock, kalıcı hesaplar için: hesap kilitleniyor, süreçleri
	 * kesiliyor, ama SİLİNMİYOR.
	 *
	 * ⚠️ SİLMEMEK BİR EKSİKLİK DEĞİL, KARAR. Silinen hesabın UID'si
	 * yeniden kullanılabiliyor; sonraki hesap aynı numarayı alırsa
	 * öncekinin bıraktığı bütün dosyaların sahibi oluyor. Kalıcı
	 * hesap, dosya sahipliğinin çıpası — "bunu kim bıraktı"
	 * sorusunun altı ay sonraki tek cevabı.
	 */
	ModeLock RevokeMode = "lock"

	/*
	 * ModeDelete, JIT hesapları için: hesap ve dosyaları siliniyor.
	 *
	 * ⚠️ YALNIZCA POSTERN'İN AÇTIĞI HESAPLARDA. JIT hesabının o
	 * makinede kalıcı bir işi yok; ama aynı ada sahip, postern'den
	 * önce var olan bir hesabı silmek başka bir şey olurdu.
	 */
	ModeDelete RevokeMode = "delete"
)

/*
 * JITGroup, postern'in açtığı geçici hesapların üye olduğu grup.
 *
 * ⚠️ SİLMENİN ÖN KOŞULU BU ÜYELİK. Ada bakarak silmek, postern'den
 * önce var olan bir hesabı yok edebilirdi; göç 022'nin dersi
 * ("satır kararlı kimlikle anahtarlanır, adla değil") burada da
 * geçerli. Grup, "bu hesabı ben açtım" demenin makinedeki hâli.
 */
const JITGroup = "postern-jit"

// Revoke, geri alınacak hak.
type Revoke struct {
	User string
	Mode RevokeMode

	// Home, hesabın ev dizini (getent'ten okunuyor).
	Home string

	/*
	 * Scratch, ev dizini dışında silinecek YOLLAR — operatörün
	 * önceden bildirdikleri.
	 *
	 * ⚠️ "KULLANICIYA AİT HER ŞEYİ SİL" DEĞİL. `find / -uid N -delete`
	 * bir üretim makinesini bir kez mahveder: yanlış UID, paylaşılan
	 * dizinde bırakılmış bir dosya, ya da bir editörün sahipliğini
	 * değiştirdiği sistem dosyası. Kapsam bildirilmiş yollarla
	 * sınırlı; dışarıda kalanlar SİLİNMİYOR, raporlanıyor.
	 */
	Scratch []string

	/*
	 * UID, hesabın numarası — SİLMEDEN ÖNCE okunuyor.
	 *
	 * ⚠️ RAPOR ADI DEĞİL NUMARAYI KULLANIYOR — ÖLÇÜLDÜ. Adla arama
	 * `userdel`den sonra çalışmıyor: ad artık çözülmüyor, find hata
	 * veriyor ve rapor SESSİZCE BOŞ dönüyor. Yani kalan dosyaları
	 * gösteren şey, tam da işe yarayacağı anda hiçbir şey göstermiyordu.
	 */
	UID int

	// InJITGroup, hesabın postern tarafından açıldığının kanıtı.
	InJITGroup bool

	// SudoFiles, bu hesap için yazılmış postern sudo dosyaları.
	SudoFiles []string
	// PrincipalsFile, hesabın principals dosyası (PrincipalsPath ile
	// çözülmüş); boşsa dosya yok.
	PrincipalsFile string
	/*
	 * DeleteGroups, hesapla birlikte silinecek gruplar — çağıranın
	 * "postern açtı ve başka kimse kullanmıyor" diye ÖLÇTÜĞÜ gruplar
	 * (GroupUsage). Plan bunu yeniden ölçmüyor; hesap silindikten sonra
	 * groupdel'e veriyor. Yalnızca silme kipinde.
	 */
	DeleteGroups []string
}

const (
	StepSudoRemove      StepKind = "sudo.remove"
	StepPrincipalRemove StepKind = "principal.remove"
	StepKill            StepKind = "user.kill"
	StepLock            StepKind = "user.lock"
	StepUserDel         StepKind = "user.delete"
	StepGroupDel        StepKind = "group.delete"
	StepScratchDel      StepKind = "scratch.delete"
	StepReportOwned     StepKind = "files.report"
)

/*
 * RevokePlan, hakkı geri alan adımları üretir.
 *
 * ⚠️ SIRA: SUDO, SÜREÇLER, SONRA HESAP. Kuralı önce almak, süreçler
 * ölene kadar geçen sürede yeni bir yükseltmeyi engelliyor. Süreçleri
 * hesaptan ÖNCE öldürmek ise zorunlu: hesap silindiğinde ad-UID eşlemesi
 * kayboluyor ve süreçler sahipsiz bir numarayla koşmaya devam ediyor.
 */
func RevokePlan(caps upstream.ManageCapabilities, r Revoke) ([]Step, error) {
	if !caps.Manageable() {
		return nil, fmt.Errorf("provision.RevokePlan: %s", caps.Summary())
	}
	if bad := checkName(r.User); bad != "" {
		return nil, fmt.Errorf("provision.RevokePlan: user %q: %s", r.User, bad)
	}

	/*
	 * ⚠️ ROOT'A DOKUNULMUYOR — VE KONTROLÜN KAPSAMI BU KADAR. Bu yorum
	 * önceden "1000'in altı dağıtımların kendi hesapları" diyordu ve kod
	 * yalnızca 0'ı reddediyordu: iddia koddan genişti. Sayısal bir taban
	 * güvenilir değil (UID_MIN eski RHEL'de 500, bazı kurulumlarda başka;
	 * doğrusu hedefin login.defs'ini okumak).
	 *
	 * Silmeyi aşağıdaki JIT grubu şartı koruyor. KİLİTLEMEDE böyle bir
	 * şart yok: orada yönetim hesabını durduran tek şey checkName'in onu
	 * adıyla reddetmesi. Rol o hesabı sistem hesabı olarak açıyor, yani bu
	 * UID kontrolü onu tek başına durdurmazdı ve postern kendini makineden
	 * kilitlerdi.
	 */
	if r.UID <= 0 {
		return nil, fmt.Errorf("provision.RevokePlan: %q has uid %d; postern does not touch system accounts",
			r.User, r.UID)
	}

	var steps []Step

	for _, f := range r.SudoFiles {
		if bad := checkSudoPath(f); bad != "" {
			return nil, fmt.Errorf("provision.RevokePlan: sudo file %q: %s", f, bad)
		}
		steps = append(steps, Step{
			Kind:    StepSudoRemove,
			Command: "sudo -n rm -f " + f,
			Why:     "take the sudo rule away before anything else",
		})
	}

	/*
	 * ⚠️ SÜREÇLER KESİLİYOR VE BU BİLİNÇLİ OLARAK SERT. nohup, tmux,
	 * screen ve systemd-run oturumla birlikte ölmüyor; süresi dolan bir
	 * hakkın arkasında koşan bir süreç bırakmak, hakkın bitmediği
	 * anlamına gelir. Yarım kalan iş kabul edilen bedel: doğru süre
	 * istemek kullanıcının işi.
	 */
	// Principals dosyası süreçlerden ÖNCE: kalan süreçler ölene kadar yeni
	// bir sertifika girişi olmasın.
	if r.PrincipalsFile != "" {
		st, err := PrincipalRemoveStep(r.PrincipalsFile, r.User)
		if err != nil {
			return nil, fmt.Errorf("provision.RevokePlan: %w", err)
		}
		steps = append(steps, st)
	}
	steps = append(steps, Step{
		Kind:    StepKill,
		Command: "sudo -n pkill -KILL -u " + r.User + " || true",
		Why:     "kill what the account is still running",
	})

	if r.Mode == ModeLock {
		steps = append(steps,
			Step{
				Kind:    StepLock,
				Command: "sudo -n " + caps.ModUser + " -L -s /usr/sbin/nologin " + r.User,
				Why:     "lock the account without deleting it",
			},
			/*
			 * ⚠️ KİLİTLENEN HESABIN DOSYALARI SİLİNMİYOR, LİSTELENİYOR.
			 * Neyin kaldığına yönetici karar veriyor; postern'in kendi
			 * başına silmesi, denetim kanıtını da götürebilirdi.
			 */
			Step{
				Kind:    StepReportOwned,
				Command: ownedCommand(r.UID),
				Why:     "list what the account still owns, for a human to decide",
			},
		)

		return steps, nil
	}

	/*
	 * ⚠️ SİLME, POSTERN'İN AÇTIĞINI KANITLAMADAN YAPILMIYOR. Aynı ada
	 * sahip, makineye postern'den önce konmuş bir hesabı silmek geri
	 * alınamaz; üyelik "bunu ben açtım" demenin tek güvenilir hâli.
	 */
	if !r.InJITGroup {
		return nil, fmt.Errorf(
			"provision.RevokePlan: %q is not in %s; postern only deletes accounts it created",
			r.User, JITGroup)
	}

	for _, p := range r.Scratch {
		if bad := checkScratch(p, r.Home); bad != "" {
			return nil, fmt.Errorf("provision.RevokePlan: scratch %q: %s", p, bad)
		}
		steps = append(steps, Step{
			Kind:    StepScratchDel,
			Command: "sudo -n rm -rf " + p,
			Why:     "remove a declared scratch path",
		})
	}

	steps = append(steps,
		// -r: ev dizini de gidiyor. Kapsam burada bitiyor.
		Step{
			Kind:    StepUserDel,
			Command: "sudo -n " + caps.DelUser + " -r " + r.User,
			Why:     "delete the temporary account and its home",
			Subject: r.User,
		},
	)
	// Gruplar hesaptan SONRA: hesap hâlâ üyeyken groupdel reddediliyor
	// (birincil gruptaysa) ya da üyeliği koparıyor.
	gsteps, err := GroupDeleteSteps(caps, r.DeleteGroups)
	if err != nil {
		return nil, fmt.Errorf("provision.RevokePlan: %w", err)
	}
	steps = append(steps, gsteps...)
	steps = append(steps,
		/*
		 * ⚠️ KAPSAM DIŞINDA KALANLAR SİLİNMİYOR, RAPORLANIYOR. Hesap
		 * gittikten sonra sahipsiz kalan dosyalar varsa operatör
		 * bunları görmeli; `find / -delete` ile temizlemek, bir kez
		 * yanlış UID'de makineyi bitirir.
		 */
		Step{
			Kind:    StepReportOwned,
			Command: ownedCommand(r.UID),
			Why:     "report anything the account owned outside the scope that was deleted",
		},
	)

	return steps, nil
}

/*
 * RemoveSudoFilesPlan, yalnızca postern'in yazdığı sudo dosyalarını
 * kaldıran adımlar — hesabı OLMAYAN bir hak için.
 *
 * ⚠️ NEDEN AYRI: sökme planı hesabın UID'sini ve üyeliğini istiyor, çünkü
 * silme kararı onlara bağlı. Hesap çoktan gitmişse (yedek süre, elle
 * silme, önceki yarım deneme) geride yalnızca sudo dosyası kalmış
 * olabilir ve o dosya hesap yeniden açıldığı gün yeniden yetki verir.
 * Yol kontrolü sökme planınınkinin aynısı.
 */
/*
 * PrincipalRemoveStep, hesabın principals dosyasını kaldıran adım.
 *
 * ⚠️ YOL HESABIN ADIYLA BİTMEK ZORUNDA. Silinen şey `rm -f` ile gidiyor;
 * desenden gelen yol bir başka hesabın (ya da paylaşılan bir dosyanın)
 * yolu olsaydı, geri alma başka birinin girişini kapatırdı.
 */
func PrincipalRemoveStep(path, user string) (Step, error) {
	if bad := checkName(user); bad != "" {
		return Step{}, fmt.Errorf("principals file for %q: %s", user, bad)
	}
	if bad := unsafePathByte(path); bad != "" {
		return Step{}, fmt.Errorf("principals file %q: %s", path, bad)
	}
	if !strings.HasPrefix(path, "/") || !strings.HasSuffix(path, "/"+user) {
		return Step{}, fmt.Errorf("principals file %q is not the file of account %q", path, user)
	}
	return Step{
		Kind:    StepPrincipalRemove,
		Command: "sudo -n rm -f " + path,
		Why:     "stop the certificate for " + user + " from opening this account",
	}, nil
}

/*
 * GroupDeleteSteps, postern'in açtığı ve artık boş olan grupları silen
 * adımlar. Adlar buraya gelmeden ölçülmüş olmalı (GroupUsage); burada
 * yalnızca ad biçimi ve postern-jit koruması var — kanıt grubu hiçbir
 * koşulda silinmiyor, başka geçici hesaplar ona bağlı.
 */
func GroupDeleteSteps(caps upstream.ManageCapabilities, groups []string) ([]Step, error) {
	var steps []Step
	for _, g := range groups {
		if bad := checkName(g); bad != "" {
			return nil, fmt.Errorf("group %q: %s", g, bad)
		}
		if g == JITGroup {
			return nil, fmt.Errorf("group %q is postern's marker group and is never deleted", g)
		}
		steps = append(steps, Step{
			Kind:    StepGroupDel,
			Command: "sudo -n " + caps.DelGroup + " " + g,
			Why:     "remove group " + g + ": postern created it for this account and nothing else uses it",
			Subject: g,
		})
	}
	return steps, nil
}

func RemoveSudoFilesPlan(files []string) ([]Step, error) {
	var steps []Step
	for _, f := range files {
		if bad := checkSudoPath(f); bad != "" {
			return nil, fmt.Errorf("provision.RemoveSudoFilesPlan: sudo file %q: %s", f, bad)
		}
		steps = append(steps, Step{
			Kind:    StepSudoRemove,
			Command: "sudo -n rm -f " + f,
			Why:     "remove the rule of an account that is already gone",
		})
	}

	return steps, nil
}

/*
 * ownedCommand, hesabın sahip olduğu dosyaları SINIRLI bir kümede arar.
 *
 * ⚠️ KÖKTEN ARAMA YOK. `find /` bir üretim makinesinde dakikalar sürüyor
 * ve ağ dosya sistemlerine dalıyor; -xdev ile sınırlı, sayılı dizinde
 * arama, cevabın çoğunu bedelsiz veriyor. Bulunan şey SİLİNMİYOR.
 */
func ownedCommand(uid int) string {
	return "sudo -n find /home /tmp /var/tmp /opt /srv -xdev -uid " + strconv.Itoa(uid) +
		" -maxdepth 4 -print 2>/dev/null | head -n 200 || true"
}

// checkSudoPath, silinecek sudo dosyasının postern'e ait olduğunu doğrular.
func checkSudoPath(p string) string {
	if !strings.HasPrefix(p, "/etc/sudoers.d/postern-") {
		// ⚠️ postern yalnızca KENDİ yazdığı dosyayı siliyor: başka bir
		// şeyin koyduğu kuralı kaldırmak, o makinenin yetkilerini
		// kimsenin beklemediği biçimde değiştirirdi.
		return "is not a file postern wrote"
	}
	if bad := unsafePathByte(p); bad != "" {
		return bad
	}
	if strings.Contains(p, "..") {
		return "contains path traversal"
	}

	return ""
}

/*
 * unsafePathByte, yolun komut satırına girmesi güvenli olmayan bir bayt
 * taşıyıp taşımadığını söyler.
 *
 * ⚠️ İZİN LİSTESİ, YASAK LİSTESİ DEĞİL — VE FARK ÖLÇÜLDÜ. Bu kontrol
 * önceden " \t\n;|&$*?" karakterlerini yasaklıyordu; ters tırnak, `<`,
 * `>`, süslü parantez ve tırnak geçiyordu. "/srv/build/`sh</tmp/p`"
 * bütün kontrollerden geçip `sudo -n rm -rf /srv/build/`sh</tmp/p``
 * üretti: kabuk ters tırnağı rm'den ÖNCE açıyor ve /tmp/p'yi parolasız
 * root sudo tutan hesapla çalıştırıyor. Aynı sınıf hata plan.go'da
 * usermod satırı için kapatılmıştı (7a85bab); buradaki yollar aynı
 * kapıdan geçmemişti. Kabuğun yorumlayabileceği her şeyi saymak yerine
 * bir yolun taşıması GEREKENİ sayıyoruz: harf, rakam, /, ., _ ve -.
 */
func unsafePathByte(p string) string {
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/', c == '.', c == '_', c == '-':
		default:
			return fmt.Sprintf("contains %q, which is not allowed in a path postern removes", c)
		}
	}

	return ""
}

/*
 * checkScratch, silinecek yolun güvenli olduğunu doğrular.
 *
 * ⚠️ BU FONKSİYON BİR ÜRETİM MAKİNESİ İLE ARAMIZDAKİ TEK ŞEY.
 * `rm -rf` kök, /home ya da boş bir değerle koşarsa geri dönüş yok.
 */
func checkScratch(p, home string) string {
	switch {
	case strings.TrimSpace(p) == "":
		return "is empty"
	case !strings.HasPrefix(p, "/"):
		return "is not an absolute path"
	case strings.Contains(p, ".."):
		return "contains .."
	}
	if bad := unsafePathByte(p); bad != "" {
		return bad
	}

	clean := path.Clean(p)
	if clean != p {
		return "is not in canonical form"
	}

	// ⚠️ Kök ve tepe dizinler asla: bunlar "kullanıcının çalışma alanı"
	// değil, makinenin kendisi.
	forbidden := map[string]bool{
		"/": true, "/home": true, "/etc": true, "/var": true, "/usr": true,
		"/bin": true, "/sbin": true, "/lib": true, "/opt": true, "/srv": true,
		"/tmp": true, "/root": true, "/boot": true, "/dev": true, "/proc": true,
		"/sys": true, "/run": true,
	}
	if forbidden[clean] {
		return "is a system directory"
	}
	if home != "" && clean == path.Clean(home) {
		// Ev dizini zaten userdel -r ile gidiyor; iki kez silmek
		// gereksiz ve sırayı kırılgan yapar.
		return "is the home directory, which userdel -r already removes"
	}
	// ⚠️ En az iki seviye derinlik: /var gibi bir üst dizin yasak,
	// /var/lib de öyle. Çalışma alanı bir yaprak olmalı.
	if strings.Count(clean, "/") < 2 {
		return "is a top-level directory"
	}

	return ""
}
