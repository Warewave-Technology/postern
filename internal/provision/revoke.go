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
}

const (
	StepSudoRemove  StepKind = "sudo.remove"
	StepKill        StepKind = "user.kill"
	StepLock        StepKind = "user.lock"
	StepUserDel     StepKind = "user.delete"
	StepScratchDel  StepKind = "scratch.delete"
	StepReportOwned StepKind = "files.report"
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
	 * ⚠️ SİSTEM HESAPLARINA DOKUNULMUYOR. UID 0 root; 1000'in altı
	 * dağıtımların kendi hesapları. Bir yapılandırma hatası oraya
	 * işaret ederse, sökme planı makineyi bitirirdi.
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
		},
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
	if strings.Contains(p, "..") || strings.ContainsAny(p, " \t\n;|&$*?") {
		return "contains path traversal or shell syntax"
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
	case strings.ContainsAny(p, " \t\n;|&$*?"):
		return "contains shell syntax"
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
