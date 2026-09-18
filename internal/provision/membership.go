package provision

/*
 * postern'in kendi ad uzayındaki grupların ÜYELİĞİNİ zorlamak.
 *
 * ⚠️ NEDEN GEREKLİ: PLAN YALNIZCA EKLİYOR. `usermod -a -G` katıcı, yani
 * eksik üyelik her koşuda düzeliyor ama FAZLA üyelik hiç düzelmiyor.
 * Hedefte elle `postern-dba` grubuna eklenen bir hesap, postern'in o
 * gruba yazdığı sudo kuralını alıyor — ve postern'in hiçbir kaydında
 * görünmüyor. Ölçülebilir sonuç: postern'in verdiği yetki, postern'in
 * bilmediği bir kişide.
 *
 * ⚠️ ÖNEK BURADA DA KONTROL EDİLİYOR, ÇAĞIRANA GÜVENİLMİYOR. Bu kod
 * hesap çıkarma komutu üretiyor; yanlış bir grup adıyla çağrılması,
 * makinedeki gerçek bir ekibi kendi grubundan atmak demek. Çağıranın
 * doğru listeyi vermesine bağlı kalmak, o hatayı sessiz yapardı.
 */

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/Warewave-Technology/postern/internal/upstream"
)

/*
 * OwnedPrefix, postern'in hedefte açtığı grupların öneki.
 *
 * ⚠️ SAHİPLİK KANITI. Makinede zaten bir `dba` grubu olabilir ve içinde
 * postern'in tanımadığı yirmi kişi durabilir; üyeliğini zorlamak o yirmi
 * kişiyi kendi grubundan atmak olurdu. Önekli ad uzayı postern'in kendi
 * ilanı ve zorlama YALNIZCA orada yapılıyor.
 */
const OwnedPrefix = "postern-"

// Extra, postern'in ad uzayındaki bir grupta postern'in koymadığı üyelik.
type Extra struct {
	Group string
	User  string
}

/*
 * ExtraMembers, önekli gruplarda beklenmeyen üyeleri bulur.
 *
 * expected: grup adı → o grupta olması beklenen hesaplar. Listede
 * OLMAYAN bir grup hiç incelenmiyor — "beklenen kimse yok" ile "bu grubu
 * bilmiyorum" ayrı şeyler ve ikincisini birincisi gibi okumak, süpürmenin
 * görmediği bir grubun bütün üyelerini attırırdı.
 */
func ExtraMembers(o Observed, expected map[string][]string) []Extra {
	var out []Extra
	for group, members := range o.GroupMembers {
		if !strings.HasPrefix(group, OwnedPrefix) {
			continue
		}
		/*
		 * ⚠️ İŞARET GRUPLARI DIŞARIDA. postern-managed ve postern-jit
		 * üyeliği "bu hesabı postern açtı" demek ve silmenin ön koşulu.
		 * Yanlışlıkla kaldırmak, postern'in AÇTIĞI bir hesabı sonsuza
		 * dek silinemez yapar — kaydı bir yeniden kurulumda kaybolmuş
		 * bir hesapta bu tek yönlü bir hasar. Fazla üyeliğin buradaki
		 * zararı ise tek başına yetki vermiyor: silme ayrıca satır ve
		 * insan onayı istiyor.
		 */
		if group == ManagedGroup || group == JITGroup {
			continue
		}
		want, known := expected[group]
		if !known {
			continue
		}
		set := make(map[string]bool, len(want))
		for _, w := range want {
			set[w] = true
		}
		for _, m := range members {
			if m == "" || set[m] {
				continue
			}
			out = append(out, Extra{Group: group, User: m})
		}
	}
	// Sıralı: adım listesi koşudan koşuya aynı olmalı, yoksa denetim
	// defterindeki iki satırı karşılaştırmak imkânsız olur.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}

		return out[i].User < out[j].User
	})

	return out
}

/*
 * MembershipPlan, fazla üyelikleri kaldıran adımları üretir.
 *
 * ⚠️ HESABA DOKUNMUYOR, YALNIZCA ÜYELİĞE. Kişi makinede kalıyor, evi
 * duruyor, başka grupları duruyor; giden tek şey postern'in verdiği
 * sudo. Fazla üyeliği "postern'in açmadığı hesap" sanıp silmek, başka
 * bir aracın sahibi olduğu bir hesabı yok etmek olurdu.
 */
func MembershipPlan(caps upstream.ManageCapabilities, extras []Extra) ([]Step, error) {
	if len(extras) == 0 {
		return nil, nil
	}
	if caps.DelMember == "" {
		return nil, fmt.Errorf("provision.MembershipPlan: this target has neither gpasswd nor delgroup, " +
			"so postern cannot take an account out of a group here")
	}

	steps := make([]Step, 0, len(extras))
	for _, e := range extras {
		if bad := checkName(e.User); bad != "" {
			return nil, fmt.Errorf("provision.MembershipPlan: user %q: %s", e.User, bad)
		}
		if bad := checkName(e.Group); bad != "" {
			return nil, fmt.Errorf("provision.MembershipPlan: group %q: %s", e.Group, bad)
		}
		if !strings.HasPrefix(e.Group, OwnedPrefix) {
			return nil, fmt.Errorf("provision.MembershipPlan: %q is not one of postern's groups; "+
				"postern only enforces membership inside its own namespace", e.Group)
		}
		steps = append(steps, Step{
			Kind:    StepUserUngroup,
			Command: delMemberCommand(caps, e.User, e.Group),
			Why: e.User + " is in " + e.Group + " but no postern group puts them there; " +
				"they are holding the sudo rule postern wrote for that group",
		})
	}

	return steps, nil
}

/*
 * delMemberCommand, iki aracın FARKLI komut satırını üretir.
 *
 * ⚠️ ARGÜMAN ŞEKLİ AYNI DEĞİL: gpasswd `-d <user> <group>` istiyor,
 * busybox'ın delgroup'u `<user> <group>`. Tek bir şablon yazmak,
 * Alpine'de "gpasswd: -d: hesap yok" ile sessizce başarısız olurdu.
 */
func delMemberCommand(caps upstream.ManageCapabilities, user, group string) string {
	if path.Base(caps.DelMember) == "gpasswd" {
		return "sudo -n " + caps.DelMember + " -d " + user + " " + group
	}

	return "sudo -n " + caps.DelMember + " " + user + " " + group
}
