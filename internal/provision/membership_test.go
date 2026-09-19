package provision

import (
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/v2/internal/upstream"
)

func observedWith(members map[string][]string) Observed {
	o := empty()
	o.GroupMembers = members

	return o
}

/*
 * ⚠️ ASIL BULGU: postern'in grubunda postern'in koymadığı hesap.
 *
 * O hesap, postern'in o gruba yazdığı sudo kuralını alıyor ve postern'in
 * hiçbir kaydında görünmüyor — yani postern'in verdiği yetki, postern'in
 * bilmediği birinde.
 */
func TestAMemberPosternDidNotPutThereIsFound(t *testing.T) {
	o := observedWith(map[string][]string{
		"postern-dba": {"ayse", "sızan"},
	})
	got := ExtraMembers(o, map[string][]string{"postern-dba": {"ayse"}})

	if len(got) != 1 || got[0].User != "sızan" || got[0].Group != "postern-dba" {
		t.Fatalf("bulunan: %+v", got)
	}
}

/*
 * ⚠️ ÖNEKSİZ GRUPLARA DOKUNULMUYOR. Makinede zaten bir `dba` grubu
 * olabilir ve içinde postern'in tanımadığı yirmi kişi durabilir;
 * üyeliğini zorlamak, o yirmi kişiyi kendi grubundan atmak olurdu.
 */
func TestGroupsOutsidePosternsNamespaceAreNeverTouched(t *testing.T) {
	o := observedWith(map[string][]string{
		"dba":    {"veli", "ahmet"},
		"docker": {"veli"},
	})
	if got := ExtraMembers(o, map[string][]string{"dba": {}, "docker": {}}); len(got) != 0 {
		t.Fatalf("postern'in olmayan gruba dokunuldu: %+v", got)
	}
}

/*
 * ⚠️ İŞARET GRUPLARI DIŞARIDA. postern-managed üyeliği "bu hesabı postern
 * açtı" demek ve silmenin ön koşulu; yanlışlıkla kaldırmak, postern'in
 * AÇTIĞI bir hesabı sonsuza dek silinemez yapardı.
 */
func TestTheMarkerGroupsAreNotEnforced(t *testing.T) {
	o := observedWith(map[string][]string{
		ManagedGroup: {"ayse", "veli"},
		JITGroup:     {"jit-ayse"},
	})
	got := ExtraMembers(o, map[string][]string{ManagedGroup: {"ayse"}, JITGroup: nil})
	if len(got) != 0 {
		t.Fatalf("işaret grubunda zorlama yapıldı: %+v", got)
	}
}

/*
 * ⚠️ "BEKLENEN KİMSE YOK" İLE "BU GRUBU BİLMİYORUM" AYRI ŞEYLER.
 *
 * Süpürmenin hiç görmediği bir grubu "beklenen boş" saymak, o grubun
 * BÜTÜN üyelerini attırırdı. Listede olan ama boş olan grup ise gerçekten
 * boşalmıştır: herkesin grubu düşmüştür ve oradaki herkes fazladır.
 */
func TestAnUnknownGroupIsSkippedButAnEmptyOneIsEnforced(t *testing.T) {
	o := observedWith(map[string][]string{
		"postern-dba": {"ayse"},
		"postern-ops": {"veli"},
	})

	// dba listede yok → hiç incelenmiyor.
	got := ExtraMembers(o, map[string][]string{"postern-ops": nil})
	if len(got) != 1 || got[0].Group != "postern-ops" || got[0].User != "veli" {
		t.Fatalf("bulunan: %+v", got)
	}
}

// Sıralı: iki koşunun defter satırları karşılaştırılabilmeli.
func TestExtrasComeBackInAStableOrder(t *testing.T) {
	o := observedWith(map[string][]string{
		"postern-ops": {"zeynep", "ahmet"},
		"postern-dba": {"veli"},
	})
	got := ExtraMembers(o, map[string][]string{"postern-ops": nil, "postern-dba": nil})
	if len(got) != 3 {
		t.Fatalf("bulunan: %+v", got)
	}
	if got[0].Group != "postern-dba" || got[1].User != "ahmet" || got[2].User != "zeynep" {
		t.Fatalf("sıra: %+v", got)
	}
}

/*
 * ⚠️ İKİ ARACIN KOMUT SATIRI AYNI DEĞİL: gpasswd `-d <user> <group>`,
 * busybox delgroup `<user> <group>`. Tek şablon yazmak Alpine'de sessizce
 * başarısız olurdu.
 */
func TestTheRemovalCommandMatchesTheToolOnTheHost(t *testing.T) {
	extras := []Extra{{Group: "postern-dba", User: "sizan"}}

	caps := able()
	caps.DelMember = "/usr/bin/gpasswd"
	steps, err := MembershipPlan(caps, extras)
	if err != nil {
		t.Fatal(err)
	}
	if got := steps[0].Command; got != "sudo -n /usr/bin/gpasswd -d sizan postern-dba" {
		t.Errorf("gpasswd komutu: %q", got)
	}

	caps.DelMember = "/bin/delgroup"
	steps, err = MembershipPlan(caps, extras)
	if err != nil {
		t.Fatal(err)
	}
	if got := steps[0].Command; got != "sudo -n /bin/delgroup sizan postern-dba" {
		t.Errorf("delgroup komutu: %q", got)
	}
}

/*
 * ⚠️ ÇAĞIRANA GÜVENİLMİYOR. Bu kod hesap çıkarma komutu üretiyor; yanlış
 * bir grup adıyla çağrılması, makinedeki gerçek bir ekibi kendi grubundan
 * atmak demek.
 */
func TestThePlanRefusesAGroupOutsideThePrefix(t *testing.T) {
	caps := able()
	caps.DelMember = "/usr/bin/gpasswd"
	_, err := MembershipPlan(caps, []Extra{{Group: "wheel", User: "veli"}})
	if err == nil {
		t.Fatal("öneksiz grup kabul edildi")
	}
	if !strings.Contains(err.Error(), "wheel") {
		t.Errorf("cümle grubu söylemiyor: %v", err)
	}
}

// Aracı olmayan hedefte zorlama yapılamıyor ve bu açıkça söyleniyor.
func TestAHostWithNeitherToolIsRefusedWithAReason(t *testing.T) {
	_, err := MembershipPlan(upstream.ManageCapabilities{}, []Extra{{Group: "postern-dba", User: "x"}})
	if err == nil {
		t.Fatal("araçsız hedefte plan üretildi")
	}
	for _, want := range []string{"gpasswd", "delgroup"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("cümle %q demiyor: %v", want, err)
		}
	}
}
