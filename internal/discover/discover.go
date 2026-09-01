// Package discover, sanallaştırma platformundan makine keşfi.
//
// ⚠️ KAYNAK ARAYÜZ ARKASINDA ve bu ilk günden böyle. Bugün tek
// uygulaması Proxmox; vSphere aynı arayüzü dolduracak. Arayüzü sonradan
// çıkarmak, Proxmox'a özel varsayımların keşif mantığının içine
// dağılmasından SONRA olurdu — ve o noktada ikinci kaynağı eklemek,
// birinciyi yeniden yazmak demek olurdu.
//
// ⚠️ KEŞİF ERİŞİM VERMEZ, HEDEF VE ROL YARATIR. Bir makinenin
// postern'de hedef olması, kimsenin oraya girebildiği anlamına gelmiyor:
// erişim yalnızca rolden geliyor ve rolü insanlara bağlamak ayrı,
// bilinçli bir adım. Keşif o adımı yapmıyor.
package discover

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Machine, bir kaynağın bildirdiği tek bir makine.
type Machine struct {
	// Name, platformdaki adı. Hedef adı olarak kullanılıyor.
	Name string

	/*
	 * Host, SSH için kullanılacak adres.
	 *
	 * Boş olabilir: Proxmox'ta adresi öğrenmek konuk aracısına
	 * (guest agent) bağlı ve o her makinede kurulu değil. Boşken
	 * makinenin ADI adres olarak deneniyor — kurumların çoğunda
	 * makine adı zaten çözülüyor. Çözülmezse makine ATLANIYOR ve
	 * sebebi raporda yazıyor; uydurma bir adres yazmak, bir gün
	 * başka bir makineye açılan bir hedef bırakırdı.
	 */
	Host string

	// Tags, platformdaki etiketler. Rol bunlardan çıkarılıyor.
	Tags []string

	// Running, makine çalışıyor mu. Kapalı makinenin host anahtarı
	// taranamaz; rapor bunu ayrı bir sebep olarak söylüyor.
	Running bool

	// Ref, platformdaki kimliği (teşhis için: "qemu/101").
	Ref string
}

// Source, makineleri sayabilen bir platform.
type Source interface {
	// Name, raporda ve denetim kaydında görünen ad ("proxmox").
	Name() string
	// Machines, platformdaki makineleri döner.
	Machines(ctx context.Context) ([]Machine, error)
}

/*
 * RoleFromTags, etiketlerden rol adını çıkarır.
 *
 * ⚠️ ANAHTAR ETİKETİN İÇİNDE, ayrı bir alan değil. Proxmox etiketleri
 * anahtar/değer çifti DEĞİL, düz dizeler ("prod", "role=ops"). Bu
 * yüzden operatörden bir "etiket anahtarı" istiyoruz ve onu etiketin
 * içinde arıyoruz: `role=ops` ya da `role:ops`.
 *
 * İki ayraç da kabul ediliyor çünkü ikisi de yaygın ve hangisinin
 * kullanıldığını keşif sırasında öğrenmek, kurulumu yeniden
 * etiketlemekten ucuz.
 *
 * ⚠️ ANAHTARSIZ MAKİNE HATA DEĞİL. Etiketi olmayan ya da anahtarı
 * taşımayan makine `unknown` rolüne düşüyor — kaynağın hiçbir grup
 * söylemediği kullanıcının düştüğü yerin aynısı (model.UnknownGroup).
 * Sebebi aynı: "bilmiyorum" ile "hiçbiri" ayrı şeyler ve bilmediğimiz
 * makineyi sessizce dışarıda bırakmak, onu envanterden düşürürdü.
 */
/*
 * ⚠️ EŞLEŞME ÖN EKLE, "İLK AYIRICIDA BÖL" DEĞİL.
 *
 * Alt çizgi hem anahtarın hem değerin İÇİNDE geçebiliyor:
 * "role_name_os-admins" etiketi, anahtar "role_name" iken değer
 * "os-admins" demek. İlk ayırıcıda bölen bir uygulama burada anahtarı
 * "role" sanır, eşleşmez, ve makine sessizce unknown'a düşer — yani
 * alt çizgiyi desteklemek TEK BAŞINA yetmiyor.
 *
 * Anahtar bilindiği için doğru olan onu ön ek olarak aramak; geriye
 * kalan her şey değerdir ("role_web_prod" + anahtar "role" =
 * "web_prod").
 */
func RoleFromTags(tags []string, key string) (role string, tagged bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		return UnknownRole, false
	}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if len(t) <= len(key) || !strings.EqualFold(t[:len(key)], key) {
			continue
		}
		// Anahtardan sonra: (boşluk) ayırıcı (boşluk) değer.
		rest := strings.TrimLeft(t[len(key):], " \t")
		if rest == "" || !isTagSeparator(rest[0]) {
			// Ayırıcı yoksa bu etiket bizim anahtarımız DEĞİL, yalnızca
			// onunla başlıyor: "role" anahtarı "roles_web" etiketini
			// yakalamamalı, yoksa makine yanlış role girer.
			continue
		}
		v := strings.TrimSpace(rest[1:])
		if v == "" {
			continue
		}
		return v, true
	}
	return UnknownRole, false
}

/*
 * isTagSeparator, "anahtar<ayırıcı>değer" etiketlerinde kabul edilen
 * ayırıcılar.
 *
 * ⚠️ ALT ÇİZGİ ŞART — ve eksikliği bu özelliği PROXMOX'TA TAMAMEN
 * ÇALIŞMAZ KILIYORDU.
 *
 * ÖLÇÜLDÜ: Proxmox etiketleri düz dizgi ve karakter kümesi dar —
 * [a-z0-9_.+-] (pve-common'daki `pve-tag` biçimi). Yani `=` de `:` de
 * bir Proxmox etiketine HİÇ yazılamıyor. Yalnızca o ikisini tanıyan
 * eski kod, gerçek bir Proxmox kurulumunda her makineyi sessizce
 * `unknown` rolüne düşürüyordu: hata yok, uyarı yok, sadece hiçbir
 * makinenin rolü yok.
 *
 * `=` ve `:` duruyor çünkü vSphere onları yazabiliyor ve keşif orada
 * "kategori=etiket" üretiyor (vsphere.go).
 */
func isTagSeparator(c byte) bool {
	return c == '=' || c == ':' || c == '_'
}

/*
 * UnknownRole, rol etiketi olmayan makinelerin düştüğü rol.
 *
 * ⚠️ model.UnknownGroup ile AYNI KELİME ve bu kasıtlı: operatör aynı
 * anlamı iki farklı adla öğrenmek zorunda kalmasın. Orada "kaynak
 * cevap verdi ama grup söylemedi", burada "makine var ama rolü
 * söylenmemiş" — ikisi de "bilmiyoruz, ama sakladık" demek.
 */
const UnknownRole = "unknown"

/*
 * ValidRoleName, etiketten gelen değerin rol adı olarak kullanılabilir
 * olduğu.
 *
 * ⚠️ ETİKET GÜVENİLMEYEN GİRDİ. Hipervizöre makine ekleyebilen herkes
 * etiket yazabiliyor ve o değer burada bir ROL ADINA dönüşüyor —
 * yani erişim modelinin bir parçasına. Boşluk, virgül ya da yol
 * ayracı taşıyan bir ad, sonradan liste ayrıştıran her yerde
 * belirsizlik üretir.
 */
func ValidRoleName(name string) error {
	if name == "" {
		return fmt.Errorf("role name is empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("role name is longer than 64 characters")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("role name contains %q; letters, digits, - _ . only", r)
		}
	}
	return nil
}

// Outcome, tek bir makine için keşfin sonucu.
type Outcome struct {
	Machine Machine
	Role    string
	// Tagged: rol etiketten mi geldi (yoksa unknown'a mı düştü).
	Tagged bool

	// Skipped doluysa makine için hiçbir şey yazılmadı ve sebebi bu.
	Skipped string

	// Aşağıdakiler yalnızca uygulama (apply) turunda dolar.
	CreatedRole   bool
	CreatedTarget bool
	Granted       bool
	// Existing: hedef zaten vardı ve DOKUNULMADI.
	Existing bool
}

// SortOutcomes, raporu okunur bir sıraya koyar: önce atlananlar (asıl
// bakılacak olan onlar), sonra rol, sonra ad.
func SortOutcomes(out []Outcome) {
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Skipped != "") != (b.Skipped != "") {
			return a.Skipped != ""
		}
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		return a.Machine.Name < b.Machine.Name
	})
}
