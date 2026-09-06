package policy

// SFTP yol politikası: rollerden bir karar vericiye.

import (
	"strings"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/sftpaudit"
)

/*
 * SFTPDecider, kullanıcının rollerinden bir yol politikası üretir.
 *
 * ⚠️ HİÇBİR ROLDE KURAL YOKSA nil DÖNÜYOR — ve bu, "her şeyi reddet"in
 * tersi. nil politika kurulmadığı anlamına geliyor, yani veri yolu bu
 * özellik eklenmeden önceki gibi çalışıyor: fazladan karar, fazladan
 * tutma, fazladan gecikme yok. Kısıtlama kural yazıldığında başlıyor.
 *
 * ⚠️ BİRLEŞİM. Rollerden HERHANGİ BİRİ izin veriyorsa erişim var. Kesişim
 * seçseydik kısıtlı bir rol eklemek, kullanıcının mevcut erişimini
 * SESSİZCE daraltırdı. Birleşimde rol eklemek yalnızca genişletiyor.
 *
 * Sonucu: kuralsız BİR rol, kurallı diğerlerini etkisiz kılıyor. Sezgiye
 * aykırı görünüyor ama tutarlı — kural yazmak bir ROLÜ kısıtlamak demek,
 * kullanıcıyı değil. Belge bunu böyle anlatıyor.
 */
func SFTPDecider(roles []model.Role) sftpaudit.Decider {
	var active []model.Role
	for _, r := range roles {
		if len(r.Paths) > 0 {
			active = append(active, r)
		}
	}
	if len(active) == 0 {
		return nil
	}

	// Kuralsız bir rol her şeye izin veriyor: politika kurmanın anlamı
	// kalmıyor ve veri yolunu boş yere yavaşlatmıyoruz.
	if len(active) != len(roles) {
		return nil
	}

	/*
	 * ⚠️ KURALLAR TEK KÜMEDE TOPLANIYOR, ROL ROL DEĞERLENDİRİLMİYOR.
	 *
	 * ÖLÇÜLEN ARIZA: rol rol değerlendirip "herhangi biri izin veriyorsa
	 * evet" dediğimizde AÇIK RETLER HAYATTA KALMIYORDU. Demoda görüldü:
	 * bir rolde /home/u/.ssh reddedilmişti, başka bir rol /home/u'ya izin
	 * veriyordu ve .ssh açık kaldı. Yönetici bir dalı kestiğini sanıyor,
	 * kesmemiş oluyor — sessizce fazla erişim, kural yazmanın en kötü
	 * sonucu.
	 */
	var all []model.PathRule
	for _, r := range active {
		all = append(all, r.Paths...)
	}

	return func(req sftpaudit.Request) (bool, string) {
		for _, p := range paths(req) {
			ok, reason := allows(all, p, req.Write)
			if !ok {
				return false, reason
			}
		}

		return true, ""
	}
}

/*
 * paths, isteğin politikaya sunulan yollarının hepsi.
 *
 * ⚠️ İKİ YOLLU İSTEKLERDE İKİSİ DE KONTROL EDİLİYOR. rename, symlink ve
 * link'te tek bir yola bakmak, izinli bir dizinden yasak bir yere bağ
 * kurmayı ya da yasak bir yerden izinliye taşımayı serbest bırakırdı —
 * yol politikasını tümüyle boşa çıkaran şey tam olarak budur.
 */
func paths(req sftpaudit.Request) []string {
	if req.NewPath == "" {
		return []string{req.Path}
	}

	return []string{req.Path, req.NewPath}
}

/*
 * allows, tek bir yol için kararı verir.
 *
 * ⚠️ EN UZUN EŞLEŞEN ÖNEK KAZANIYOR, EŞİTLİKTE RET KAZANIYOR. İkisi de
 * gerekli: uzunluk kuralı, izinli bir ağacın içinden dal kesmeyi mümkün
 * kılıyor; retin eşitlikte kazanması ise o kesiğin BAŞKA BİR ROLÜN aynı
 * uzunluktaki izniyle geri açılmasını engelliyor. Açık ret bir vetodur.
 */
func allows(rules []model.PathRule, path string, write bool) (bool, string) {
	best := -1
	for _, r := range rules {
		if prefixMatches(r.Prefix, path) && len(r.Prefix) > best {
			best = len(r.Prefix)
		}
	}
	if best < 0 {
		return false, "no rule covers this path"
	}

	canWrite := false
	for _, r := range rules {
		if len(r.Prefix) != best || !prefixMatches(r.Prefix, path) {
			continue
		}
		if !r.Allow {
			return false, "this path is explicitly denied"
		}
		if r.CanWrite {
			canWrite = true
		}
	}

	if write && !canWrite {
		return false, "this path is read-only"
	}

	return true, ""
}

/*
 * prefixMatches, önek eşleşmesini DİZİN SINIRINDA yapar.
 *
 * ⚠️ DÜZ DİZGİ ÖNEKİ YANLIŞ OLURDU: "/home/user" kuralı "/home/username"i
 * de kapsardı ve kuralı yazan kişi bunu fark etmezdi. Sessizce fazla
 * erişim veren bir kural, hiç kural olmamasından kötü.
 */
func prefixMatches(prefix, path string) bool {
	if prefix == "/" {
		return true
	}
	prefix = strings.TrimSuffix(prefix, "/")

	if path == prefix {
		return true
	}

	return strings.HasPrefix(path, prefix+"/")
}
