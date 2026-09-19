package model

import "strings"

// Group, bir hedef kümesine erişim yetkisi.
//
// S3 şemasında groups + group_targets tablolarının karşılığı.
type Group struct {
	Name string

	// Targets, bu grubun erişebildiği hedef adları.
	Targets []string

	/*
	 * Paths, bu grubun SFTP yol kuralları.
	 *
	 * ⚠️ BOŞ LİSTE "HİÇBİR ŞEY" DEĞİL, "KISIT YOK" DEMEK. Kuralı olmayan
	 * bir grup bugünkü gibi her yola erişiyor; kısıtlama kural
	 * EKLENDİĞİNDE başlıyor. Aksi hâli, yükseltmenin ertesi sabahı her
	 * kurulumun SFTP'sini kırmak olurdu.
	 */
	Paths []PathRule
}

// PathRule, bir yol öneği üzerindeki karar.
/*
 * HomeToken, yol kuralının "kişinin kendi evi" yazma biçimi.
 *
 * ⚠️ BURADA, PathRule'UN YANINDA: hem yazma yolu (store.SetGroupPath)
 * hem karar yolu (policy) aynı şeye bakmak zorunda. İki ayrı sabit,
 * birinin değişip öbürünün kalmasıyla "kabul edilen ama hiç eşleşmeyen"
 * bir kural üretirdi — yönetici koruma koyduğunu sanır, koymamış olurdu.
 */
const HomeToken = "~"

/*
 * IsHomeRule, önek ev token'ıyla mı başlıyor.
 *
 * "~" ve "~/..." evet; "~otheruser" HAYIR — başka birinin evini bu
 * token üzerinden adreslemek, kuralı yazanın beklemediği bir yere
 * erişim açardı ve kabuğun ~user sözdizimiyle karışırdı.
 */
func IsHomeRule(prefix string) bool {
	return prefix == HomeToken || strings.HasPrefix(prefix, HomeToken+"/")
}

type PathRule struct {
	// Prefix, mutlak yol öneki. Eşleşme DİZİN SINIRINDA yapılıyor.
	Prefix string

	// Allow false ise açık ret: izinli bir ağacın içinden dal kesmeye
	// yarıyor. En uzun eşleşen önek kazandığı için çalışıyor.
	Allow bool

	// CanWrite, iznin yazmayı da kapsayıp kapsamadığı.
	CanWrite bool
}
