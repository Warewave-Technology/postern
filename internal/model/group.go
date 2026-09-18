package model

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
type PathRule struct {
	// Prefix, mutlak yol öneki. Eşleşme DİZİN SINIRINDA yapılıyor.
	Prefix string

	// Allow false ise açık ret: izinli bir ağacın içinden dal kesmeye
	// yarıyor. En uzun eşleşen önek kazandığı için çalışıyor.
	Allow bool

	// CanWrite, iznin yazmayı da kapsayıp kapsamadığı.
	CanWrite bool
}
