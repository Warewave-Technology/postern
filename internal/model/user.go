// Package model holds postern's domain types.
//
// S2'de bu tipler config'den elle kuruluyordu; S3'ten beri veritabanından
// geliyorlar (şema bu alanların birebir karşılığı). Kararları veren kod
// model tiplerine baktığı için, kaynağın değişmesi policy'yi etkilemedi —
// motorun SQLite'tan PostgreSQL'e geçmesi de bu pakete dokunmadı.
package model

// User, bastion'da kimliği doğrulanmış kişi.
type User struct {
	// Name, postern kullanıcı adı ("yigit"). auth.go'nun doğruladığı ve
	// Permissions'a koyduğu değer.
	Name string

	// OSUser, kişinin hedeflerdeki VARSAYILAN hesabı. İstek boş geldiğinde
	// principal bu olur.
	//
	// S3 şemasında users.os_user (NOT NULL) — kişiye özel, paylaşılmaz.
	// Driver 1'in özü bu alan: herkes hedefe kendi adıyla düşüyor.
	OSUser string

	// Roles, kişinin sahip olduğu roller. Hedef erişimi rollerden gelir.
	Roles []Role

	// SSOOnly true ise bu kullanıcı YALNIZCA kimlik sağlayıcı üzerinden
	// girebilir; public key ile girişi reddedilir.
	//
	// IdP'den otomatik oluşan (JIT) kullanıcılar böyle doğar: erişimleri
	// IdP'de kapatılınca gerçekten bitsin ve rolleri her girişte
	// tazelensin diye. Elle oluşturulan servis hesapları false kalır.
	SSOOnly bool

	/*
	 * DirBound, hesabın bir DİZİN kimliğine bağlı olduğu.
	 *
	 * ⚠️ Oturum açılışında dizine yeniden sorulup sorulmayacağının
	 * DOĞRU koşulu bu — SSOOnly değil. Ölçüldü: yetkisi dizinden gelen
	 * bir yönetici (admin_via='group') sso_only=false ile duruyordu,
	 * yani dizinde kapatılsa bile anahtarıyla oturum açardı.
	 */
	DirBound bool

	// Admin, uygulama YÖNETİM yetkisi (kullanıcı/rol/hedef değiştirme,
	// web'deki yönetim sayfaları). Hedef erişimiyle ilgisi yok: admin
	// olmayan biri terminale girebilir, admin olan biri rolü yoksa hiçbir
	// hedefe giremez. İki eksen bilerek ayrık.
	Admin bool
}
