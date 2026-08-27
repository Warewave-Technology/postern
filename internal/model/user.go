// Package model holds postern's domain types.
//
// S2'de bu tipler config'den elle kuruluyor; S3'te SQLite'tan gelecekler
// (plan S3.1'deki şema bu alanların birebir karşılığı). Kararları veren
// kod model tiplerine baktığı için, kaynağın değişmesi policy'yi
// etkilemeyecek.
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

	// Admin, uygulama YÖNETİM yetkisi (kullanıcı/rol/hedef değiştirme,
	// web'deki yönetim sayfaları). Hedef erişimiyle ilgisi yok: admin
	// olmayan biri terminale girebilir, admin olan biri rolü yoksa hiçbir
	// hedefe giremez. İki eksen bilerek ayrık.
	Admin bool
}
