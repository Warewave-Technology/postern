package model

/*
 * Grup adları arasında ÜRÜNÜN kendi adı.
 *
 * ⚠️ NEDEN model'de: hem ayarları okuyan taraf (internal/auth) hem de
 * grupları role çeviren taraf (internal/store) buna bakıyor ve auth
 * zaten store'u kullanıyor — sabiti ikisinden birine koymak, diğerinin
 * onu kopyalaması ya da bir bağımlılık döngüsü demekti.
 */

/*
 * UnknownGroup, kaynağın CEVAP VERDİĞİ ama hiçbir grup söylemediği
 * kullanıcıların düştüğü grup.
 *
 * ⚠️ ÇÖZÜLDÜ AMA BOŞ ≠ ÇÖZÜLEMEDİ. Bu grup YALNIZCA kaynak "bu kişiyi
 * tanıyorum ve hiçbir grupta değil" dediğinde uygulanır. Dizin cevap
 * veremediğinde ya da kullanıcıyı hiç bulamadığında uygulanmaz — o iki
 * hâlde hiçbir şey bilinmiyor demektir ve bir arızayı yetkiye çevirmek,
 * default-deny'ın tam tersi olurdu.
 *
 * Var olma sebebi somut: grup claim'i göndermeyen bir IdP'de hiç kimse
 * hiçbir role eşleşmiyor, ProvisionUser hesabı AÇMIYOR ve kullanıcı
 * kapıda kalıyor — yöneticinin elinde onu düzeltecek bir tutamak bile
 * olmadan. Bu grup o tutamağı veriyor: yönetici `unknown`'ı bir role
 * eşler, kullanıcı içeri girer ve doğru grubuna elle atanır.
 */
const UnknownGroup = "unknown"

/*
 * ResolvedGroups, çözülmüş bir grup listesini role çevrilmeye hazırlar.
 *
 * ⚠️ YALNIZCA PRESENCE=PRESENT olan çağrı noktalarından çağrılmalı.
 * İmzası bunu zorlayamıyor (bir []string alıyor), o yüzden kural her
 * çağrı yerinde yazılı: "kaynak cevap verdi" bilgisi orada duruyor,
 * burada değil.
 */
func ResolvedGroups(groups []string) []string {
	if len(groups) > 0 {
		return groups
	}
	return []string{UnknownGroup}
}
