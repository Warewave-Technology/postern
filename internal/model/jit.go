package model

import "time"

/*
 * TemporaryAccess, bir kişinin bir hedefte SÜRELİ hesabı — politikanın
 * gördüğü hâli (jit_grants satırının yetkiye dair kısmı).
 *
 * ⚠️ ROL DEĞİL, AYRI BİR YETKİ KAYNAĞI. Rol, rolü taşıyan herkese kalıcı
 * erişim; bu ise tek kişiye, tek hedefte, bir vadeye kadar. İkisini aynı
 * yapıya sıkıştırmak — geçici hakkı bir role çevirmek — süresi dolunca
 * silinmesi gereken şeyi rol tablosuna sızdırırdı.
 */
type TemporaryAccess struct {
	Target string
	// OSUser, hedefte açılan hesabın adı. Kişinin o günkü os_user'ı;
	// sertifikanın principal'ı da bu olmak zorunda.
	OSUser    string
	ExpiresAt time.Time
	/*
	 * Applied, hesabın hedefte GERÇEKTEN açılmış olduğu. Yarım kalan bir
	 * hak da kayıtta duruyor (süpürücü toplayacak); ona yetki vermek,
	 * var olmayan bir hesaba oturum açtırmaya çalışmak olurdu.
	 */
	Applied bool
}

// Live, hakkın şu an yetki verip vermediği.
func (a TemporaryAccess) Live(now time.Time) bool {
	return a.Applied && now.Before(a.ExpiresAt)
}
