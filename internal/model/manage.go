package model

/*
 * Yönetim hesabının adları.
 *
 * ⚠️ BU İKİ AD, HEDEFTE PAROLASIZ ROOT SUDO TUTAN HESABIN ANAHTARI.
 * deploy/ansible/roles/postern_target, "postern" hesabını açıyor ve onu
 * yalnızca "postern-manage" principal'ı taşıyan bir sertifikayla
 * açılabilir kılıyor. Bu yüzden adlar tek bir yerde duruyor: store,
 * policy ve upstream aynı sabiti okumazsa, birinin reddettiği adı öbürü
 * sessizce kabul eder.
 *
 * ⚠️ YAPILANDIRILAMAZ. Ansible rolünde değişken olarak duruyorlar ama
 * rol, varsayılandan farklı bir değeri REDDEDİYOR. Operatörün adı
 * değiştirebildiği bir kurulumda ikili eski adı reddetmeye devam eder,
 * yeni adı ise sıradan bir hesap sanardı.
 */
const (
	// ManagementAccount, hedefteki yönetim hesabının OS adı.
	ManagementAccount = "postern"

	// ManagementPrincipal, o hesabı açan tek sertifika principal'ı.
	ManagementPrincipal = "postern-manage"
)

/*
 * IsManagementName, adın yönetim hesabına ait olup olmadığı.
 *
 * ⚠️ İKİSİ DE REDDEDİLİYOR, YALNIZCA HESAP ADI DEĞİL. Sıradan oturumlarda
 * sertifikanın principal'ı kullanıcının os_user'ı. os_user'ı
 * "postern-manage" olan bir panel kullanıcısı için postern tam da yönetim
 * principal'ını imzalardı; os_user'ı "postern" olan biri ise yönetim
 * hesabına giriş denerdi. Hedefin principal dosyası bugün ikisini de
 * durduruyor — ama elle kurulmuş, eski bir playbook'la ya da başka bir
 * araçla yapılandırılmış bir makinede o dosya daha gevşek olabilir ve
 * postern bunu göremez. Savunma hedefe bırakılmıyor.
 */
func IsManagementName(name string) bool {
	return name == ManagementAccount || name == ManagementPrincipal
}
