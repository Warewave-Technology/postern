// Package hostacct, bir kişinin bir hedefte ne olması gerektiğine karar
// verir ve o kararı uygular.
//
// ⚠️ KARAR SAF, UYGULAMA AYRI. Bu dosyada I/O yok, saat yok, SSH yok:
// "kim hangi gruptan bu makineye erişiyor ve bu ne demek" sorusu bir
// tablo testiyle milisaniyede kanıtlanabilsin diye. Aynı ayrım
// groupsync'te de var ve orada, iptal kararının doğruluğunu tartışmak
// yerine ölçmeyi mümkün kıldı.
package hostacct

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/provision"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/sudoers"
)

/*
 * HostGroupPrefix, postern'in hedefte açtığı grupların öneki.
 *
 * ⚠️ ÖNEK SAHİPLİK KANITI. Makinede zaten bir `dba` grubu olabilir ve
 * içinde postern'in tanımadığı yirmi kişi durabilir; kuralı o gruba
 * yazmak, verilen yetkiyi onlara da vermek olurdu. Önekli ad uzayı
 * postern'in kendi ilanı: oraya yazdığı kural yalnızca oraya koyduğu
 * kişilere işliyor.
 *
 * ⚠️ TEK KAYNAK: provision.OwnedPrefix. Süpürmenin üyelik zorlaması aynı
 * öneke bakıyor ve iki ayrı sabit, birinin değişip öbürünün kalmasıyla
 * "zorlama hiç koşmayan bir ad uzayı" üretirdi.
 */
const HostGroupPrefix = provision.OwnedPrefix

// GroupRule, hedefte açılacak bir grup ve taşıdığı sudo kuralı.
type GroupRule struct {
	// Name, hedefteki grup adı — önekli.
	Name string
	Sudo sudoers.Rule
}

/*
 * Account, postern'in kişinin hesabı hakkında ZATEN VERDİĞİ kararlar —
 * gruplardan türemeyen, kayıttan gelen iki şey.
 *
 * Ayrı bir tip: Compute'un imzası iki sondaki skalerle (bool, int)
 * karışmaya açıktı ve ikisi de sessizce yanlış sonuç üretirdi.
 */
type Account struct {
	// Managed, hesabı postern'in açtığı — marker grubunun koşulu.
	Managed bool
	/*
	 * UID, kişinin filo boyunca taşıdığı numara; 0 ise hedef kendi
	 * seçiyor (numara ne dizinden ne havuzdan gelebildiyse).
	 */
	UID int
}

// Want, bir kişinin bir hedefte olması gereken hâli.
type Want struct {
	OSUser string
	Groups []GroupRule
	// UID, hesaba verilmek istenen numara; 0 ise hedef kendi seçiyor.
	UID int

	/*
	 * Fingerprint, bu istenen durumun özeti.
	 *
	 * ⚠️ HEDEFE YAZILACAK METİNDEN TÜRÜYOR, kural yapısından değil.
	 * Sebebi somut: iki farklı Rule aynı sudoers dosyasını üretiyorsa
	 * hedefte değişen bir şey yok ve bağlanmaya gerek yok; tersine,
	 * yapı aynı görünüp render farklıysa hedefte gerçekten bir şey
	 * değişmiştir. Ölçü, makinede duracak olan şey olmalı.
	 */
	Fingerprint string
}

/*
 * Compute, kişinin bu hedefte olması gereken hâlini üretir.
 *
 * ⚠️ YALNIZCA BU HEDEFİ VEREN GRUPLAR. Kişinin bütün gruplarını her
 * makineye yazmak, postern'i tam da yerine geçtiği şeye — N kullanıcıyı
 * M makineye basan bir dağıtıcıya — çevirirdi.
 */
func Compute(u model.User, t model.Target, rules map[string]store.GroupSudo, acct Account) Want {
	w := Want{OSUser: u.OSUser, Groups: []GroupRule{}, UID: acct.UID}

	/*
	 * ⚠️ MARKER GRUBU YALNIZCA POSTERN'İN AÇTIĞI HESAPTA.
	 *
	 * postern-managed, "bu hesabı ben açtım"ın makine üstündeki hâli ve
	 * silmenin ön koşulu. Devralınan bir hesaba koymak, postern'den önce
	 * var olan bir hesabı silinebilir yapardı — ayrımın tamamı bu.
	 */
	if acct.Managed {
		w.Groups = append(w.Groups, GroupRule{Name: provision.ManagedGroup})
	}

	names := make([]string, 0, len(u.Groups))
	for _, g := range u.Groups {
		if reaches(g, t.Name) {
			names = append(names, g.Name)
		}
	}
	// ⚠️ SIRALI: gruplar veritabanından farklı sırayla gelebiliyor ve
	// sırasız bir iz, hiçbir şey değişmediği hâlde her bağlantıda hedefe
	// bağlanmaya yol açar — yani hızlı şeridi yok eder.
	sort.Strings(names)

	var sb strings.Builder
	sb.WriteString("os_user=")
	sb.WriteString(u.OSUser)
	sb.WriteString("\n")
	/*
	 * Marker da izin içinde: hesabın postern tarafından mı açıldığı,
	 * hedefte duran durumun parçası. İzin dışında kalsaydı, marker'ı
	 * eksik bir hesap hiç düzelmezdi.
	 */
	if acct.Managed {
		sb.WriteString("managed\n")
	}
	/*
	 * ⚠️ NUMARA DA İZİN İÇİNDE. Dizin bir kişiye numara vermeye yeni
	 * başladığında (ya da havuz aralığı değiştiğinde) istenen durum
	 * gerçekten değişiyor; iz bunu görmezse hızlı şerit hedefe hiç
	 * uğramaz ve numara sonsuza dek eski hâlinde kalır.
	 */
	if acct.UID > 0 {
		sb.WriteString("uid=")
		sb.WriteString(strconv.Itoa(acct.UID))
		sb.WriteString("\n")
	}

	for _, n := range names {
		gr := GroupRule{Name: HostGroupPrefix + n}
		if r, ok := rules[n]; ok {
			gr.Sudo = r.Rule
		}
		w.Groups = append(w.Groups, gr)

		sb.WriteString("group=")
		sb.WriteString(gr.Name)
		sb.WriteString("\n")
		/*
		 * Render hata verirse (kaçış riski onaylanmamış, bozuk ad) izin
		 * içine HATANIN KENDİSİ giriyor. Sessizce atlamak, reddedilen bir
		 * kuralın izini kuralsız hâlle aynı yapar ve kural düzeltilip
		 * geçerli hâle geldiğinde hedefe hiç inmez.
		 */
		text, err := sudoers.Render(gr.Name, gr.Sudo, "")
		if err != nil {
			sb.WriteString("sudo-error=")
			sb.WriteString(err.Error())
		} else {
			sb.WriteString(text)
		}
		sb.WriteString("\n")
	}

	sum := sha256.Sum256([]byte(sb.String()))
	w.Fingerprint = hex.EncodeToString(sum[:])

	return w
}

func reaches(g model.Group, target string) bool {
	for _, t := range g.Targets {
		if strings.EqualFold(t, target) {
			return true
		}
	}

	return false
}
