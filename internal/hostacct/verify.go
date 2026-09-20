package hostacct

/*
 * Dördüncü ölçüm: KİŞİNİN KENDİ BAĞLANTISINDA doğrulama.
 *
 * ⚠️ HIZLI ŞERİDİN KÖR NOKTASI — ÖLÇÜLDÜ (2026-09-20). Sıcak yol, satır
 * "uyguladım" diyor ve parmak izi tutuyorsa hedefe HİÇ bağlanmıyor;
 * özelliğin yaşamasının şartı bu (bkz. apply.go). Ama makine postern'in
 * ayağının altından yeniden kurulduğunda satır hâlâ "uyguladım" der:
 * demo hedefi 07:30:55'te sıfırdan doğdu, ayşe 17:08:18'de bağlandı ve
 * hedefte tek bir yönetim bağlantısı açılmadı (hedefin auth log'unda
 * "postern-manage" sayısı 9'dan 9'a). Grubu ve sudo kuralı, bir sonraki
 * süpürmeye kadar — en kötü bir saat — yoktu.
 *
 * ⚠️ FAZLADAN BAĞLANTI AÇMIYOR. Soru, kişinin ZATEN açık olan kendi
 * bağlantısında soruluyor: `id -Gn`. Yönetim bağlantısı açmak, tam da
 * hızlı şeridin var olma sebebini geri alırdı.
 *
 * ⚠️ HEDEFİN CEVABI YALNIZCA DAHA FAZLA İŞ ÇIKARABİLİR, ASLA İŞ
 * ATLATAMAZ. "Hepsi bende" diyen bir hedef postern'in yapacağı hiçbir
 * şeyi değiştirmiyor; yalnızca "eksik" cevabı iş üretiyor ve o iş de
 * postern'in zaten istediği durumu yazmak. Düşmanca bir hedefin elde
 * edebileceği tek şey, kendisine zaten uygulanacak olanın yeniden
 * uygulanması — hedefin yazdığı veriyi savunma olarak kullanmamanın bu
 * depodaki hâli.
 *
 * ⚠️ HER KOŞU DEFTERE YAZILIYOR. Komut hedefin günlüklerinde BAĞLANAN
 * KİŞİNİN adına görünüyor: kullanıcının yazmadığı bir komut, onun
 * hesabında. Yoklamada (proxy.maybeProbe) aynı sebeple aynı kural var ve
 * orada izsiz koşan hâli bir kez ölçülüp kapatıldı.
 */

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/store"
)

/*
 * Peek, kişinin kendi bağlantısında TEK bir komut koşturmak için gereken
 * en küçük yüzey. *upstream.Conn bunu karşılıyor.
 *
 * ⚠️ Close YOK — ve olmaması kasıtlı. Bağlantı kişinin oturumu; bu kod
 * onu kapatamamalı.
 */
type Peek interface {
	Exec(ctx context.Context, command, stdin string) (string, error)
}

/*
 * groupsCommand, doğrulamanın tek komutu.
 *
 * ⚠️ ARGÜMANSIZ — VE BU BİR GÜVENLİK KARARI. `id -Gn <ad>` yazsaydık bir
 * hesap adı hedefin kabuğuna girerdi; argümansız hâli BAĞLANAN hesabın
 * gruplarını veriyor, ki postern hedefe zaten kişinin OSUser'ı olarak
 * bağlanıyor. Yani doğru cevabı veren biçim, aynı zamanda enterpolasyon
 * yüzeyi olmayan biçim.
 */
const groupsCommand = "id -Gn"

// VerifyDeps, doğrulamanın dışarıya bağlandığı yerler.
type VerifyDeps struct {
	// Rules, grupların sudo kuralları; yalnızca istenen hâli kurmak için.
	Rules func(ctx context.Context) (map[string]store.GroupSudo, error)
	// Row, (hedef, kişi) satırı; yoksa store.ErrNotFound.
	Row func(ctx context.Context, target, username string) (store.HostAccount, error)
	// Save, satırı yazar.
	Save func(ctx context.Context, a store.HostAccount) error
	// Audit, koşuyu deftere yazar — actor, bağlantısı kullanılan kişi.
	Audit func(ctx context.Context, target, actor, detail string) error
	/*
	 * Repair, sürüklenme bulunduğunda sıcak yolu bir kez koşturuyor
	 * (hostacct.Hook'un ürettiği fonksiyon). nil ise onarım bir sonraki
	 * bağlantıya kalıyor — parmak izi düşürüldüğü için o bağlantı artık
	 * hızlı şeride girmiyor.
	 */
	Repair func(ctx context.Context, u model.User, t model.Target) error

	Logger *slog.Logger
	Now    func() time.Time
}

func (d VerifyDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}

	return time.Now()
}

/*
 * Verify, postern'in kaydının hedefte karşılığı olup olmadığını kişinin
 * kendi bağlantısında ölçer; tutmuyorsa kaydı düzeltip onarımı başlatır.
 *
 * Hata döndürmüyor: bu yol oturumun yanında koşuyor ve hiçbir sonucu
 * oturumu etkilememeli.
 */
func Verify(ctx context.Context, d VerifyDeps, p Peek, u model.User, t model.Target) {
	if p == nil || d.Row == nil {
		return
	}

	/*
	 * ⚠️ SATIR YOKSA SORU DA YOK. Kaydı olmayan bir (kişi, hedef) çifti,
	 * postern'in o makinede o hesabın kaynağı OLMADIĞI anlamına geliyor:
	 * hesabı başka bir araç açmışsa gruplarını postern'e sormak, kendi
	 * yazmadığı bir durumu "sürüklenmiş" ilan etmek olurdu. Okuma hatası
	 * da aynı kapıya çıkıyor — okunamayan bir satır, yanlış satır değil.
	 */
	row, rerr := d.Row(ctx, t.Name, u.Name)
	if rerr != nil || row.State != store.HostAccountActive {
		return
	}

	/*
	 * Kurallar okunamazsa kuralsız devam: karşılaştırma yalnızca GRUP
	 * ADLARINA bakıyor ve adlar kişinin gruplarından geliyor, sudo
	 * metninden değil. Numara da sorulmuyor — parmak izi burada hiç
	 * kullanılmıyor, yalnızca silinen bir değer olarak geçiyor.
	 */
	rules, _ := d.rules(ctx)
	want := Compute(u, t, rules, Account{Managed: row.Origin == store.OriginCreated})
	names := groupNames(want.Groups)
	if len(names) == 0 {
		// postern bu hedefte ona hiçbir grup yazmamış: ölçülecek bir iddia yok.
		return
	}

	out, xerr := p.Exec(ctx, groupsCommand, "")
	ran := "ran on this user's connection: " + groupsCommand
	if xerr != nil {
		d.audit(ctx, t.Name, u.Name, ran+"; target answered nothing: "+xerr.Error())
		return
	}
	have := strings.Fields(strings.TrimSpace(out))
	if len(have) == 0 {
		/*
		 * ⚠️ BOŞ CEVAP "GRUBU YOK" DEĞİL. Her hesap en az birincil
		 * grubunda; boş çıktı, komutun cevap vermediği anlamına geliyor.
		 * Sürüklenme saymak, sessiz bir kanalı bütün filoda root komutu
		 * çalıştıran bir tetiğe çevirirdi.
		 */
		d.audit(ctx, t.Name, u.Name, ran+"; the target answered nothing readable")
		return
	}

	missing := missingFrom(names, have)
	if len(missing) == 0 {
		/*
		 * Satır "postern öyle diyor" değil, "makine o an öyle dedi":
		 * kaydın doğruluğu artık ölçülmüş bir şey.
		 */
		d.audit(ctx, t.Name, u.Name, fmt.Sprintf(
			"%s; the machine has every group postern applied (%s)",
			ran, strings.Join(names, ", ")))

		return
	}

	d.audit(ctx, t.Name, u.Name, fmt.Sprintf(
		"%s; the machine does not have %s, which postern's record says it applied; "+
			"the record was cleared and the account is being prepared again",
		ran, strings.Join(missing, ", ")))

	/*
	 * ⚠️ ÖNCE KAYIT DÜZELİYOR, SONRA ONARIM. Ters sıra kaydı yalanlardı:
	 * onarım parmak izini zaten doğru değere yazıyor ve ARDINDAN
	 * silseydik, gerçekten uygulanmış bir durumu "uygulanmadı" diye
	 * işaretlemiş olurduk. Kayıt yazılamıyorsa onarım da çağrılmıyor:
	 * sıcak yol parmak izine bakıyor ve eski değerle yine hızlı şeride
	 * girer, yani koşu boşuna bir yönetim bağlantısı olurdu.
	 */
	row.AppliedFP = ""
	row.UpdatedAt = d.now()
	if serr := d.Save(ctx, row); serr != nil {
		d.log("the record could not be cleared after the machine disagreed",
			"target", t.Name, "user", u.Name, "error", serr)

		return
	}
	if d.Repair == nil {
		return
	}
	if perr := d.Repair(ctx, u, t); perr != nil {
		d.log("the account could not be prepared again after the machine disagreed",
			"target", t.Name, "user", u.Name, "error", perr)
	}
}

func (d VerifyDeps) rules(ctx context.Context) (map[string]store.GroupSudo, error) {
	if d.Rules == nil {
		return nil, nil
	}

	return d.Rules(ctx)
}

func (d VerifyDeps) audit(ctx context.Context, target, actor, detail string) {
	if d.Audit == nil {
		return
	}
	if err := d.Audit(ctx, target, actor, detail); err != nil {
		d.log("the verification was not audited", "target", target, "error", err)
	}
}

func (d VerifyDeps) log(msg string, args ...any) {
	if d.Logger != nil {
		d.Logger.Warn(msg, args...)
	}
}

// missingFrom, want'ta olup have'de olmayan adlar — sırası want'ın sırası.
func missingFrom(want, have []string) []string {
	in := make(map[string]bool, len(have))
	for _, g := range have {
		in[g] = true
	}

	var out []string
	for _, g := range want {
		if !in[g] {
			out = append(out, g)
		}
	}

	return out
}
