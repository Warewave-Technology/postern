package hostacct

/*
 * İstenen durumun hedefe uygulanması — bağlanma anında.
 *
 * ⚠️ BU KOD SICAK YOLDA. Her oturum buradan geçiyor, dolayısıyla asıl
 * iş "ne yapılacağı" değil, ÇOĞU ZAMAN HİÇBİR ŞEY YAPMAMAK: parmak izi
 * tutuyorsa hedefe bağlanılmıyor bile. Her bağlantıya ikinci bir SSH
 * eklemek, özelliği kullanılamaz yapardı.
 *
 * ⚠️ HİÇBİR HATA OTURUMU KESMİYOR (K6). postern bugünkünden daha sıkı
 * bir kapı olmamalı: yönetim hesabı kurulmamış bir makineye, hesabı
 * zaten olan kişi bugün girebiliyor. Hazırlamayı ön koşul yapmak
 * postern'i tek hata noktasına çevirirdi — sebep Outcome'da taşınıyor ve
 * çağıran onu dial hatasına ekliyor.
 */

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/provision"
	"github.com/Warewave-Technology/postern/v2/internal/store"
	"github.com/Warewave-Technology/postern/v2/internal/upstream"
)

// Runner, hedefte komut çalıştıran bağlantı (provision.Runner'ın aynısı).
type Runner interface {
	provision.Runner
	Close() error
}

// Deps, Ensure'ün dışarıya bağlandığı yerler. Testte hepsi taklit edilir.
type Deps struct {
	// Rules, grupların sudo kuralları (grup adı → kural).
	Rules func(ctx context.Context) (map[string]store.GroupSudo, error)
	// Row, (hedef, kişi) satırı; yoksa store.ErrNotFound.
	Row func(ctx context.Context, target, username string) (store.HostAccount, error)
	// Save, satırı yazar.
	Save func(ctx context.Context, a store.HostAccount) error
	// Connect, hedefe yönetim bağlantısı açar.
	Connect func(ctx context.Context, t model.Target, reason string) (Runner, error)
	// Caps, hedefin yetenekleri: hangi araçlar var, sshd principals
	// dosyası istiyor mu.
	Caps func(ctx context.Context, r Runner) (upstream.ManageCapabilities, error)
	/*
	 * UID, kişinin filo boyunca taşıdığı numarayı verir. 0 dönerse
	 * numarayı hedef seçiyor.
	 *
	 * ⚠️ HATA OTURUMU KESMİYOR, NUMARASIZ DEVAM EDİYOR. Havuz dolduğunda
	 * ya da veritabanı cevap vermediğinde hesabın hiç açılmaması,
	 * postern'i tam da olmaması gereken şeye — girişin önündeki tek hata
	 * noktasına — çevirirdi. Numarasız hesap, yanlış numaralı hesaptan da
	 * kapalı kapıdan da iyi.
	 */
	UID func(ctx context.Context, u model.User) (int, error)
	// Audit, hedefe YAZILDIĞINDA bir denetim satırı bırakır.
	Audit func(ctx context.Context, target, detail string) error
	// Now, saat (testte sabitlenebilir).
	Now func() time.Time
}

// Outcome, hazırlamanın sonucu. Err ASLA dolmuyor; sebep Reason'da.
type Outcome struct {
	// Skipped true ise hedefe hiç bağlanılmadı.
	Skipped bool
	// Reason, atlanma ya da başarısızlık sebebi; boşsa iş yapıldı.
	Reason string
	// Wrote true ise hedefte gerçekten bir şey değişti.
	Wrote bool
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}

	return time.Now()
}

/*
 * Ensure, kişinin bu hedefteki hesabını istenen duruma getirir.
 *
 * Sıra: satırı oku → istenen durumu hesapla → izler eşitse DÖN →
 * bağlan → gözle → planla → uygula → satırı yaz.
 */
func Ensure(ctx context.Context, d Deps, u model.User, t model.Target) Outcome {
	rules, err := d.Rules(ctx)
	if err != nil {
		return Outcome{Skipped: true, Reason: "the groups' sudo rules could not be read: " + err.Error()}
	}
	row, rerr := d.Row(ctx, t.Name, u.Name)

	var uid int
	if d.UID != nil {
		// Hata hâlinde uid 0 kalıyor ve hesap numarasız açılıyor;
		// gerekçe Deps.UID'in yanında.
		if n, uerr := d.UID(ctx, u); uerr == nil {
			uid = n
		}
	}

	/*
	 * ⚠️ MARKER, KAYITLI KAYNAKTAN GELİYOR. İlk koşuda kaynak henüz
	 * bilinmiyor (satır yok) ve marker'sız hesaplanıyor; Observe hesabın
	 * orada olmadığını söylerse kaynak "created" olur ve satıra YAZILAN
	 * fingerprint marker'lı hesaplanır. Sonraki koşular kayıtlı kaynakla
	 * aynı değeri üretir, yani fast lane tutar.
	 */
	want := Compute(u, t, rules, Account{
		Managed: rerr == nil && row.Origin == store.OriginCreated,
		UID:     uid,
	})
	switch {
	case rerr == nil:
		/*
		 * ⚠️ HIZLI ŞERİT. En son uygulanan durum istenen durumla aynıysa
		 * hedefte yapılacak bir şey yok ve bağlanmak saf kayıp. Kilitli
		 * bir satır bu şeritten geçmiyor: kilidi açmak yazma gerektiriyor.
		 */
		if row.State == store.HostAccountActive && row.AppliedFP == want.Fingerprint {
			return Outcome{Skipped: true}
		}
	case errors.Is(rerr, store.ErrNotFound):
		row = store.HostAccount{
			TargetName: t.Name, Username: u.Name, FirstSeen: d.now(),
		}
	default:
		return Outcome{Skipped: true, Reason: "the account row could not be read: " + rerr.Error()}
	}

	runner, cerr := d.Connect(ctx, t, "preparing "+u.Name+"'s account")
	if cerr != nil {
		return d.fail(ctx, row, want, "could not reach the target as its management account: "+cerr.Error())
	}
	defer func() { _ = runner.Close() }()

	caps, derr := d.Caps(ctx, runner)
	if derr != nil {
		return d.fail(ctx, row, want, "could not measure the target: "+derr.Error())
	}

	var desired provision.Desired
	for _, g := range want.Groups {
		desired.Groups = append(desired.Groups, provision.Group{Name: g.Name, Sudo: g.Sudo})
	}
	/*
	 * ⚠️ DESEN HESABIN BAĞLAMINDA OKUNUYOR. Match User bloğu olan bir
	 * sshd'de genel değer yanlış yolu gösteriyor ve dosya sshd'nin
	 * bakmadığı yere yazılıyor — hesap açılır ama sertifika onu açamaz.
	 */
	desired.PrincipalsFile = provision.PrincipalsPatternFor(ctx, runner, want.OSUser, caps.PrincipalsFile)
	/*
	 * ⚠️ KALICI HESAP, JIT DEĞİL: JIT bayrağı ve süre YOK, dolayısıyla
	 * hesap postern-jit işaret grubuna GİRMİYOR. JIT sökümü yalnızca o
	 * gruptaki hesapları siliyor; bu ayrım, iki yolun bir arada güvenle
	 * yaşamasını sağlayan tek mekanizma (spec §12.1).
	 */
	desired.Users = []provision.User{{
		Name:   want.OSUser,
		Groups: groupNames(want.Groups),
		UID:    want.UID,
	}}

	/*
	 * ⚠️ KAYNAK BİLİNMİYORKEN MARKER GRUBU DA SORULUYOR — ÖLÇÜLDÜ.
	 *
	 * Kaynak Observe'dan SONRA çözülüyor, yani ilk Compute marker'sız
	 * çalışıyor ve grup istenen durumda hiç görünmüyor. Sorulmazsa
	 * o.Groups[postern-managed] false kalıyor ve plan bir `groupadd`
	 * üretiyor. Aynı makinedeki İKİNCİ kişide o komut "grup zaten var"
	 * diye düşüyor ve hesap hiç açılmıyor: entegrasyon testi "1 of 5
	 * steps did not finish" dedi, yani bir makinede postern yalnızca tek
	 * kişiye hesap açabiliyordu. Bir `getent` daha, bu bedelin yanında
	 * hiçbir şey.
	 */
	if row.Origin == "" {
		desired.Groups = append(desired.Groups, provision.Group{Name: provision.ManagedGroup})
	}

	observed, oerr := provision.Observe(ctx, runner, desired)
	if oerr != nil {
		return d.fail(ctx, row, want, "could not read the target: "+oerr.Error())
	}

	/*
	 * ⚠️ SAHİPLİK BURADA, TEK KEZ BELİRLENİYOR (K7). Hesap gözlemde
	 * varsa postern onu DEVRALIYOR: yeniden açmıyor, kabuğunu ve ev
	 * dizinini kendi varsayılanlarıyla ezmiyor. Satır zaten varsa
	 * kaynağı korunuyor; store da onu güncellemiyor.
	 */
	if row.Origin == "" {
		if _, existed := observed.Users[want.OSUser]; existed {
			row.Origin = store.OriginAdopted
		} else {
			row.Origin = store.OriginCreated
		}
		/*
		 * Kaynak yeni çözüldü: istenen durumu ONA GÖRE yeniden kur.
		 * postern açıyorsa hesap marker grubuna giriyor ve fingerprint
		 * de onu içeriyor; devralıyorsa ikisi de yok.
		 */
		want = Compute(u, t, rules, Account{Managed: row.Origin == store.OriginCreated, UID: uid})
		desired.Groups = desired.Groups[:0]
		for _, g := range want.Groups {
			desired.Groups = append(desired.Groups, provision.Group{Name: g.Name, Sudo: g.Sudo})
		}
		desired.Users[0].Groups = groupNames(want.Groups)
	}

	/*
	 * ⚠️ ÇAKIŞMA ZORLANMIYOR, KAYDEDİLİYOR. Numara hedefte başka bir
	 * hesabın üstündeyse plan `-u`'yu hiç geçmiyor ve hesap hedefin kendi
	 * numarasıyla açılıyor. Zorlamak, o numaraya ait bütün dosyaların
	 * sahipliğini yeni hesaba devretmek olurdu — eski sahibin evi,
	 * log'ları, anahtarları. Kişinin o makinede filo numarasını
	 * taşımaması, bunun yanında küçük bir zarar; ama sessiz kalmaması
	 * gerekiyor, çünkü "neden bu makinede numarası farklı" sorusunun
	 * cevabı başka hiçbir yerde yok.
	 */
	if owner := observed.UIDOwner[want.UID]; owner != "" && d.Audit != nil {
		_ = d.Audit(ctx, t.Name, fmt.Sprintf(
			"uid conflict: %s should be uid %d but %s already holds it here; "+
				"%s was given the target's own number instead",
			u.Name, want.UID, owner, want.OSUser))
	}

	steps, perr := provision.Plan(caps, desired, observed)
	if perr != nil {
		return d.fail(ctx, row, want, "refused before touching the target: "+perr.Error())
	}
	if len(steps) == 0 {
		// Hedef zaten istenen hâlde: izi güncelle, yazma yapma.
		return d.settle(ctx, row, want, false)
	}

	rep := provision.Apply(ctx, runner, steps)
	if rep.Failed() > 0 || rep.Unreachable() > 0 {
		return d.fail(ctx, row, want,
			fmt.Sprintf("%d of %d steps did not finish on the target", rep.Failed()+rep.Unreachable(), len(steps)))
	}
	if d.Audit != nil {
		_ = d.Audit(ctx, t.Name,
			fmt.Sprintf("prepared %s (account %s) in %d step(s): %s",
				u.Name, want.OSUser, len(steps), groupList(want.Groups)))
	}

	return d.settle(ctx, row, want, true)
}

// settle, başarılı sonucu satıra yazar.
func (d Deps) settle(ctx context.Context, row store.HostAccount, want Want, wrote bool) Outcome {
	now := d.now()
	row.OSUser = want.OSUser
	row.State = store.HostAccountActive
	row.AwaitingDecision = false
	row.DesiredFP = want.Fingerprint
	row.AppliedFP = want.Fingerprint
	row.AppliedAt = now
	row.Attempts = 0
	row.LastError = ""
	row.NextAttemptAt = time.Time{}
	row.UpdatedAt = now
	if err := d.Save(ctx, row); err != nil {
		return Outcome{Reason: "the target was prepared but the record could not be written: " + err.Error(), Wrote: wrote}
	}

	return Outcome{Wrote: wrote}
}

/*
 * fail, başarısızlığı satıra yazar ve geri çekilme zamanı koyar.
 *
 * ⚠️ HATA DÖNMÜYOR. Çağıran oturumu açmaya devam edecek; buradaki tek iş
 * sebebi kaydetmek ve bozuk bir hedefin her bağlantıda yeniden
 * dövülmesini engellemek.
 */
func (d Deps) fail(ctx context.Context, row store.HostAccount, want Want, reason string) Outcome {
	now := d.now()
	row.OSUser = want.OSUser
	if row.State == "" {
		row.State = store.HostAccountFailed
	}
	if row.Origin == "" {
		row.Origin = store.OriginCreated
	}
	row.DesiredFP = want.Fingerprint
	row.Attempts++
	row.LastError = reason
	row.NextAttemptAt = now.Add(backoff(row.Attempts))
	row.UpdatedAt = now
	_ = d.Save(ctx, row)

	return Outcome{Reason: reason}
}

/*
 * backoff, üstel geri çekilme, tavanı 15 dakika.
 *
 * ⚠️ TAVAN VAR: bozuk bir hedefe her bağlantıda yeniden bağlanmaya
 * çalışmak, o hedefe giden herkesin oturumuna bağlantı zaman aşımı kadar
 * gecikme ekler.
 */
func backoff(attempts int) time.Duration {
	d := time.Duration(1<<min(attempts, 10)) * time.Second
	if d > 15*time.Minute {
		return 15 * time.Minute
	}

	return d
}

func groupNames(gs []GroupRule) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.Name)
	}

	return out
}

func groupList(gs []GroupRule) string {
	if len(gs) == 0 {
		return "no group"
	}
	out := ""
	for i, g := range gs {
		if i > 0 {
			out += ", "
		}
		out += g.Name
	}

	return out
}
