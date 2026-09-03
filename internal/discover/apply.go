package discover

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

/*
 * Keşfin postern tarafı: makineleri hedeflere, etiketleri rollere
 * çevirmek.
 *
 * ⚠️ ÖNİZLEME VE UYGULAMA AYNI KODU KULLANIYOR. İki ayrı yol yazmak,
 * operatörün gördüğü şeyle yapılan şeyin zamanla ayrışması demekti —
 * ve bu ekranın bütün değeri "ne olacağını önce görmek". Fark tek bir
 * bayrakta: apply false ise hiçbir yazma çağrısı yapılmıyor.
 */

// Planner, keşfi postern'e uygular.
type Planner struct {
	DB *store.Store
	// TagKey, rol adını taşıyan etiket anahtarı ("role").
	TagKey string
	// Port, hedeflerin SSH portu.
	Port int
	// Actor, denetim kaydına yazılacak kim.
	Actor string
}

/*
 * Run, makineleri işler.
 *
 * apply=false ise HİÇBİR yazma yapılmıyor; dönen Outcome listesi yine
 * de "ne olurdu"yu tam olarak anlatıyor — host anahtarı taraması dahil,
 * çünkü taramanın başarısız olması bir makinenin atlanmasının en sık
 * sebebi ve onu önizlemede göstermemek, önizlemeyi yalancı yapardı.
 */
func (p Planner) Run(ctx context.Context, machines []Machine, apply bool) ([]Outcome, error) {
	existing, err := p.DB.Targets(ctx)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]model.Target, len(existing))
	for _, t := range existing {
		byName[t.Name] = t
	}

	roles, err := p.DB.Roles(ctx)
	if err != nil {
		return nil, err
	}
	haveRole := make(map[string]bool, len(roles))
	// haveGrant, KOŞU BAŞLARKEN var olan (rol, hedef) bağları. Denetim
	// satırının yalnızca YENİ bir erişim doğduğunda yazılması için:
	// GrantTarget ON CONFLICT DO NOTHING kullanıyor ve "zaten vardı"yı
	// çağırana söylemiyor, o yüzden fark buradan okunuyor. Ek sorgu yok
	// — roller zaten hedefleriyle geldi.
	haveGrant := map[string]bool{}
	for _, r := range roles {
		haveRole[r.Name] = true
		for _, tn := range r.Targets {
			haveGrant[grantKey(r.Name, tn)] = true
		}
	}

	out := make([]Outcome, 0, len(machines))
	for _, m := range machines {
		o := Outcome{Machine: m}
		o.Role, o.Tagged = RoleFromTags(m.Tags, p.TagKey)

		if err := ValidRoleName(o.Role); err != nil {
			// ⚠️ Etiket güvenilmeyen girdi: kabul edilemeyen bir ad
			// makineyi unknown'a düşürmüyor, ATLIYOR. Sessizce
			// unknown'a koymak, operatörün yazım hatasını bir daha
			// göremeyeceği bir yere süpürürdü.
			o.Skipped = fmt.Sprintf("tag names an unusable role (%v)", err)
			out = append(out, o)
			continue
		}

		if !m.Running {
			o.Skipped = "not running, so its host key cannot be read"
			out = append(out, o)
			continue
		}

		host := strings.TrimSpace(m.Host)
		if host == "" {
			// Adres öğrenilemedi: makinenin ADI deneniyor.
			host = m.Name
		}

		/*
		 * ⚠️ HOST ANAHTARI HER ZAMAN TARANIYOR, önizlemede bile.
		 *
		 * Anahtar postern'in güven çıpası: hedefi anahtarsız yazmak
		 * "sonra bakarız" demek olurdu ve o hedefe ilk bağlanan kişi,
		 * karşısındakinin kim olduğunu bilmeden bağlanırdı. Taranamayan
		 * makine hedef olmuyor.
		 */
		key, serr := upstream.ScanHostKey(ctx, host, p.Port)
		t, existing := byName[m.Name]
		o.Existing = existing

		if serr != nil {
			/*
			 * ⚠️ TARAMA HATASI YENİ HEDEFİ DÜŞÜRÜR, VAR OLANI DÜŞÜRMEZ.
			 *
			 * ÖLÇÜLEN ARIZA: hata hangi durumda olursa olsun makineyi
			 * atlıyordu — ve atlanan şeylerin arasında GrantTarget da
			 * vardı. Oysa grant HİÇ AĞ İSTEMİYOR: rolle hedef arasında
			 * yerel bir bağ. Sonuç: etiketi değişmiş bir makine, o an
			 * ağda bir aksaklık olduğu için yeni rolüne geçmiyordu ve
			 * bir sonraki koşuma kadar eski rolünde kalıyordu — bu
			 * dosyanın kendi yorumu (aşağıda) grant'ın her turda
			 * çalışması gerektiğini söylüyor.
			 *
			 * Yeni bir hedef için hata hâlâ ölümcül: anahtarsız hedef
			 * yazmak, ona ilk bağlanan kişinin karşısındakini
			 * bilmemesi demek.
			 */
			if !existing {
				o.Skipped = fmt.Sprintf("no host key from %s:%d (%v)", host, p.Port, serr)
				out = append(out, o)
				continue
			}
			// Anahtar bu turda DOĞRULANAMADI ve bu söyleniyor: sessizce
			// "kontrol ettim" gibi davranmak, değişmiş bir makineyi
			// değişmemiş göstermek olurdu.
			o.KeyUnchecked = fmt.Sprintf("host key not re-checked (%v)", serr)
		}

		var authorized string
		if serr == nil {
			authorized = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		}

		if existing && serr == nil {
			/*
			 * ⚠️ VAR OLAN HEDEFE DOKUNULMUYOR — anahtarı farklı olsa
			 * bile, ÖZELLİKLE anahtarı farklıysa.
			 *
			 * Keşif toplu ve otomatik çalışıyor. Kayıtlı bir host
			 * anahtarını sessizce üzerine yazmak, "makine değişti"yi
			 * "makine yenilendi" sanıp kabul etmek demek — ve bu, host
			 * anahtarının var olma sebebini ortadan kaldırır. Fark
			 * varsa rapora yazılıyor ve kararı insan veriyor.
			 */
			if t.HostKey != "" && fingerprint(t.HostKey) != ssh.FingerprintSHA256(key) {
				o.Skipped = "already registered with a DIFFERENT host key — " +
					"left untouched; check the machine before changing it"
				out = append(out, o)
				continue
			}
		}

		if apply {
			if !haveRole[o.Role] {
				if _, cerr := p.DB.CreateRole(ctx, o.Role); cerr != nil &&
					!errors.Is(cerr, store.ErrConflict) {
					return out, fmt.Errorf("create role %q: %w", o.Role, cerr)
				}
				haveRole[o.Role] = true
				o.CreatedRole = true
				if aerr := p.audit(ctx, "discover.role_created", o.Role,
					"created from tag "+p.TagKey); aerr != nil {
					return out, aerr
				}
			}

			if !o.Existing {
				if _, cerr := p.DB.CreateTarget(ctx, model.Target{
					Name: m.Name, Host: host, Port: p.Port, HostKey: authorized,
				}); cerr != nil && !errors.Is(cerr, store.ErrConflict) {
					return out, fmt.Errorf("create target %q: %w", m.Name, cerr)
				}
				o.CreatedTarget = true
				if aerr := p.audit(ctx, "discover.target_created", m.Name,
					fmt.Sprintf("%s:%d from %s", host, p.Port, m.Ref)); aerr != nil {
					return out, aerr
				}
			}

			/*
			 * ⚠️ GRANT HER TURDA ÇALIŞIYOR, yalnızca yeni hedeflerde
			 * değil. Etiketi değişen bir makine ikinci koşuda yeni
			 * rolüne bağlanmalı; "zaten vardı" diye atlamak, keşfi bir
			 * kerelik bir işlem yapardı.
			 *
			 * ESKİ ROLDEN DÜŞÜRMÜYOR: erişim kaldırmak bilinçli bir
			 * karar ve toplu bir tarama onu veremez.
			 */
			/*
			 * ⚠️ VE DEFTERE YAZILIYOR — YAZILMADIĞI HÂLİ ÖLÇÜLDÜ.
			 *
			 * Yukarıdaki iki yazma (rol ve hedef oluşturma) denetleniyor,
			 * bu denetlenmiyordu. Kaçırdığı durum tam da yorumun bir üstte
			 * anlattığı durum: etiketi değişen bir makine ikinci koşuda
			 * yeni rolüne bağlanıyor — ne rol ne hedef yaratılıyor, yani
			 * iki satırın ikisi de yazılmıyor ve `postern discover
			 * --apply`, hedefe erişim dağıtan TEK yol olarak defterde hiç
			 * iz bırakmıyordu. "prod erişimini web01'e kim verdi?"
			 * sorusuna `postern log` sessizlikle cevap veriyordu.
			 *
			 * Komut bunu operatörün terminaline basıyor, ama bu depo
			 * terminali yeterli SAYMAMAYA zaten karar verdi (yönetici
			 * grubu kolunda aynı gerekçe).
			 *
			 * ErrConflict yazılmıyor: o "zaten vardı" demek, yani yeni
			 * bir erişim doğmadı ve deftere her koşuda aynı satırı
			 * eklemek defteri gürültüye boğardı.
			 */
			if gerr := p.DB.GrantTarget(ctx, o.Role, m.Name); gerr != nil &&
				!errors.Is(gerr, store.ErrConflict) {
				return out, fmt.Errorf("grant %q to %q: %w", m.Name, o.Role, gerr)
			}
			if k := grantKey(o.Role, m.Name); !haveGrant[k] {
				haveGrant[k] = true
				if aerr := p.audit(ctx, "role.grant", o.Role,
					"target "+m.Name+" (from tag "+p.TagKey+")"); aerr != nil {
					return out, aerr
				}
			}
			o.Granted = true
		}

		out = append(out, o)
	}

	SortOutcomes(out)
	return out, nil
}

// grantKey, (rol, hedef) çiftinin anahtarı. Hedef adları harf duyarsız
// tekil (ciColumns), o yüzden karşılaştırma da öyle.
func grantKey(role, target string) string {
	return strings.ToLower(role) + "\x00" + strings.ToLower(target)
}

/*
 * audit, keşfin yaptığı bir değişikliği denetim kaydına yazar.
 *
 * ⚠️ HATA ARTIK YUTULMUYOR — VE YUTULDUĞU HÂLİ BU DOSYANIN KENDİSİ
 * ANLAMSIZ KILIYORDU.
 *
 * Eski gerekçe "denetim satırı yazılamadı diye yarım kalmış bir keşif
 * bırakmak, kaydı olmayan bir keşiften daha kötü" idi. O tartışma,
 * yazılan satırlar yalnızca "rol yaratıldı"/"hedef yaratıldı" iken
 * savunulabilirdi. Artık ERİŞİM VEREN satır da buradan geçiyor: yutmak,
 * "hedefe erişim verildi ve defterde izi yok" demek — az önce
 * kapatılan deliğin aynısı, başka bir sebeple.
 *
 * Ve aynı ikilideki cmd/postern/audit.go tam tersini yazıyor:
 * "izlenemeyen bir değişiklik, yapılmamış bir değişiklikten daha
 * kötü". Bir ikilide iki denetim politikası olamaz.
 *
 * ⚠️ YARIM KALMA ENDİŞESİ GEÇERSİZ: bu döngüdeki her yazma
 * yeniden-çalıştırılabilir (CreateRole/CreateTarget ErrConflict'i
 * tolere ediyor, GrantTarget ON CONFLICT DO NOTHING). Yani duran bir
 * koşum yeniden koşularak tamamlanıyor. Üstelik LogAdmin düşüyorsa
 * veritabanının kendisi arızalı — kaydedemeyen bir veritabanına karşı
 * erişim dağıtmaya devam etmek, bu projenin her yerde reddettiği şey.
 */
func (p Planner) audit(ctx context.Context, action, entity, details string) error {
	if p.DB == nil {
		return nil
	}
	if err := p.DB.LogAdmin(ctx, store.AdminLogEntry{
		Actor: p.Actor, Via: "cli", Action: action, Entity: entity, Details: details,
	}); err != nil {
		return fmt.Errorf("audit %s %q: %w", action, entity, err)
	}
	return nil
}

func fingerprint(authorized string) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}
