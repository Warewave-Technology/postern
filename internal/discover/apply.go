package discover

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/upstream"
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
	for _, r := range roles {
		haveRole[r.Name] = true
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
		if serr != nil {
			o.Skipped = fmt.Sprintf("no host key from %s:%d (%v)", host, p.Port, serr)
			out = append(out, o)
			continue
		}
		authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))

		if t, ok := byName[m.Name]; ok {
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
			o.Existing = true
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
				p.audit(ctx, "discover.role_created", o.Role,
					"created from tag "+p.TagKey)
			}

			if !o.Existing {
				if _, cerr := p.DB.CreateTarget(ctx, model.Target{
					Name: m.Name, Host: host, Port: p.Port, HostKey: authorized,
				}); cerr != nil && !errors.Is(cerr, store.ErrConflict) {
					return out, fmt.Errorf("create target %q: %w", m.Name, cerr)
				}
				o.CreatedTarget = true
				p.audit(ctx, "discover.target_created", m.Name,
					fmt.Sprintf("%s:%d from %s", host, p.Port, m.Ref))
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
			if gerr := p.DB.GrantTarget(ctx, o.Role, m.Name); gerr != nil &&
				!errors.Is(gerr, store.ErrConflict) {
				return out, fmt.Errorf("grant %q to %q: %w", m.Name, o.Role, gerr)
			}
			o.Granted = true
		}

		out = append(out, o)
	}

	SortOutcomes(out)
	return out, nil
}

func (p Planner) audit(ctx context.Context, action, entity, details string) {
	if p.DB == nil {
		return
	}
	// Hatası akışı DÜŞÜRMÜYOR: denetim satırı yazılamadı diye yarım
	// kalmış bir keşif bırakmak, kaydı olmayan bir keşiften daha kötü.
	_ = p.DB.LogAdmin(ctx, store.AdminLogEntry{
		Actor: p.Actor, Via: "cli", Action: action, Entity: entity, Details: details,
	})
}

func fingerprint(authorized string) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}
