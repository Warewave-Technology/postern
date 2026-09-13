package provision

/*
 * Hedefin ŞU ANKİ durumunu okumak — plan bunun üstüne kuruluyor.
 *
 * ⚠️ BU KOD UZUN SÜRE YALNIZCA TESTTE YAŞADI. Plan bir Observed istiyor
 * ve onu üreten tek şey canlı testin yardımcısıydı; ürünün kendisi hedefi
 * hiç okuyamıyordu. Buraya taşınırken bir de ders geldi: err != nil "yok"
 * demek DEĞİL. Cevapsız kalan bir `getent`, grubu yok gösterir, plan onu
 * yeniden yaratmaya kalkar; cevapsız kalan bir `id`, silinmemiş bir hesabı
 * "gitti" gösterir. Yalnızca hedefin sıfırdan farklı çıkış kodu "yok"
 * demek; her şey hata.
 */

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Warewave-Technology/postern/internal/upstream"
)

// absent, hedefin "yok" cevabını cevapsızlıktan ayırır.
func absent(err error) (bool, error) {
	if err == nil {
		return false, nil
	}
	var cmdErr *upstream.CommandError
	if errors.As(err, &cmdErr) {
		return true, nil
	}

	return false, err
}

/*
 * Observe, istenen durumun ilgilendirdiği her şeyi hedeften okur: gruplar
 * var mı, hesaplar hangi gruplarda, postern'in sudo dosyalarında ne var.
 *
 * ⚠️ YALNIZCA SORULANI OKUYOR. Makinenin bütün grup ve hesap listesini
 * çekmek daha kolay olurdu ama hedefin envanterini bastion'a taşımak
 * demekti; plan neyi değiştirecekse yalnızca onu soruyor.
 */
func Observe(ctx context.Context, r Runner, d Desired) (Observed, error) {
	o := Observed{
		Groups: map[string]bool{}, Users: map[string][]string{},
		PosternSudoers: map[string]string{},
	}

	groups := append([]Group(nil), d.Groups...)
	if anyJIT(d.Users) && !hasGroup(groups, JITGroup) {
		groups = append(groups, Group{Name: JITGroup})
	}
	for _, g := range groups {
		if bad := checkName(g.Name); bad != "" {
			return Observed{}, fmt.Errorf("provision.Observe: group %q: %s", g.Name, bad)
		}
		_, err := r.Exec(ctx, "getent group "+g.Name, "")
		gone, err := absent(err)
		if err != nil {
			return Observed{}, fmt.Errorf("provision.Observe: group %s: %w", g.Name, err)
		}
		o.Groups[g.Name] = !gone

		if len(g.Sudo.Commands) == 0 {
			continue
		}
		if err := readSudoFile(ctx, r, SudoPath(g.Name), o); err != nil {
			return Observed{}, err
		}
	}

	for _, u := range d.Users {
		if bad := checkName(u.Name); bad != "" {
			return Observed{}, fmt.Errorf("provision.Observe: user %q: %s", u.Name, bad)
		}
		out, err := r.Exec(ctx, "id -Gn "+u.Name, "")
		gone, err := absent(err)
		if err != nil {
			return Observed{}, fmt.Errorf("provision.Observe: user %s: %w", u.Name, err)
		}
		if !gone {
			o.Users[u.Name] = strings.Fields(strings.TrimSpace(out))
		}
		if u.Sudo != nil {
			if err := readSudoFile(ctx, r, UserSudoPath(u.Name), o); err != nil {
				return Observed{}, err
			}
		}
	}

	return o, nil
}

// readSudoFile, postern'in yazdığı bir sudoers dosyasını olduğu gibi okur.
func readSudoFile(ctx context.Context, r Runner, path string, o Observed) error {
	out, err := r.Exec(ctx, "sudo -n cat "+path, "")
	gone, err := absent(err)
	if err != nil {
		return fmt.Errorf("provision.Observe: %s: %w", path, err)
	}
	if !gone {
		// ⚠️ Kırpılmıyor: plan bunu yazacağıyla BAYT BAYT karşılaştırıyor.
		o.PosternSudoers[path] = out
	}

	return nil
}

// AccountFacts, sökme planının bir hesap hakkında bilmesi gerekenler.
type AccountFacts struct {
	Exists bool
	UID    int
	Home   string
	Groups []string
}

// InJITGroup, hesabın postern tarafından açıldığının kanıtı.
func (a AccountFacts) InJITGroup() bool { return hasName(a.Groups, JITGroup) }

/*
 * Account, bir hesabın numarasını, evini ve gruplarını hedeften okur —
 * sökme planının varsayım değil ölçüm istediği üç şey.
 *
 * ⚠️ SİLMEDEN ÖNCE OKUNUYOR. Ad-UID eşlemesi userdel ile kayboluyor ve
 * kalan dosyaların raporu o numarayla aranıyor; sonradan sorulsa cevap
 * yok. Ev dizini de getent'ten: "/home/<ad>" varsaymak, farklı evi olan
 * bir hesapta karalama yolu kontrolünü yanlış yere baktırırdı.
 */
func Account(ctx context.Context, r Runner, name string) (AccountFacts, error) {
	if bad := checkName(name); bad != "" {
		return AccountFacts{}, fmt.Errorf("provision.Account: %q: %s", name, bad)
	}

	out, err := r.Exec(ctx, "getent passwd "+name, "")
	gone, err := absent(err)
	if err != nil {
		return AccountFacts{}, fmt.Errorf("provision.Account: %s: %w", name, err)
	}
	if gone {
		return AccountFacts{}, nil
	}

	fields := strings.Split(strings.TrimSpace(out), ":")
	if len(fields) < 7 {
		return AccountFacts{}, fmt.Errorf("provision.Account: %s: unexpected passwd entry %q", name, out)
	}
	uid, err := strconv.Atoi(fields[2])
	if err != nil {
		return AccountFacts{}, fmt.Errorf("provision.Account: %s: uid %q is not a number", name, fields[2])
	}

	groups, err := r.Exec(ctx, "id -Gn "+name, "")
	if _, err := absent(err); err != nil {
		return AccountFacts{}, fmt.Errorf("provision.Account: %s: %w", name, err)
	}

	return AccountFacts{
		Exists: true, UID: uid, Home: fields[5],
		Groups: strings.Fields(strings.TrimSpace(groups)),
	}, nil
}
