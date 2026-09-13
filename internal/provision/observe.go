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
		Groups: map[string]bool{}, GIDs: map[string]int{}, Users: map[string][]string{},
		PosternSudoers: map[string]string{}, Principals: map[string]string{},
	}

	groups := append([]Group(nil), d.Groups...)
	if anyJIT(d.Users) && !hasGroup(groups, JITGroup) {
		groups = append(groups, Group{Name: JITGroup})
	}
	for _, g := range groups {
		if bad := checkName(g.Name); bad != "" {
			return Observed{}, fmt.Errorf("provision.Observe: group %q: %s", g.Name, bad)
		}
		out, err := r.Exec(ctx, "getent group "+g.Name, "")
		gone, err := absent(err)
		if err != nil {
			return Observed{}, fmt.Errorf("provision.Observe: group %s: %w", g.Name, err)
		}
		o.Groups[g.Name] = !gone
		if !gone {
			/*
			 * ⚠️ NUMARA DA OKUNUYOR. Plan, geçici hesabı 1000'in altındaki
			 * (sistem) gruplara almayı reddediyor ve bunun için grubun
			 * numarasını bilmek zorunda; "var" bilgisi tek başına
			 * docker'ı dba'dan ayıramaz.
			 */
			info, err := parseGroupLine(strings.TrimSpace(out))
			if err != nil {
				return Observed{}, fmt.Errorf("provision.Observe: group %s: %w", g.Name, err)
			}
			o.GIDs[g.Name] = info.GID
		}

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
		// Geçici hesabın principals dosyası: plan bayt bayt karşılaştırıyor.
		if u.JIT && d.PrincipalsFile != "" {
			path, err := PrincipalsPath(d.PrincipalsFile, u.Name)
			if err != nil {
				return Observed{}, fmt.Errorf("provision.Observe: user %s: %w", u.Name, err)
			}
			out, err := r.Exec(ctx, "sudo -n cat "+path, "")
			gone, err := absent(err)
			if err != nil {
				return Observed{}, fmt.Errorf("provision.Observe: %s: %w", path, err)
			}
			if !gone {
				o.Principals[path] = out
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

/*
 * MinJITGID, bir geçici hesabın alınabileceği en küçük grup numarası.
 *
 * ⚠️ ALTINDAKİLER KORUNUYOR. Linux'ta 1000'in altı sistem gruplarıdır
 * (login.defs: SYS_GID_MAX 999, GID_MIN 1000): root, wheel/sudo, adm,
 * shadow, docker… Bunlardan birine üyelik, hiçbir sudo kuralı yazmadan
 * root'a giden bir yol — docker grubu root eşdeğeridir, shadow parola
 * özetlerini okutur. Geçici hesap yalnızca kullanıcı gruplarına
 * alınabilir; sınır kullanıcının kararı (2026-09-13).
 */
const MinJITGID = 1000

// GroupInfo, hedefteki bir grubun adı, numarası ve üyeleri.
type GroupInfo struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
}

// Protected, grubun geçici hesaplara kapalı olup olmadığı.
func (g GroupInfo) Protected() bool { return g.GID < MinJITGID }

/*
 * Groups, hedefin bütün gruplarını okur — panelin "hangi gruba alayım"
 * seçicisi için. Observe'un aksine envanterin tamamı isteniyor; seçici
 * ancak listeyi görerek seçebilir. `getent group` sudo istemiyor ve NSS
 * üzerinden dizin gruplarını da veriyor.
 */
func Groups(ctx context.Context, r Runner) ([]GroupInfo, error) {
	out, err := r.Exec(ctx, "getent group", "")
	if err != nil {
		return nil, fmt.Errorf("provision.Groups: %w", err)
	}
	groups := make([]GroupInfo, 0)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		g, err := parseGroupLine(line)
		if err != nil {
			return nil, fmt.Errorf("provision.Groups: %w", err)
		}
		groups = append(groups, g)
	}

	return groups, nil
}

// parseGroupLine, "ad:x:gid:üye,üye" satırını çözer.
func parseGroupLine(line string) (GroupInfo, error) {
	f := strings.Split(line, ":")
	if len(f) < 3 {
		return GroupInfo{}, fmt.Errorf("unexpected group entry %q", line)
	}
	gid, err := strconv.Atoi(f[2])
	if err != nil {
		return GroupInfo{}, fmt.Errorf("group %s: gid %q is not a number", f[0], f[2])
	}
	g := GroupInfo{Name: f[0], GID: gid, Members: []string{}}
	if len(f) > 3 && f[3] != "" {
		g.Members = strings.Split(f[3], ",")
	}

	return g, nil
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
