package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ldap"
)

/*
 * Grup üzerinden yönetici yetkisi.
 *
 * ⚠️ ÜRÜN KURALI DEĞİŞTİ: is_admin artık yalnızca host CLI'ından değil,
 * belirlenmiş bir dizin grubundan da gelebiliyor. PANELDEN atama hâlâ
 * yok — değişen şey, CLI'ın tek kaynak olmaktan çıkıp iki kaynaktan
 * biri olması.
 *
 * Gerekçe: kurum, kurulumdan sonra postern'in çalıştığı sunucuya girmek
 * zorunda kalmasın. Ve tutarlılık: dizin zaten kimin production'a
 * erişeceğine karar veriyor, roller ondan geliyor — admin bayrağını
 * kutsal saymak tutarsızdı. Sorumluluk dizini yönetene geçiyor.
 */

// adminGroupName, yapılandırılmış yönetici grubunu döner. Boşsa grup
// üzerinden yönetici atanmıyor.
func (s *Server) adminGroupName(ctx context.Context) string {
	v, err := s.store.Setting(ctx, ldap.KeyAdminGroup)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

/*
 * applyGroupAdmin, çözülmüş gruplara bakarak yönetici yetkisini uygular.
 *
 * ⚠️ YALNIZCA GRUPLAR GERÇEKTEN ÇÖZÜLDÜĞÜNDE çağrılmalı. "Bulamadım"
 * ya da "cevap veremedim" hâlinde çağrılırsa, bir dizin arızası bütün
 * yöneticilerin yetkisini kaldırırdı — ve onu geri verecek kişinin de
 * kapısını kapatırdı.
 *
 * Karşılaştırma harf duyarsız: dizinler grup adlarını öyle sayıyor ve
 * "SysAdmins" yazan bir ayarın "sysadmins" grubunu görmemesi, sessiz
 * bir yetki kaybı olurdu.
 */
func (s *Server) applyGroupAdmin(ctx context.Context, username string, groups []string) {
	want := s.adminGroupName(ctx)
	if want == "" {
		return
	}

	member := false
	for _, g := range groups {
		if strings.EqualFold(strings.TrimSpace(g), want) {
			member = true
			break
		}
	}

	if err := s.store.SetGroupAdmin(ctx, username, member); err != nil {
		// Yetki uygulanamadıysa girişi düşürmüyoruz: kullanıcı zaten
		// kimlik doğruladı ve yönetici olmayan bir oturum, hiç oturum
		// olmamasından iyi. Ama sessiz kalmıyor.
		s.logger.Error("group admin apply failed", "user", username, "error", err)
		return
	}
	s.logger.Info("group admin applied", "user", username,
		"admin", member, "group", want)
}

/*
 * adminAdminGroupPreview: POST /api/admin/ldap/admin-group/preview
 *
 * ⚠️ ONAY EKRANININ ÇEKİRDEĞİ. Operatör bir grup adı yazıyor ve
 * kaydetmeden ÖNCE "bu kişilere yönetici yetkisi veriyorsun" listesini
 * görüyor.
 *
 * ⚠️ LİSTE, GİRİŞTEKİ KARARLA AYNI YOLDAN ÜRETİLİYOR. Üye listesini
 * dizinden çıkarmak yalnızca ADAYLARI veriyor; her aday sonra
 * kullanıcı başına çalışan gerçek çözümlemeden (Lookup) geçiriliyor ve
 * yalnızca çözülmüş grupları içinde admin grubu ÇIKANLAR listeleniyor.
 *
 * Ayrı bir sorgu yazmak daha ucuz olurdu ve tam da onay ekranının
 * yapabileceği en kötü şeyi yapardı: ekran güven verir, giriş başka
 * davranır. İç içe gruplar, kapsam kuralı ve normalizasyon burada da
 * aynı.
 */
func (s *Server) adminAdminGroupPreview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Group string `json:"group"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	group := strings.TrimSpace(in.Group)
	if group == "" {
		writeErr(w, http.StatusBadRequest, "group is required")
		return
	}

	src, err := ldap.SourceFromStore(r.Context(), s.store)
	if err != nil {
		if errors.Is(err, ldap.ErrNotConfigured) {
			writeErr(w, http.StatusBadRequest, "ldap is not configured")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	members, err := src.MembersOf(r.Context(), group)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if len(members.Usernames) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "group": group, "admins": []string{}, "skipped": []string{},
			"note": "no group by that name was found in scope, or it has no members",
		})
		return
	}

	// Her aday GERÇEK yoldan doğrulanıyor.
	admins := make([]string, 0, len(members.Usernames))
	skipped := make([]string, 0)
	for _, name := range members.Usernames {
		res, lerr := src.Lookup(r.Context(), auth.Identity{Username: name})
		if lerr != nil || res.Presence != ldap.PresencePresent {
			// Aday listesinde var ama çözümleme onu doğrulamıyor:
			// sessizce atmak yerine SÖYLÜYORUZ.
			skipped = append(skipped, name)
			continue
		}
		if res.Disabled {
			skipped = append(skipped, name+" (disabled)")
			continue
		}
		for _, g := range res.Groups {
			if strings.EqualFold(strings.TrimSpace(g), group) {
				admins = append(admins, name)
				break
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"group":     group,
		"admins":    admins,
		"skipped":   skipped,
		"truncated": members.Truncated,
	})
}
