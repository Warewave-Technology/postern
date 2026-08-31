package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/store"
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
	name := strings.TrimSpace(v)

	/*
	 * ⚠️ `unknown` YÖNETİCİ GRUBU OLAMAZ ve kontrol EN DERİN yerde.
	 *
	 * `unknown`, kaynağın cevap verip hiçbir grup söylemediği herkesin
	 * düştüğü ad (bkz. model.UnknownGroup). Yönetici grubu olarak
	 * yazılırsa, GRUBU OLMAYAN HERKES yönetici olur — yani en az
	 * ayrıcalıklı kullanıcı kümesi, en ayrıcalıklısına dönüşür. Yazma
	 * uçları bunu zaten reddediyor; burada da durmasının sebebi, elle
	 * yazılmış ya da eski bir satırın sessizce iş görmemesi.
	 */
	if strings.EqualFold(name, model.UnknownGroup) {
		s.logger.Error("admin group is set to the catch-all group; ignoring",
			"group", name)
		return ""
	}
	return name
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

	pv, err := s.previewAdminGroup(r.Context(), group)
	if err != nil {
		if errors.Is(err, ldap.ErrNotConfigured) {
			writeErr(w, http.StatusBadRequest, "ldap is not configured")
			return
		}
		// Dizin cevap veremedi: bu bir SUNUCU hatası değil, bir CEVAP.
		// Operatör grubu yanlış yazmış da olabilir, dizin de düşmüş
		// olabilir; ikisini de aynı ekranda görmeli.
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, pv.body(true))
}

// adminGroupPreview, "bu grubu kaydedersem kim yönetici olur" sorusunun
// cevabı.
type adminGroupPreview struct {
	Group     string
	Admins    []string
	NoAccount []string
	Skipped   []string
	Truncated bool
}

func (p adminGroupPreview) body(okFlag bool) map[string]any {
	out := map[string]any{
		"ok":         okFlag,
		"error":      "",
		"group":      p.Group,
		"admins":     p.Admins,
		"no_account": p.NoAccount,
		"skipped":    p.Skipped,
		"truncated":  p.Truncated,
	}
	if !okFlag {
		// req() gövdeyi 2xx dışında atıyor ve yalnızca "error" alanını
		// okuyor: mesaj burada olmazsa panelde "request failed (409)"
		// görünür — yani asıl söylenmek istenen şey kaybolur.
		out["error"] = "the membership changed since you looked — check the list again"
	}
	if len(p.Admins) == 0 {
		out["note"] = "no group by that name was found in scope, or it has no members that resolve"
	}
	return out
}

/*
 * previewAdminGroup, adayları dizinden çıkarır ve HER BİRİNİ GİRİŞTEKİ
 * YOLDAN doğrular.
 *
 * ⚠️ Üye listesini okumak yalnızca ADAYLARI verir. Kimin gerçekten
 * yönetici olacağını, kullanıcı başına çalışan çözümleme (Lookup)
 * söyler: kapsam kuralı, iç içe gruplar, ad normalizasyonu ve kapalı
 * hesap kontrolü orada. Ayrı bir sorgu yazmak daha ucuz olurdu ve tam
 * da onay ekranının yapabileceği en kötü şeyi yapardı: ekran güven
 * verir, giriş başka davranır.
 */
func (s *Server) previewAdminGroup(ctx context.Context, group string) (adminGroupPreview, error) {
	pv := adminGroupPreview{
		Group:     group,
		Admins:    []string{},
		NoAccount: []string{},
		Skipped:   []string{},
	}

	src, err := ldap.SourceFromStore(ctx, s.store)
	if err != nil {
		return pv, err
	}

	members, err := src.MembersOf(ctx, group)
	if err != nil {
		return pv, err
	}
	pv.Truncated = members.Truncated

	for _, name := range members.Usernames {
		res, lerr := src.Lookup(ctx, auth.Identity{Username: name})
		if lerr != nil || res.Presence != ldap.PresencePresent {
			// Aday listesinde var ama çözümleme onu doğrulamıyor:
			// sessizce atmak yerine SÖYLÜYORUZ.
			pv.Skipped = append(pv.Skipped, name)
			continue
		}
		if res.Disabled {
			pv.Skipped = append(pv.Skipped, name+" (disabled)")
			continue
		}
		member := false
		for _, g := range res.Groups {
			if strings.EqualFold(strings.TrimSpace(g), group) {
				member = true
				break
			}
		}
		if !member {
			pv.Skipped = append(pv.Skipped, name)
			continue
		}
		pv.Admins = append(pv.Admins, name)

		// postern hesabı olmayanı AYRI söylüyoruz: yetkisi ancak ilk
		// girişinde oluşur ve ekran "şimdi yönetici oldu" derse yalan
		// söylemiş olur.
		if _, uerr := s.store.UserByNameFold(ctx, name); uerr != nil {
			pv.NoAccount = append(pv.NoAccount, name)
		}
	}
	return pv, nil
}

/*
 * adminAdminGroupStatus: GET /api/admin/ldap/admin-group
 *
 * Ayarlı grup ve ŞU AN yönetici olan herkes, yetkinin kaynağıyla.
 *
 * Kaynağın görünmesi şart: grup üzerinden gelen yetki panelden
 * kaldırılamaz (bir sonraki eşitlemede geri gelir) ve CLI'ın verdiği
 * hiç kaldırılamaz. Ekran bunu söylemezse operatör, kaldıramayacağı bir
 * yetkiyi kaldırabileceğini sanır.
 */
func (s *Server) adminAdminGroupStatus(w http.ResponseWriter, r *http.Request) {
	holders, err := s.store.Admins(r.Context())
	if err != nil {
		s.storeErr(w, "admin_group.status", err)
		return
	}

	// Dizin üyeliği sayılabiliyor mu? OIDC claim'i grup ÜYELİĞİNİ
	// listeleyemez — yalnızca "bu kişi bu gruptaymış" der. Onay ekranı
	// o kurulumda kimseyi sayamaz ve bunu saklamak yerine söylüyoruz.
	//
	// ⚠️ "Sayamıyorum"un İKİ ayrı sebebi var ve ekranda aynı cümleye
	// düşerlerse yanlış teşhis koydururlar: LDAP hiç kurulmamış olabilir
	// (gruplar claim'den geliyor, yapacak bir şey yok) ya da kurulmuş
	// ama bozuk olabilir (yapılacak bir şey var, ve söylenmezse operatör
	// "claim modundayım" sanıp arızayı hiç aramaz).
	enumerable, why := true, ""
	if _, serr := ldap.SourceFromStore(r.Context(), s.store); serr != nil {
		enumerable = false
		if !errors.Is(serr, ldap.ErrNotConfigured) {
			why = serr.Error()
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"group":            s.adminGroupName(r.Context()),
		"holders":          holders,
		"enumerable":       enumerable,
		"enumerable_error": why,
	})
}

/*
 * adminAdminGroupSet: POST /api/admin/ldap/admin-group
 *
 * ⚠️ ONAYIN BAĞLAYICI OLDUĞU YER. İstek, panelin GÖSTERDİĞİ listeyi
 * geri yollamak zorunda; sunucu listeyi yeniden hesaplayıp eşleşmiyorsa
 * REDDEDİYOR.
 *
 * Neden sadece "confirm: true" değil: o, onayı tiyatroya çevirirdi.
 * Kutuya bir grup adı yazıp önizlemeye hiç bakmadan kaydeden bir istemci
 * (ya da CSRF'i geçmiş bir istek) "evet"i bedavaya üretebilirdi. Listeyi
 * geri istemek, "bunu gördüm" iddiasını İSPATLANABİLİR yapıyor.
 *
 * ⚠️ Liste DONDURULMUYOR ve arayüz bunu söylemek zorunda: yetkiyi veren
 * GRUP. Yarın gruba eklenen de yönetici olur. Onay, o anki fotoğrafın
 * değil, grubun onayı.
 */
func (s *Server) adminAdminGroupSet(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Group   string   `json:"group"`
		Confirm []string `json:"confirm"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	group := strings.TrimSpace(in.Group)
	if strings.EqualFold(group, model.UnknownGroup) {
		writeErr(w, http.StatusBadRequest,
			"`"+model.UnknownGroup+"` is where everyone whose source named no group "+
				"lands — making it the administrator group would hand administrator "+
				"to every account that has no groups at all")
		return
	}

	// Kaydedildikten sonra yönetici olacak küme.
	var want []string
	// previewed: kimin yönetici olacağını ÖNCEDEN bilebildik mi.
	previewed := true
	if group != "" {
		pv, err := s.previewAdminGroup(r.Context(), group)
		if err != nil {
			if errors.Is(err, ldap.ErrNotConfigured) {
				/*
				 * ⚠️ DİZİN YOK: ÖNİZLEME YAPISAL OLARAK İMKÂNSIZ,
				 * AMA GRUP YİNE DE AYARLANABİLMELİ.
				 *
				 * Burası eskiden "ldap is not configured" ile
				 * REDDEDİYORDU ve sonucu bir çıkmazdı: OIDC girişinde
				 * yöneticilik YALNIZCA grup iddiasından geliyor
				 * (weblogin.go), kaynağı OIDC'ye çevirmek de grubun
				 * ayarlı olmasını şart koşuyor (canSwitchTo) — yani
				 * dizini olmayan bir kurulum OIDC'ye HİÇBİR ZAMAN
				 * geçemiyordu. Ayarı yapmanın tek yolu, ihtiyacı
				 * olmayan bir dizin kurmaktı.
				 *
				 * Önizlemeyi taklit ETMİYORUZ: bir kimlik sağlayıcıya
				 * "bu grupta kimler var" diye sorulamıyor, cevabı
				 * yalnızca kişi giriş yaptığında belirtecinde geliyor.
				 * Onay listesi de bu yüzden yok — olmayan bir listeyi
				 * onaylatmak, güvence veriyormuş gibi yapmak olurdu.
				 *
				 * Karşılığında yetki ŞİMDİ dağıtılmıyor: kimse bu
				 * kaydetmeyle yönetici olmuyor ya da olmaktan çıkmıyor.
				 * Herkes KENDİ bir sonraki girişinde değerlendiriliyor.
				 * Aşağıdaki refuseIfLastAdmin yine çalışıyor ve asıl
				 * korumayı o veriyor: ortada CLI'dan açılmış bir
				 * yönetici yoksa bu kaydetme reddediliyor.
				 */
				previewed = false
			} else {
				// ⚠️ Dizin VAR ama cevap vermiyorsa YAZMIYORUZ.
				// Doğrulanabilecek ama doğrulanamamış bir grup adını
				// kaydetmek, kimin yönetici olacağını bilmeden yetki
				// dağıtmak demek. Yukarıdaki dal bundan farklı:
				// orada doğrulanacak bir şey HİÇ yok.
				writeErr(w, http.StatusServiceUnavailable,
					"the directory could not be asked who is in that group: "+err.Error())
				return
			}
		}
		if previewed {
			want = pv.Admins
			if !sameNameSet(in.Confirm, want) {
				// Gördüğü liste artık geçerli değil: YENİSİNİ göster ve
				// tekrar sor. Sessizce kaydetmek, onaylanmamış bir kümeye
				// yetki vermek olurdu.
				writeJSON(w, http.StatusConflict, pv.body(false))
				return
			}
		}
	} else {
		// Temizleme: kaybedecek olanlar, ŞU AN grup üzerinden yönetici
		// olanlar. Onay yine listeye bağlı.
		current, err := s.groupAdminNames(r.Context())
		if err != nil {
			s.storeErr(w, "admin_group.set", err)
			return
		}
		if !sameNameSet(in.Confirm, current) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok": false, "group": "", "admins": current,
				"no_account": []string{}, "skipped": []string{}, "truncated": false,
				"error": "the list changed since you looked — check it again",
			})
			return
		}
	}

	/*
	 * ⚠️ SON YÖNETİCİYİ SİLDİRMİYORUZ.
	 *
	 * Grubu temizlemek ya da kimsenin çözülmediği bir gruba geçmek,
	 * bütün grup yöneticilerini düşürür. Geriye CLI yöneticisi de
	 * kalmıyorsa postern yönetici olmadan kalır ve tek çıkış, ürünün
	 * bütün amacı olan "kurulumdan sonra sunucuya girmemek"i bozmak:
	 * host'a girip `postern admin issue` çalıştırmak.
	 */
	if err := s.refuseIfLastAdmin(r.Context(), want); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if group == "" {
		if err := s.store.DeleteSetting(r.Context(), ldap.KeyAdminGroup); err != nil &&
			!errors.Is(err, store.ErrNotFound) {
			s.storeErr(w, "admin_group.set", err)
			return
		}
	} else if err := s.store.SetSetting(r.Context(), ldap.KeyAdminGroup, group, false, sessionUser(r)); err != nil {
		s.storeErr(w, "admin_group.set", err)
		return
	}

	/*
	 * ⚠️ ŞİMDİ uygulanıyor, "bir sonraki girişte" değil. Yalnızca
	 * girişte uygulansaydı, grubu değiştirmek ESKİ yöneticileri yerinde
	 * bırakırdı: bir daha hiç giriş yapmayan kişi süresiz yönetici
	 * kalırdı. Ve onay ekranı "bu kişiler yönetici oluyor" derken
	 * gerçeği söylemiş olmazdı.
	 *
	 * ⚠️ ÖNİZLENEMEYEN GRUPTA ÇALIŞTIRILMIYOR. Orada `want` boş ve
	 * boş bir kümeyle çağırmak "bu grupta kimse yok" demek olurdu —
	 * yani bütün grup yöneticilerini düşürürdü. Bilinmeyen bir küme,
	 * boş bir küme DEĞİL.
	 */
	var granted, revoked []string
	if previewed {
		var aerr error
		granted, revoked, aerr = s.store.ApplyAdminGroup(r.Context(), want)
		if aerr != nil {
			s.storeErr(w, "admin_group.set", aerr)
			return
		}
	}

	detail := "group=" + group
	if group == "" {
		detail = "cleared"
	}
	s.audit(r, "admin_group.set", group,
		detail+"; granted "+strings.Join(granted, ",")+"; revoked "+strings.Join(revoked, ","))
	s.logger.Warn("admin group changed", "actor", sessionUser(r), "group", group,
		"granted", granted, "revoked", revoked)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		// ⚠️ Panel bu bayrağa bakıp doğru cümleyi kuruyor: önizlenemeyen
		// bir grupta "şu kişiler yönetici oldu" demek yalan olurdu.
		"deferred": !previewed,
		"group":    group,
		"granted":  granted,
		"revoked":  revoked,
	})
}

// groupAdminNames, şu an yetkisi GRUPTAN gelen yöneticiler.
func (s *Server) groupAdminNames(ctx context.Context) ([]string, error) {
	holders, err := s.store.Admins(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(holders))
	for _, h := range holders {
		if h.Via == "group" {
			out = append(out, h.Username)
		}
	}
	return out, nil
}

/*
 * refuseIfLastAdmin, işlem sonunda hiç yönetici kalmayacaksa reddeder.
 *
 * Veriyi TOPLAR, kararı vermez: karar wouldLeaveNoAdmin'de ve orada
 * durmasının sebebi sınanabilirlik — bu koşulun yanlış olması, panelin
 * kendini kilitlemesi ya da kilitlenmeyi yanlışlıkla engellemesi demek
 * ve ikisi de veritabanı gerektirmeden ölçülebilmeli.
 */
func (s *Server) refuseIfLastAdmin(ctx context.Context, want []string) error {
	holders, err := s.store.Admins(ctx)
	if err != nil {
		return err
	}

	// ⚠️ Yalnızca postern HESABI OLAN üyeler sayılıyor. Hesabı olmayanın
	// yetkisi ancak ilk girişinde oluşur ve "birileri bir gün girer" bir
	// yönetici değil: aradaki sürede panelin yöneticisi yok demektir.
	withAccounts := make([]string, 0, len(want))
	for _, name := range want {
		if _, err := s.store.UserByNameFold(ctx, name); err == nil {
			withAccounts = append(withAccounts, name)
		}
	}

	if !wouldLeaveNoAdmin(holders, withAccounts) {
		return nil
	}
	return errors.New("this would leave postern with no administrator at all — " +
		"create one on the bastion host first (`postern admin issue --name <name>`), " +
		"or pick a group that has at least one member with a postern account")
}

/*
 * wouldLeaveNoAdmin, eşitleme sonrası ortada yönetici kalmayacak mı?
 *
 * Hayatta kalanlar: yetkisi GRUPTAN GELMEYEN yöneticiler (CLI'ınki ve
 * 017 öncesinden kalma kaynaksız kayıtlar — ikisine de bu mantık
 * dokunmuyor) artı yeni grubun hesabı olan üyeleri.
 *
 * Kaçınılan durum somut: grubu temizlemek ya da kimsenin çözülmediği
 * bir gruba geçmek bütün grup yöneticilerini düşürür. Geriye CLI
 * yöneticisi de kalmıyorsa postern yönetici olmadan kalır ve tek çıkış,
 * ürünün bütün amacı olan "kurulumdan sonra sunucuya girmemek"i
 * bozmaktır.
 */
func wouldLeaveNoAdmin(holders []store.AdminHolder, wantWithAccounts []string) bool {
	for _, h := range holders {
		if h.Via != "group" {
			return false
		}
	}
	return len(wantWithAccounts) == 0
}

/*
 * sameNameSet, iki ad kümesini SIRADAN VE YAZIMDAN bağımsız karşılaştırır.
 *
 * Harf duyarsız, çünkü dizin adları öyle sayıyor ve panelin gösterdiği
 * yazımın sunucununkiyle harfi harfine aynı olmasını şart koşmak,
 * gerçek bir onayı sahte bir farkla reddederdi. Sıra duyarsız, çünkü
 * listenin sırası bir bilgi taşımıyor.
 */
func sameNameSet(a, b []string) bool {
	norm := func(in []string) map[string]bool {
		out := make(map[string]bool, len(in))
		for _, v := range in {
			v = strings.ToLower(strings.TrimSpace(v))
			if v != "" {
				out[v] = true
			}
		}
		return out
	}
	x, y := norm(a), norm(b)
	if len(x) != len(y) {
		return false
	}
	for k := range x {
		if !y[k] {
			return false
		}
	}
	return true
}
