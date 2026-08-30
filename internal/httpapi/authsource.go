package httpapi

// Aktif giriş kaynağı: hangi kapının açık olduğu, ve onu değiştirmenin
// kilitlenmeye dönüşmemesi için gereken kontroller.

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ldap"
)

/*
 * loginSource, panelin kapısını hangi kaynağın açtığı.
 *
 * ⚠️ HER İSTEKTE OKUNUYOR, önbelleğe alınmıyor. Kaynak panelden ya da
 * host'tan değişebiliyor ve yakalanmış bir "açık", kapatıldıktan sonra
 * da kimlik bilgisi kabul etmeye devam ederdi — acil çıkışın en çok
 * gerektiği anda çalışmaması demek.
 */
func (s *Server) loginSource(ctx context.Context) (auth.LoginSource, bool, error) {
	return auth.ActiveLoginSource(ctx, s.store, s.oidc != nil)
}

/*
 * sourceOrRefuse, kaynağı okur; okunamazsa isteği DÜŞÜRÜR.
 *
 * Hata hâlinde bir varsayılana düşmüyoruz: hangi kapının açık olduğunu
 * bilmeden kimlik bilgisi kabul etmek, kapalı sanılan bir kapıyı açık
 * tutmak olabilirdi.
 */
func (s *Server) sourceOrRefuse(w http.ResponseWriter, r *http.Request) (auth.LoginSource, bool) {
	src, _, err := s.loginSource(r.Context())
	if err != nil {
		s.logger.Error("login source unreadable", "error", err)
		writeErr(w, http.StatusServiceUnavailable,
			"postern cannot tell which sign-in method is active right now")
		return "", false
	}
	return src, true
}

// --- yönetim uçları ---

func (s *Server) registerAuthSourceRoutes(mux *http.ServeMux) {
	admin := func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	}
	mux.Handle("GET /api/admin/auth/source", admin(s.adminAuthSourceStatus))
	mux.Handle("POST /api/admin/auth/source", admin(s.adminAuthSourceSet))
}

/*
 * adminAuthSourceStatus: GET /api/admin/auth/source
 *
 * Aktif kaynak, seçilmiş mi yoksa türetilmiş mi, ve her seçeneğin ŞU AN
 * seçilebilir olup olmadığı — seçilemiyorsa NEDEN.
 *
 * Sebebi de dönmek zorunda: "OIDC" seçeneğini gri gösterip susmak,
 * operatöre config dosyasında ne eksik olduğunu aratırdı.
 */
func (s *Server) adminAuthSourceStatus(w http.ResponseWriter, r *http.Request) {
	src, stored, err := s.loginSource(r.Context())
	if err != nil {
		s.storeErr(w, "auth.source", err)
		return
	}

	type option struct {
		Source   string `json:"source"`
		Eligible bool   `json:"eligible"`
		Why      string `json:"why,omitempty"`
	}
	opts := make([]option, 0, 3)
	for _, cand := range []auth.LoginSource{auth.SourceLocal, auth.SourceOIDC, auth.SourceLDAP} {
		o := option{Source: string(cand), Eligible: true}
		if werr := s.canSwitchTo(r.Context(), cand); werr != nil {
			o.Eligible, o.Why = false, werr.Error()
		}
		opts = append(opts, o)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"source":  string(src),
		"stored":  stored,
		"options": opts,
	})
}

/*
 * adminAuthSourceSet: POST /api/admin/auth/source
 *
 * ⚠️ ÜRÜNÜN EN KİLİTLENME EĞİLİMLİ İŞLEMİ. Yanlış kaynağa geçmek,
 * paneli herkese — düzeltecek kişiye de — kapatır. Bu yüzden panel
 * yolunda kontroller SERT: geçilecek kaynağın gerçekten birini içeri
 * alabildiği KANITLANMADAN geçiş yapılmıyor.
 *
 * Aynı kontroller CLI'da YOK ve bu bilinçli: host'a erişebilen kişi
 * zaten en yüksek güven seviyesinde ve acil çıkış yolunun bir dizine ya
 * da bir yapılandırmaya bağlı olmaması onun bütün anlamı.
 */
func (s *Server) adminAuthSourceSet(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Source string `json:"source"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	want, err := auth.ParseLoginSource(in.Source)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if werr := s.canSwitchTo(r.Context(), want); werr != nil {
		writeErr(w, http.StatusBadRequest, werr.Error())
		return
	}

	if err := s.store.SetSetting(r.Context(), auth.KeyLoginSource,
		string(want), false, sessionUser(r)); err != nil {
		s.storeErr(w, "auth.source", err)
		return
	}

	s.audit(r, "auth.source_changed", string(want),
		"panel sign-in now goes through "+string(want))
	s.logger.Warn("login source changed", "actor", sessionUser(r), "source", want)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"source": string(want),
		// Kendi oturumunu kapatmış olabilir: SÖYLE. Kapatmadıysa da
		// zararsız, kapattıysa ekranda tek açıklama bu olacak.
		"note": "existing sessions keep working; the next sign-in goes through " +
			string(want),
	})
}

/*
 * canSwitchTo, bu kaynağa geçmek birini içeri alabilir mi?
 *
 * Her dal, o kaynağın kapısını AÇIKÇA açabildiğini kanıtlıyor. "Herhâlde
 * çalışır" yeterli değil: bu kontrolün yanlış olması, panelin bir daha
 * hiç açılmaması demek.
 */
func (s *Server) canSwitchTo(ctx context.Context, want auth.LoginSource) error {
	switch want {
	case auth.SourceLocal:
		/*
		 * ⚠️ YERELE DÖNMEK DE KİLİTLEYEBİLİR ve bu sezgiye aykırı
		 * olduğu için asıl tehlikeli olan. Yerel kapı yalnızca yerel
		 * kimlik bilgisi OLAN hesapları alıyor; gruptan yönetici olmuş
		 * herkes o kapıdan giremez. Yerel yöneticisi olmayan bir
		 * kurulumda "yerele dön" demek, panelin kapanması demek.
		 */
		holders, err := s.store.LocalCredentialHolders(ctx)
		if err != nil {
			return err
		}
		for _, h := range holders {
			if h.IsAdmin {
				return nil
			}
		}
		return errors.New("no local administrator has a sign-in secret — " +
			"run `postern admin issue <name>` on the bastion host first, " +
			"otherwise switching to local sign-in closes the panel for everyone")

	case auth.SourceOIDC:
		if s.oidc == nil {
			return errors.New("the identity provider is not configured in the config file " +
				"(oidc.issuer_url); postern cannot open a door it has no address for")
		}
		if strings.TrimSpace(s.adminGroupName(ctx)) == "" {
			return errors.New("no administrator group is set — with OIDC sign-in, " +
				"administrator comes only from a group claim, so without one " +
				"nobody could administer postern")
		}
		/*
		 * ⚠️ BURADA DURUYORUZ ve durduğumuzu arayüz söylemek zorunda.
		 * Bir claim'e "bu grupta kimler var" diye sorulamaz — grup
		 * üyeliğini ancak kişi giriş yaparken, tek tek öğreniyoruz.
		 * Yani LDAP'ta yaptığımız "en az bir kişi gerçekten içeri
		 * girebiliyor" kanıtı burada ÜRETİLEMİYOR.
		 */
		return nil

	case auth.SourceLDAP:
		if _, err := ldap.SourceFromStore(ctx, s.store); err != nil {
			if errors.Is(err, ldap.ErrNotConfigured) {
				return errors.New("the directory is not configured yet")
			}
			return errors.New("the directory configuration is not usable: " + err.Error())
		}
		group := strings.TrimSpace(s.adminGroupName(ctx))
		if group == "" {
			return errors.New("no administrator group is set — with directory sign-in, " +
				"administrator comes only from a group, so without one " +
				"nobody could administer postern")
		}
		/*
		 * ⚠️ BURASI GERÇEKTEN KANITLANABİLİR, o yüzden kanıtlanıyor.
		 *
		 * Dizin kapısı JIT hesap açmıyor: yalnızca postern'de HESABI
		 * OLAN dizin kullanıcıları girebiliyor. Dolayısıyla "yönetici
		 * grubunda birileri var" yetmez — o kişilerden en az birinin
		 * postern hesabı da olmalı. Yoksa geçiş, kimsenin giremediği
		 * bir panel üretir.
		 */
		pv, err := s.previewAdminGroup(ctx, group)
		if err != nil {
			return errors.New("the directory could not be asked who is in " + group +
				": " + err.Error())
		}
		for _, name := range pv.Admins {
			if _, uerr := s.store.UserByNameFold(ctx, name); uerr == nil {
				return nil
			}
		}
		return errors.New("nobody in " + group + " has a postern account yet, and the " +
			"directory door does not create accounts — switching now would leave " +
			"the panel with no administrator who can sign in")
	}
	return auth.ErrUnknownSource
}
