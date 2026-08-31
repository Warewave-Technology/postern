package httpapi

// Aktif giriş kaynağı: hangi kapının açık olduğu, ve onu değiştirmenin
// kilitlenmeye dönüşmemesi için gereken kontroller.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/store"
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
	return auth.ActiveLoginSource(ctx, s.store, s.oidc.Configured())
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
	// Kaynağı çevirmeden ÖNCE kendi dizin kimliğini bağlamanın yolu.
	mux.Handle("POST /api/admin/auth/bind-directory", admin(s.adminBindOwnDirectory))
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

	// ⚠️ Eşlemelerin YENİ kaynakta karşılığı var mı? Asıl risk
	// kaybolmaları değil — kaybolmuyorlar. Risk, YERİNDE KALIP
	// HİÇBİRİNİN EŞLEŞMEMESİ: LDAP "sysadmins" der, OIDC claim'i
	// bambaşka bir şey; sonuç "grup gelmiyor" ile birebir aynı görünür
	// ve herkes sessizce rolsüz kalır.
	stale, serr := s.staleMappings(r.Context())
	if serr != nil {
		s.logger.Error("mapping check failed", "error", serr)
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
		// Aktif kaynakta karşılığı GÖRÜLMEMİŞ eşlemeler.
		"unseen_mappings": stale,
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

	/*
	 * ⚠️ KAYNAĞI ÇEVİREN KİŞİ, KENDİ KAPISINI KAPATIYOR OLABİLİR.
	 *
	 * Yerel sırla girmiş bir yönetici OIDC'ye geçtiğinde yerel kapı
	 * kapanıyor ve o hesap — yönetici olduğu için — artık ad
	 * eşleşmesiyle devralınamıyor. Yani kurulumu yapan kişi kendini
	 * dışarıda bırakıyor.
	 *
	 * Dizin için çözüm temiz ve penceresiz: bind-directory ucu, oturum
	 * ZATEN açıkken kimliği bağlıyor.
	 *
	 * OIDC için tarayıcı turu gerekiyor ve onu kaynağı çevirmeden
	 * yapamıyoruz (kapı kapalı). O yüzden burada TEK KULLANIMLIK izin
	 * bırakıyoruz: bir sonraki IdP girişi bu hesabı sahiplenebilir.
	 * Pencere dar, denetleniyor ve arayüz "şimdi gir" diyor — ama
	 * penceresiz değil ve bunu saklamıyoruz.
	 */
	note := ""
	if want == auth.SourceOIDC {
		actor := sessionUser(r)
		bound, berr := s.store.HasIdPIdentity(r.Context(), actor)
		if berr != nil {
			s.storeErr(w, "auth.source", berr)
			return
		}
		if !bound {
			if aerr := s.store.AllowIdentityBind(r.Context(), actor, time.Now()); aerr != nil {
				s.storeErr(w, "auth.source", aerr)
				return
			}
			s.audit(r, "user.allow_bind", actor,
				"switching to the identity provider left this account unbound; "+
					"the next sign-in may claim it")
			note = "your own account is not linked to the identity provider yet. " +
				"Sign in through it now, as " + actor + ": the first sign-in claims " +
				"this account, once."
		}
	}

	if err := s.store.SetSetting(r.Context(), auth.KeyLoginSource,
		string(want), false, sessionUser(r)); err != nil {
		s.storeErr(w, "auth.source", err)
		return
	}

	s.audit(r, "auth.source_changed", string(want),
		"panel sign-in now goes through "+string(want))
	s.logger.Warn("login source changed", "actor", sessionUser(r), "source", want)

	if note == "" {
		// Kendi oturumunu kapatmış olabilir: SÖYLE. Kapatmadıysa da
		// zararsız, kapattıysa ekranda tek açıklama bu olacak.
		note = "existing sessions keep working; the next sign-in goes through " +
			string(want)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "source": string(want), "note": note,
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
		/*
		 * ⚠️ SAYMAK YETMEZ, HESABIN GERÇEKTEN GİREBİLİYOR OLMASI LAZIM.
		 *
		 * Ölçülen tutarsızlık: bu kontrol yalnızca "yerel kimlik
		 * bilgisi olan bir yönetici var mı" diye bakıyordu, ama
		 * locallogin.go SİLİNMİŞ hesabı reddediyor. Silinmiş bir
		 * yönetici bu kontrolü geçip paneli kimsenin giremediği bir
		 * duruma bırakabiliyordu — üstelik bu ekranın var olma sebebi
		 * tam olarak onu engellemek.
		 *
		 * Aynı sebeple must_change de saymıyor: o hesap girebiliyor ama
		 * parolasını değiştirene kadar HİÇBİR ŞEY yapamıyor, ve
		 * yapamadığı şeylerden biri kaynağı geri çevirmek. Zaten bir
		 * yönetici hiç must_change taşıyamaz (göç 026) — kontrol,
		 * kuralın bir gün değişmesi ihtimaline karşı burada.
		 */
		for _, h := range holders {
			if h.IsAdmin && h.State == store.StateActive && !h.MustChange {
				return nil
			}
		}
		return errors.New("no local administrator has a usable sign-in secret — " +
			"run `postern admin issue --name <name>` on the bastion host first, " +
			"otherwise switching to local sign-in closes the panel for everyone")

	case auth.SourceOIDC:
		if !s.oidc.Configured() {
			return errors.New("the identity provider is not configured yet — " +
				"set its address, client id and secret first")
		}
		// ⚠️ "Ayarlı" ile "çalışıyor" ayrı: ayarlı ama ulaşılamayan bir
		// sağlayıcıya geçmek, kimsenin giremediği bir panel bırakır.
		if !s.oidc.Live() {
			return errors.New("the identity provider is configured but postern " +
				"could not reach it; fix that before making it the way in")
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

/*
 * adminBindOwnDirectory: POST /api/admin/auth/bind-directory
 *
 * ⚠️ SİHİRBAZIN EN ÖNEMLİ ADIMI. Kaynağı dizine çeviren yönetici, yerel
 * kapısını kapatıyor; kendi dizin kimliğini ÖNCEDEN bağlamazsa geri
 * giremez — ve yönetici hesabı olduğu için ad eşleşmesiyle de
 * devralınamaz (ölçülmüş bir saldırı yüzünden, bkz. göç 020).
 *
 * ⚠️ NEDEN GÜVENLİ VE PENCERESİZ: bağlama, kimliği ZATEN doğrulanmış
 * bir oturumun içinde yapılıyor ve kişi dizin parolasını da veriyor.
 * İki taraf da o anda kanıtlanıyor — bir onay bayrağı, bir bekleme
 * penceresi ya da bir yarış yok. Kaynak çevrilmeden önce yapıldığı için
 * de kimse dışarıda kalmıyor.
 */
func (s *Server) adminBindOwnDirectory(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Username) == "" || in.Password == "" {
		writeErr(w, http.StatusBadRequest,
			"your directory username and password are both required")
		return
	}

	actor := sessionUser(r)

	res, err := ldap.AuthenticateFromStore(r.Context(), s.store, in.Username, in.Password)
	if err != nil {
		if errors.Is(err, ldap.ErrNotConfigured) {
			writeErr(w, http.StatusBadRequest, "the directory is not configured yet")
			return
		}
		s.logger.Error("bind-directory failed", "actor", actor, "error", err)
		writeErr(w, http.StatusServiceUnavailable,
			"the directory could not be reached; this is not a password problem")
		return
	}
	if res.Presence != ldap.PresencePresent || !res.Authenticated || res.Disabled {
		// Tek cevap, üç sebep — giriş kapısıyla aynı ketumluk.
		s.logger.Warn("bind-directory refused", "actor", actor, "user", in.Username)
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	if res.Identity == "" {
		writeErr(w, http.StatusBadRequest,
			"your directory does not publish a stable identity for this account "+
				"(objectGUID or entryUUID), so it cannot be linked; "+
				"check the directory test screen")
		return
	}

	if berr := s.store.BindDirIdentity(r.Context(), actor, res.Identity); berr != nil {
		if errors.Is(berr, store.ErrConflict) {
			writeErr(w, http.StatusConflict,
				"this account is already linked to a directory identity, "+
					"or that identity belongs to another account")
			return
		}
		s.storeErr(w, "auth.bind_directory", berr)
		return
	}

	s.audit(r, "user.dir_bind", actor,
		"linked to directory identity "+res.Identity+" from the setup screen")
	s.logger.Info("directory identity linked", "user", actor, "identity", res.Identity)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "identity": res.Identity, "directory_username": in.Username,
	})
}

/*
 * staleMappings, aktif kaynakta HİÇ GÖRÜLMEMİŞ grup eşlemelerini döner.
 *
 * ⚠️ NEDEN "GÖRÜLMEMİŞ", "YOK" DEĞİL: bir grubun kaynakta var olup
 * olmadığını genel olarak soramıyoruz (OIDC claim'i listelenemez, LDAP'ta
 * da grup adı serbest metin). Elimizdeki tek dürüst ölçüt, o grup adının
 * bugüne kadar HERHANGİ bir girişte görülmüş olması.
 *
 * Yani bu bir teşhis, bir iddia değil: "şu eşlemeleri yazdınız ama
 * kimse o grupla gelmedi". Kaynak değiştikten sonra bütün liste burada
 * belirir ve operatör sebebini görür.
 */
func (s *Server) staleMappings(ctx context.Context) ([]string, error) {
	mappings, err := s.store.GroupMappings(ctx)
	if err != nil {
		return nil, err
	}
	seen, err := s.store.SeenGroupNames(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]string, 0)
	for _, m := range mappings {
		found := false
		for _, g := range seen {
			if strings.EqualFold(strings.TrimSpace(g), strings.TrimSpace(m.ExternalGroup)) {
				found = true
				break
			}
		}
		if !found {
			out = append(out, m.ExternalGroup)
		}
	}
	return out, nil
}
