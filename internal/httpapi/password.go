package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * Kendi parolamı değiştirmek.
 *
 * ⚠️ BU UÇ, ZORUNLU DEĞİŞİKLİK KISITINDAN ÇIKIŞIN TEK YOLU
 * (weblogin.go'daki changePasswordAllowed). Dolayısıyla kısıtlı bir
 * oturumun ulaşabildiği İKİ uçtan biri ve buradaki her kontrol, o
 * kısıtın anlamının tamamı.
 */

// handleChangePassword: POST /api/me/password
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	name := sessionUser(r)
	log := s.logger.With("user", name, "remote", r.RemoteAddr)

	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	cred, err := s.store.LocalCredential(r.Context(), name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		/*
		 * postern'in doğrulayabileceği bir değeri yok: kimliği
		 * dizinden ya da kimlik sağlayıcıdan geliyor. Uydurma bir
		 * parola yaratmıyoruz — kişinin parolası ORADA yaşıyor ve
		 * postern'de ikinci bir tane açmak, tam olarak kaçındığımız
		 * şey.
		 */
		writeErr(w, http.StatusConflict,
			"this account signs in through your organisation, so postern has no password to change")
		return
	case err != nil:
		s.storeErr(w, "me.password", err)
		return
	}

	/*
	 * ⚠️ MEVCUT DEĞER SORULUYOR — ZORUNLU DEĞİŞİKLİKTE DE.
	 *
	 * Kapattığı açık somut: bu ekranın göründüğü an, tam olarak
	 * değerin İKİ kişinin elinde olduğu an. Yönetici onu sohbete
	 * yapıştırmış, telefonda okumuş ya da ekranda bırakmış olabilir.
	 * Mevcut değer sorulmasaydı, o değeri gören herkes tek istekle
	 * parolayı KENDİ seçtiğine çevirip hesabı kalıcı olarak alırdı —
	 * yani zorunlu değişiklik, devralmayı zorlaştırmak yerine
	 * kolaylaştırırdı.
	 *
	 * Aynı gerekçe bir dosya ötede yazılı: ikinci anahtarı eklemek de
	 * yeniden doğrulama istiyor (mykeys.go).
	 */
	if !s.localLimit.allow(s.clientKey(r)) {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many attempts; try again in a minute")
		return
	}
	// Gecikme kovası giriş kapısıyla ORTAK: aynı değeri doğruluyoruz,
	// ayrı kova tutmak tahmin edene ikinci bir pencere açardı.
	bkey := backoffKey(name, s.clientKey(r))
	if wait := s.guessBackoff.retryAfter(bkey); wait > 0 {
		secs := int(wait.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf(
			"too many failed attempts from here; try again in %d seconds", secs))
		return
	}

	/*
	 * ⚠️ TEK YUVA, İKİ ARGON2.
	 *
	 * Bu, argon2'yi iki kez çalıştıran tek işleyici: önce mevcut değer
	 * doğrulanıyor, sonra yenisi hash'leniyor. İkisi ARDIŞIK, yani
	 * anlık bellek tepe noktası yine bir hash'lik; ama çöp toplayıcı
	 * araya girmezse geçici olarak iki katı ayrılmış olabilir. Yuva
	 * sayısı (localLoginSlots) bunun için bir kez alınıyor ve işleyici
	 * bitene kadar tutuluyor: iki ayrı alıp bırakmak, aradaki boşlukta
	 * tavanı aşmaya izin verirdi.
	 */
	select {
	case s.localSlots <- struct{}{}:
		defer func() { <-s.localSlots }()
	default:
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "busy; try again shortly")
		return
	}

	if !verifyCredential(cred, in.Current) {
		if cred.Chosen {
			s.guessBackoff.fail(bkey)
		}
		log.Warn("password change refused: current value wrong")
		if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
			Actor: name, Via: "web", Action: "user.password_change_failed", Entity: name,
			Details: "the current value did not match",
		}); aerr != nil {
			log.Error("audit write failed", "error", aerr)
		}
		writeErr(w, http.StatusUnauthorized, "the current password is wrong")
		return
	}
	s.guessBackoff.succeed(bkey)

	/*
	 * ⚠️ POLİTİKA KONTROLÜ DOĞRULAMADAN SONRA.
	 *
	 * Sıra bir sızıntı kapatıyor: önce politika bakılsaydı, mevcut
	 * değeri BİLMEYEN biri de "bu parola zayıf" ile "bu parola güçlü
	 * ama mevcut değerin yanlış" arasındaki farkı görebilirdi. Ufak bir
	 * kanal ama bedava kapanıyor.
	 */
	policy := auth.LoadPasswordPolicy(r.Context(), s.store)
	if perr := policy.Check(in.New, name); perr != nil {
		writeErr(w, http.StatusBadRequest, perr.Error())
		return
	}

	// Aynı değeri yeniden koymak, zorunlu değişikliği hiç yapmamakla
	// aynı şey: veren kişi hâlâ biliyor.
	if verifyCredential(cred, in.New) {
		writeErr(w, http.StatusBadRequest,
			"the new password must be different from the current one")
		return
	}

	verifier, err := auth.HashPassword(in.New)
	if err != nil {
		log.Error("password hash failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "could not set the password")
		return
	}

	if err := s.store.SetChosenPassword(r.Context(), name, verifier, time.Now()); err != nil {
		if errors.Is(err, store.ErrAdminPasswordRefused) {
			/*
			 * Kural veritabanında (göç 026) ve buraya bir kopyası
			 * YAZILMADI. Yönetici hesabı, acil durum kapısı olduğu için
			 * makine üretimi bir değere bağlı kalmak zorunda.
			 */
			writeErr(w, http.StatusConflict,
				"administrator accounts keep a machine-generated secret and cannot use a password; "+
					"rotate it on the host with `postern admin revoke` then `postern admin issue`")
			return
		}
		s.storeErr(w, "me.password", err)
		return
	}

	/*
	 * ⚠️ DİĞER OTURUMLAR DÜŞÜYOR VE KENDİ BELİRTECİMİZ YENİLENİYOR.
	 *
	 * Parola değiştirmenin amacı budur: eski değeri bilen biri varsa,
	 * onun açtığı oturum ayakta kalırsa değiştirmek hiçbir işe yaramaz
	 * — saldırgan zaten içeride ve 12 saat daha içeride kalır.
	 *
	 * Kendi belirtecimizi de yeniliyoruz: değişiklikten önce açılmış
	 * bir oturumun sonrasında da geçerli kalması, sabitleme (fixation)
	 * saldırısına açık bırakırdı.
	 */
	dropped := s.webSessions.DestroyUser(name)
	token, err := s.createLocalWebSession(r.Context(), name)
	if err != nil {
		log.Error("session rotate failed", "error", err)
		// Parola DEĞİŞTİ; oturum verilemedi. Dürüst olan şey bunu
		// söylemek — "başarısız" demek, kişiyi eski parolayla yeniden
		// denemeye gönderirdi.
		s.clearSessionCookie(w)
		writeErr(w, http.StatusInternalServerError,
			"your password was changed, but the session could not be renewed — please sign in again")
		return
	}
	// #nosec G124 -- Secure koşullu: bkz. Server.SetExternalURL
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookies || r.TLS != nil,
	})

	if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
		Actor: name, Via: "web", Action: "user.password_changed", Entity: name,
		Details: fmt.Sprintf("password set by the account holder; %d other session(s) dropped",
			maxInt(dropped-1, 0)),
	}); aerr != nil {
		log.Error("audit write failed", "error", aerr)
	}
	log.Info("password changed", "sessions_dropped", dropped)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

/*
 * adminIssueCredential: POST /api/admin/users/{name}/credential
 *
 * Panelden yerel giriş bilgisi verir. Değer BİR KEZ dönüyor ve hiçbir
 * yerde saklanmıyor.
 */
func (s *Server) adminIssueCredential(w http.ResponseWriter, r *http.Request) {
	actor := sessionUser(r)
	target := r.PathValue("name")

	u, err := s.store.User(r.Context(), target)
	if err != nil {
		s.storeErr(w, "admin.credential", err)
		return
	}

	/*
	 * ⚠️ YÖNETİCİ HESABINA PANELDEN KİMLİK BİLGİSİ VERİLMİYOR.
	 *
	 * Kural, "yöneticilik panelden verilemez" kuralının aynısının
	 * devamı ve onsuz anlamsız: yöneticiliği panelden veremeyip
	 * yöneticinin GİRİŞ BİLGİSİNİ panelden verebilseydik, paneli ele
	 * geçiren kişi mevcut bir yöneticinin kimlik bilgisini kendi
	 * ürettiği bir değerle değiştirip onun yerine geçerdi — yani kural
	 * hiç yokmuş gibi olurdu.
	 *
	 * Buradaki kontrol MESAJ İÇİN. Asıl garanti store'un SQL'inde ve
	 * göç 026'nın kısıtında: bu `if` silinse bile işlem düşer.
	 */
	if u.Admin {
		writeErr(w, http.StatusConflict,
			"this account is an administrator: its credential is a break-glass secret and "+
				"is issued only on the host, with `postern admin issue --name "+u.Name+"`")
		return
	}

	/*
	 * ⚠️ SIRRI MAKİNE ÜRETİYOR, YÖNETİCİ SEÇMİYOR.
	 *
	 * Yöneticinin bir "geçici parola" yazmasına izin vermek iki şeyi
	 * birden bozardı: (1) operatörün seçtiği bir değer KDF'e ulaşırdı
	 * — kurumsal parolanın postern'e hiç girmemesini sağlayan biçim
	 * kontrolü, tam da bu kapıdan delinirdi; (2) yönetici, kişinin
	 * parolasını bilirdi ve zayıf bir değer seçebilirdi.
	 *
	 * Üretilen değer must_change ile doğuyor: kişi ilk girişte kendi
	 * parolasını koyuyor ve o andan sonra değeri yalnızca o biliyor.
	 */
	secret, verifier, err := auth.NewLocalSecret()
	if err != nil {
		s.logger.Error("secret generation failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "could not issue a credential")
		return
	}

	replaced, err := s.store.ReplaceLocalCredential(r.Context(), u.Name, verifier, actor)
	if err != nil {
		if errors.Is(err, store.ErrAdminPasswordRefused) {
			writeErr(w, http.StatusConflict,
				"this account cannot hold a panel-issued credential")
			return
		}
		s.storeErr(w, "admin.credential", err)
		return
	}

	/*
	 * ⚠️ ÜSTÜNE YAZILDIYSA ESKİ OTURUMLAR DÜŞÜYOR.
	 *
	 * Bu uç "kullanıcı parolasını unuttu" için de kullanılıyor ve o
	 * senaryonun kardeşi "hesabı ele geçirildi". Eski değerle açılmış
	 * bir oturum ayakta kalırsa, kimlik bilgisini değiştirmek hiçbir
	 * işe yaramaz — saldırgan zaten içeride.
	 */
	dropped := 0
	if replaced {
		dropped = s.webSessions.DestroyUser(u.Name)
	}

	action := "admin.credential_issued"
	detail := "local sign-in credential issued from the panel; must be changed on first use"
	if replaced {
		action = "admin.credential_replaced"
		detail = fmt.Sprintf(
			"local sign-in credential REPLACED from the panel; must be changed on first use; "+
				"%d session(s) dropped", dropped)
	}
	if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
		Actor: actor, Via: "web", Action: action, Entity: u.Name, Details: detail,
	}); aerr != nil {
		s.logger.Error("audit write failed", "error", aerr)
	}
	s.logger.Info("panel credential issued", "by", actor, "user", u.Name, "replaced", replaced)

	writeJSON(w, http.StatusOK, map[string]any{
		"username": u.Name,
		// ⚠️ TEK GÖSTERİM. Doğrulayıcı geri okunamaz; bu değer hiçbir
		// yerde saklanmıyor ve bir daha üretilemez.
		"secret":   secret,
		"replaced": replaced,
	})
}
