package httpapi

/*
 * TOTP ikinci faktörü — kendi hesabını yöneticisiz yönetebilmek için.
 *
 * NEDEN VAR: ikinci bir SSH anahtarı eklemek yeniden kimlik doğrulama
 * istiyor (mykeys.go: "ikinci anahtar eklemek, saldırganın kalıcılık
 * kurma hamlesinin ta kendisi"). Ama postern'in yalnızca YEREL parolayı
 * doğrulayabilmesi, dizinden ya da kimlik sağlayıcıdan gelen hesaplara
 * "yöneticine sor" demek anlamına geliyordu — yani dizin kullanan
 * kurumlarda, yani asıl hedef kurulumda, kimse kendi anahtarını
 * yönetemiyordu.
 *
 * ⚠️ İKİNCİ FAKTÖR BAĞLAMAK, KORUMANIN KENDİSİNİ ATLATMANIN YOLU
 * OLMAMALI. Kayıt sıradan bir oturumla yapılabilseydi, panel oturumunu
 * çalan biri önce TOTP bağlar, sonra onunla anahtar ekler ve tam da
 * engellenmek istenen kalıcılığı kurardı — üstelik "ikinci faktörü var"
 * diye daha güvenli görünen bir hesapta. Bu yüzden kayıt, anahtar
 * eklemekle AYNI kanıtı istiyor:
 *
 *   - Yerel sırrı olan hesap → sırrı yazar.
 *   - Olmayan hesap (SSO/dizin) → TAZE bir oturum ister; yani kişi az
 *     önce kimlik sağlayıcısında kimliğini kanıtlamış olmalı. 12 saat
 *     yaşayan bir belirteci çalan biri bunu sağlayamaz.
 */

import (
	"errors"
	"net/http"
	"time"

	"github.com/warewave/postern/internal/qr"
	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/totp"
)

/*
 * enrollFreshness, sırrı olmayan hesaplarda kayıt için istenen tazelik.
 *
 * ⚠️ Bu bir kolaylık ayarı değil, korumanın kendisi. Uzun tutmak
 * ("bir saat olsun") çalınmış bir oturumun kayıt yapabileceği pencereyi
 * aynı oranda açar. Kısa tutmak kullanıcıya yalnızca "yeniden giriş
 * yap" dedirtiyor; ikisi arasındaki denge simetrik değil.
 */
const enrollFreshness = 10 * time.Minute

// totpIssuer, kimlik doğrulayıcı uygulamasında görünecek ad.
const totpIssuer = "postern"

// routeTOTP, uçları bağlar.
//
// Yazma uçları same-origin: siteler arası bir POST, kurbanın hesabına
// ikinci faktör bağlatmaya ya da onunkini kapatmaya çalışabilirdi —
// anahtar uçlarındaki gerekçenin aynısı.
func (s *Server) routeTOTP(mux *http.ServeMux) {
	mux.Handle("GET /api/me/totp",
		noStore(s.requireSession(http.HandlerFunc(s.handleTOTPStatus))))
	mux.Handle("POST /api/me/totp/begin",
		s.requireSession(s.sameOrigin(http.HandlerFunc(s.handleTOTPBegin))))
	mux.Handle("POST /api/me/totp/confirm",
		s.requireSession(s.sameOrigin(http.HandlerFunc(s.handleTOTPConfirm))))
	mux.Handle("POST /api/me/totp/disable",
		s.requireSession(s.sameOrigin(http.HandlerFunc(s.handleTOTPDisable))))
}

// handleTOTPStatus: GET /api/me/totp
func (s *Server) handleTOTPStatus(w http.ResponseWriter, r *http.Request) {
	name := sessionUser(r)

	c, err := s.store.TOTP(r.Context(), name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusOK, map[string]any{
			"enrolled":  false,
			"pending":   false,
			"can_begin": s.canBeginTOTP(r),
			// Sırrı olmayan hesap için kaydın NEDEN mümkün olduğu ya da
			// olmadığı panelde yazacak: kullanıcı boş yere denemesin.
			"needs_fresh_login": !s.canReauth(r.Context(), name),
		})
		return
	case err != nil:
		s.storeErr(w, "me.totp", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enrolled":          c.Confirmed,
		"pending":           !c.Confirmed,
		"confirmed_at":      stampOrEmpty(c.ConfirmedAt),
		"last_used_at":      stampOrEmpty(c.LastUsedAt),
		"can_begin":         s.canBeginTOTP(r),
		"needs_fresh_login": !s.canReauth(r.Context(), name),
	})
}

/*
 * canBeginTOTP, bu istekle kayıt başlatılabilir mi.
 *
 * İki yoldan biri yeter: hesabın doğrulanabilir bir yerel sırrı var
 * (o zaman sır sorulacak) ya da oturum TAZE.
 */
func (s *Server) canBeginTOTP(r *http.Request) bool {
	if s.canReauth(r.Context(), sessionUser(r)) {
		return true
	}
	return s.sessionIsFresh(r)
}

// sessionIsFresh, oturumun az önce açılıp açılmadığı.
func (s *Server) sessionIsFresh(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	age, err := s.webSessions.Age(c.Value)
	if err != nil {
		// ⚠️ Bilinmeyen tazelik TAZE SAYILMIYOR: hata durumunda
		// varsayılan reddetmek, bu dosyanın bütün gerekçesi.
		return false
	}
	return age <= enrollFreshness
}

// handleTOTPBegin: POST /api/me/totp/begin
func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	name := sessionUser(r)

	var in struct {
		// Reauth, yerel sırrı olan hesaplarda istenen değer.
		Reauth string `json:"reauth"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	if !s.authoriseEnrollment(w, r, name, in.Reauth) {
		return
	}

	secret, err := totp.NewSecret()
	if err != nil {
		s.logger.Error("totp secret generation failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "could not start enrolment")
		return
	}

	if err := s.store.BeginTOTP(r.Context(), name, secret); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict,
				"this account already has an authenticator; turn the existing "+
					"one off before enrolling a new one")
			return
		}
		s.storeErr(w, "me.totp.begin", err)
		return
	}

	if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
		Actor: name, Via: "web", Action: "user.totp_begin", Entity: name,
		Details: "authenticator enrolment started",
	}); aerr != nil {
		s.logger.Error("audit write failed", "error", aerr)
	}

	uri := totp.URI(totpIssuer, name, secret)

	/*
	 * QR, kayıt bağlantısının modül matrisi.
	 *
	 * ⚠️ SUNUCUDA ÜRETİLİYOR, PANELDE DEĞİL. Kodlayıcı burada bağımsız
	 * bir uygulamaya (Apple CoreImage) karşı bit bit doğrulanıyor
	 * (internal/qr); panele ikinci bir kodlayıcı koymak, ikinci bir
	 * doğrulama yükü ve sessizce ayrışabilecek iki gerçek demek olurdu.
	 *
	 * ⚠️ ÜRETİLEMEZSE KAYIT DÜŞMÜYOR. QR bir kolaylık; kurulum anahtarı
	 * ve otpauth bağlantısı zaten dönüyor ve ikisi de tek başına
	 * yeterli. Kolaylığın arızası, kullanıcıyı hesabından etmemeli.
	 */
	var rows []string
	if m, qerr := qr.Encode(uri, qr.M); qerr != nil {
		s.logger.Error("totp qr could not be rendered",
			"user", name, "error", qerr)
	} else {
		rows = make([]string, len(m))
		for y, line := range m {
			b := make([]byte, len(line))
			for x, dark := range line {
				b[x] = '0'
				if dark {
					b[x] = '1'
				}
			}
			rows[y] = string(b)
		}
	}

	/*
	 * ⚠️ SIR YALNIZCA BURADA, YALNIZCA BİR KEZ DÖNÜYOR. Durum ucundan
	 * okunabilseydi, oturumu çalan biri onu alıp kendi telefonuna
	 * kurar ve ikinci faktör hiçbir şey korumaz hâle gelirdi.
	 */
	writeJSON(w, http.StatusOK, map[string]any{
		"secret": secret,
		"uri":    uri,
		"qr":     rows,
	})
}

/*
 * authoriseEnrollment, kayıt için kanıtı denetler.
 *
 * Sıra önemli: yerel sır VARSA o isteniyor. Taze oturum, yalnızca
 * doğrulanacak bir sır YOKKEN kabul edilen yol — aksi hâlde parolası
 * olan bir hesapta, taze bir oturum parolayı gereksiz kılardı.
 */
func (s *Server) authoriseEnrollment(w http.ResponseWriter, r *http.Request, name, reauth string) bool {
	if s.canReauth(r.Context(), name) {
		return s.checkLocalSecret(w, r, name, reauth, "totp_enroll")
	}
	if s.sessionIsFresh(r) {
		return true
	}
	writeErr(w, http.StatusForbidden,
		"sign in again and then enrol — linking an authenticator needs a "+
			"recent sign-in, so that a stolen session cannot add one")
	return false
}

// handleTOTPConfirm: POST /api/me/totp/confirm
func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	name := sessionUser(r)

	var in struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	c, err := s.store.TOTP(r.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusConflict, "start enrolment first")
			return
		}
		s.storeErr(w, "me.totp.confirm", err)
		return
	}
	if c.Confirmed {
		writeErr(w, http.StatusConflict, "this authenticator is already active")
		return
	}

	ok, step, verr := totp.Verify(c.Secret, in.Code, time.Now())
	if verr != nil {
		s.logger.Error("stored totp secret is unusable", "user", name, "error", verr)
		writeErr(w, http.StatusInternalServerError, "enrolment is broken; start again")
		return
	}
	if !ok {
		writeErr(w, http.StatusUnauthorized, "wrong code")
		return
	}

	if err := s.store.ConfirmTOTP(r.Context(), name, step); err != nil {
		s.storeErr(w, "me.totp.confirm", err)
		return
	}
	if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
		Actor: name, Via: "web", Action: "user.totp_enabled", Entity: name,
		Details: "authenticator confirmed and active",
	}); aerr != nil {
		s.logger.Error("audit write failed", "error", aerr)
	}
	w.WriteHeader(http.StatusNoContent)
}

/*
 * handleTOTPDisable: POST /api/me/totp/disable
 *
 * ⚠️ KAPATMAK BİR KOD İSTİYOR. İstemeseydi, oturumu çalan biri ikinci
 * faktörü kapatıp yerine kendininkini bağlardı — yani faktör, onu
 * atlatmak isteyen için bir engel olmaktan çıkardı.
 *
 * Telefonunu kaybeden kişi kilitlenmiyor: yönetici sıfırlayabiliyor ve
 * bu denetim kaydına düşüyor.
 */
func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	name := sessionUser(r)

	var in struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	if !s.spendTOTP(w, r, name, in.Code) {
		return
	}

	if err := s.store.DisableTOTP(r.Context(), name); err != nil {
		s.storeErr(w, "me.totp.disable", err)
		return
	}
	if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
		Actor: name, Via: "web", Action: "user.totp_disabled", Entity: name,
		Details: "authenticator removed by its owner",
	}); aerr != nil {
		s.logger.Error("audit write failed", "error", aerr)
	}
	w.WriteHeader(http.StatusNoContent)
}

/*
 * spendTOTP, kodu doğrular ve adımı TÜKETİR.
 *
 * ⚠️ TÜKETMEK ŞART. Aynı kod 30 saniye geçerli; omuz üstünden okuyan ya
 * da araya giren biri onu ikinci kez kullanabilir — ve bu bağlamda
 * ikinci kullanım "bir anahtar daha ekle" demek. Adımı harcamak,
 * doğrulamayla AYNI yerde yapılıyor ki çağıranlardan biri unutmasın.
 */
func (s *Server) spendTOTP(w http.ResponseWriter, r *http.Request, name, code string) bool {
	c, err := s.store.TOTP(r.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusForbidden, "this account has no authenticator")
			return false
		}
		s.storeErr(w, "me.totp", err)
		return false
	}
	if !c.Confirmed {
		writeErr(w, http.StatusForbidden, "finish enrolment first")
		return false
	}

	// Tahmin hızını sınırlayan kova, parola kapısıyla ORTAK: iki uç
	// arasında dönüşümlü deneyerek sınırı atlatmak mümkün olmasın.
	if !s.localLimit.allow(s.clientKey(r)) {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many attempts; try again in a minute")
		return false
	}
	bkey := backoffKey(name, s.clientKey(r))
	if wait := s.guessBackoff.retryAfter(bkey); wait > 0 {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts from here")
		return false
	}

	ok, step, verr := totp.Verify(c.Secret, code, time.Now())
	if verr != nil {
		s.logger.Error("stored totp secret is unusable", "user", name, "error", verr)
		writeErr(w, http.StatusInternalServerError, "authenticator is broken; ask an administrator to reset it")
		return false
	}
	if !ok {
		s.guessBackoff.fail(bkey)
		s.logger.Warn("totp code refused", "user", name)
		writeErr(w, http.StatusUnauthorized, "wrong code")
		return false
	}

	if err := s.store.UseTOTPStep(r.Context(), name, step); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// Tekrar edilmiş kod: bunu "yanlış kod"tan AYIRIYORUZ,
			// çünkü kullanıcının yapması gereken farklı — bir sonraki
			// kodu beklemek.
			s.logger.Warn("totp code replayed", "user", name)
			writeErr(w, http.StatusUnauthorized,
				"that code has already been used; wait for the next one")
			return false
		}
		s.storeErr(w, "me.totp", err)
		return false
	}
	s.guessBackoff.succeed(bkey)
	return true
}

// stampOrEmpty, sıfır zamanı boş dizgiye çevirir: JSON'da "0001-01-01"
// görmek, panelde gerçek bir tarih sanılıyor.
func stampOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

/*
 * adminResetTOTP: POST /api/admin/users/{name}/totp/reset
 *
 * ⚠️ TELEFONUNU KAYBEDEN KİŞİNİN YOLU. Kurtarma kodları yok — bilinçli:
 * kullanıcının bir kenara yazacağı ikinci bir sır üretmek, korumayı o
 * kâğıdın güvenliğine bağlar. Onun yerine kurtarma, kimliği ZATEN
 * doğrulayabilen tarafa bırakılıyor: yönetici.
 *
 * Sıfırlama denetim kaydına düşüyor. Düşmeseydi, ikinci faktörü sessizce
 * kaldırıp yerine kendininkini bağlamak, yönetici yetkisi olan biri için
 * izsiz bir hamle olurdu.
 */
func (s *Server) adminResetTOTP(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	actor := sessionUser(r)

	if err := s.store.DisableTOTP(r.Context(), name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// 404 değil 409: kullanıcı var, ikinci faktörü yok.
			// 404 dönmek yöneticiye "böyle bir kullanıcı yok"
			// dedirtirdi.
			writeErr(w, http.StatusConflict, "this account has no authenticator")
			return
		}
		s.storeErr(w, "admin.totp.reset", err)
		return
	}

	if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
		Actor: actor, Via: "web", Action: "user.totp_reset", Entity: name,
		Details: "authenticator removed by an administrator",
	}); aerr != nil {
		s.logger.Error("audit write failed", "error", aerr)
	}
	w.WriteHeader(http.StatusNoContent)
}
