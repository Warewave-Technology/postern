package httpapi

import (
	"errors"
	"net/http"

	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/store"
)

/*
 * Dizin parolasıyla panel girişi.
 *
 * ⚠️ ÜRÜNÜN EN KESKİN İDDİASININ HARCANDIĞI YER. postern bugüne kadar
 * kullanıcının kurumsal parolasını hiç görmüyordu. Burası görüyor —
 * yalnızca PANELDE, yalnızca doğrulamak için, hiçbir yere yazmadan.
 * SSH kapısı parolayı hâlâ hiç kullanmıyor: orada anahtar var. Kurumsal
 * parola bilerek TEK bir kapıya hapsedildi.
 */

// directoryBindSlots, aynı anda yürütülebilecek bind sayısı.
//
// Yerel sırdaki argon2 yuvalarından AYRI: orada korunan şey postern'in
// belleği, burada korunan şey KURUMUN DİZİNİ. Her deneme taze bir
// TCP+TLS+bind demek (ldap.connect'te havuz yok) ve kimliği
// doğrulanmamış bir istek bunu tetikleyebiliyor.
const directoryBindSlots = 8

/*
 * directoryLogin, kullanıcıyı dizin parolasıyla doğrular ve oturum açar.
 *
 * Çağıran (handleLocalLogin) buraya yalnızca AKTİF KAYNAK dizinken
 * düşüyor. Yani burada hiçbir hesap adı yerel doğrulayıcıya, hiçbir
 * yerel sır dizine gitmiyor: hangi kapının açık olduğu isteğin
 * içeriğine değil, ayara bağlı.
 */
func (s *Server) directoryLogin(w http.ResponseWriter, r *http.Request,
	log logger, username, password string) {

	if !s.localLimit.allow(clientKey(r)) {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many sign-in attempts; try again in a minute")
		return
	}

	select {
	case s.bindSlots <- struct{}{}:
		defer func() { <-s.bindSlots }()
	default:
		// Kuyruk yerine RET: bekleyen istekler, saldırganın bedavaya
		// tutabileceği bir kaynak olurdu — üstelik kurumun dizinine
		// karşı.
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "sign-in is busy; try again shortly")
		return
	}

	res, err := ldap.AuthenticateFromStore(r.Context(), s.store, username, password)
	switch {
	case errors.Is(err, ldap.ErrEmptySecret):
		// Boş parola bind'e HİÇ ulaşmadı (kimliksiz bind tuzağı).
		// Dışarıya yine aynı cevap: hangi kontrolde düştüğü bilgisi
		// kimseye yaramaz.
		//
		// Denetim satırı YAZILIYOR: reddedilen her giriş iz bırakmalı,
		// yoksa "hiç denenmedi" ile "denendi ve reddedildi" ayrılamaz.
		// Kullanıcı adı ham yazılmıyor — hesabı hiç aramadık, yani
		// bilinen bir ad olduğunu söyleyemeyiz.
		log.Warn("directory login refused: empty password")
		if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
			Actor: "anonymous", Via: "local", Action: "auth.directory_denied",
			Entity: "unknown account", Details: "empty password (would be an unauthenticated bind)",
		}); aerr != nil {
			log.Error("audit write failed", "error", aerr)
		}
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	case errors.Is(err, ldap.ErrNotConfigured):
		log.Error("directory login attempted with no directory configured")
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return
	case err != nil:
		// ⚠️ ARIZA "YANLIŞ PAROLA" DEĞİLDİR. Dizin cevap veremiyorsa
		// kullanıcıya parolasının yanlış olduğunu söylemek, saatlerce
		// yanlış yerde arattırır.
		log.Error("directory login failed", "error", err)
		writeErr(w, http.StatusServiceUnavailable,
			"the directory could not be reached; this is not a password problem")
		return
	}

	if res.Presence != ldap.PresencePresent || !res.Authenticated || res.Disabled {
		/*
		 * ⚠️ TEK CEVAP, ÜÇ AYRI SEBEP. "Böyle bir kullanıcı yok",
		 * "parola yanlış" ve "hesap kapalı" dışarıya aynı görünüyor:
		 * ayrım, kimliği doğrulanmamış birine hesap keşfi imkânı
		 * verirdi. Ayrım LOGDA ve denetim kaydında duruyor.
		 */
		reason := "wrong password"
		switch {
		case res.Presence == ldap.PresenceAbsent:
			reason = "no such user in the directory"
		case res.Disabled:
			reason = "account is disabled in the directory: " + res.DisabledReason
		}
		log.Warn("directory login refused", "user", username, "reason", reason)

		// Denetim kaydına, bilinen bir hesap adı olmadıkça ham kullanıcı
		// adı YAZILMIYOR — parola kutusuna yanlış alan yazan operatörün
		// değeri kalıcı bir tabloya düşmesin.
		entity := "unknown account"
		if res.Presence == ldap.PresencePresent {
			entity = username
		}
		if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
			Actor: "anonymous", Via: "local", Action: "auth.directory_denied",
			Entity: entity, Details: reason,
		}); aerr != nil {
			log.Error("audit write failed", "error", aerr)
		}
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}

	/*
	 * Kimlik doğrulandı. Hesabı postern'de kurmak/ tazelemek ProvisionUser'ın
	 * işi — gruplar GERÇEKTEN öğrenildiği için GroupsResolved true.
	 *
	 * ⚠️ Issuer/Subject: dizin kimliği için kararlı bir çift henüz yok
	 * (entryUUID bağlama işi ayrı bir dilim). Bu yüzden şimdilik yalnızca
	 * VAR OLAN hesaplar giriş yapabiliyor; JIT sağlama bilerek kapalı,
	 * çünkü kararlı bir subject olmadan hesap açmak, kullanıcı adına
	 * dayalı bir bağ kurmak olurdu — 011'de kapatılan açığın ta kendisi.
	 */
	u, err := s.store.User(r.Context(), username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			log.Warn("directory login: no postern account for this directory user",
				"user", username)
			writeErr(w, http.StatusForbidden,
				"the directory knows you, but this bastion has no account for you yet; "+
					"ask an administrator to add it")
			return
		}
		log.Error("directory login: user load failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return
	}

	// Presence yukarıda Present olarak doğrulandı: boş liste burada
	// "hiçbir grupta değil" demek, "bilmiyorum" değil.
	roles, _, rerr := s.store.RolesForGroups(r.Context(), model.ResolvedGroups(res.Groups))
	if rerr != nil {
		s.storeErr(w, "auth.directory", rerr)
		return
	}
	if serr := s.store.SyncRoles(r.Context(), u.Name, roles); serr != nil {
		s.storeErr(w, "auth.directory", serr)
		return
	}
	// Yönetici yetkisi de dizinden: gruplar BURADA gerçekten çözüldü,
	// yani uygulamak güvenli (bkz. applyGroupAdmin'deki not).
	s.applyGroupAdmin(r.Context(), u.Name, res.Groups)

	token, err := s.webSessions.Create(u.Name)
	if err != nil {
		log.Error("web session create failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
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
		Actor: u.Name, Via: "local", Action: "auth.directory_login", Entity: u.Name,
		Details: "signed in with the directory password",
	}); aerr != nil {
		log.Error("audit write failed", "error", aerr)
	}
	log.Info("directory login", "user", u.Name, "roles", len(roles))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// logger, handleLocalLogin'in kurduğu alt logger'ın arayüzü.
type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}
