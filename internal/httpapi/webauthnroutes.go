package httpapi

// Güvenlik anahtarının kayıt ve listeleme uçları (göç 039).

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * ⚠️ HEPSİ OTURUM İSTİYOR VE AYNI KÖKENİ ŞART KOŞUYOR — TOTP uçlarıyla
 * aynı gerekçe: başka bir siteden tetiklenen bir istek, kurbanın
 * hesabına saldırganın anahtarını bağlayabilirdi.
 */
func (s *Server) routeWebAuthn(mux *http.ServeMux) {
	mux.Handle("GET /api/me/webauthn",
		noStore(s.requireSession(http.HandlerFunc(s.handleWebAuthnList))))
	mux.Handle("POST /api/me/webauthn/begin",
		s.requireSession(s.sameOrigin(http.HandlerFunc(s.handleWebAuthnBegin))))
	mux.Handle("POST /api/me/webauthn/finish",
		s.requireSession(s.sameOrigin(http.HandlerFunc(s.handleWebAuthnFinish))))
	mux.Handle("POST /api/me/webauthn/remove",
		s.requireSession(s.sameOrigin(http.HandlerFunc(s.handleWebAuthnRemove))))
	mux.Handle("POST /api/me/webauthn/only",
		s.requireSession(s.sameOrigin(http.HandlerFunc(s.handleWebAuthnOnly))))
}

// handleWebAuthnList: GET /api/me/webauthn
func (s *Server) handleWebAuthnList(w http.ResponseWriter, r *http.Request) {
	name := sessionUser(r)

	creds, err := s.store.WebAuthnCredentials(r.Context(), name)
	if err != nil {
		s.storeErr(w, "webauthn.list", err)
		return
	}

	only, err := s.store.WebAuthnOnly(r.Context(), name)
	if err != nil {
		s.storeErr(w, "webauthn.list", err)
		return
	}

	/*
	 * ⚠️ "ANAHTAR VAR AMA KOD DA AÇIK" AYRI BİR DURUM VE PANEL BUNU
	 * SÖYLEMELİ. İkisi birlikte açıkken hesabın kimlik avına
	 * dayanıklılığı KODUNKİ kadar: saldırgan anahtarı hiç sormadan
	 * kodu ister. Kullanıcı bunu bilmeden "anahtarım var, güvendeyim"
	 * sanıyor — panelin susması o yanılgıyı üretirdi.
	 */
	writeJSON(w, http.StatusOK, map[string]any{
		"credentials": creds,
		"only":        only,
	})
}

// handleWebAuthnBegin: POST /api/me/webauthn/begin
func (s *Server) handleWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	name := sessionUser(r)

	/*
	 * ⚠️ KAYIT, TOTP KAYDIYLA AYNI TAZELİK KAPISINDAN GEÇİYOR. Çalınmış
	 * bir oturum çerezi tek başına yeni bir ikinci faktör bağlayabilseydi,
	 * saldırgan kendi anahtarını ekleyip hesabı kalıcı olarak devralırdı.
	 */
	if !s.canBeginTOTP(r) {
		writeErr(w, http.StatusForbidden,
			"sign in again before registering a security key")
		return
	}

	wa, err := webauthnFor(s.externalURL)
	if err != nil {
		s.logger.Error("webauthn is not configured", "error", err)
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	u, err := s.webauthnUserFor(r, name)
	if err != nil {
		s.storeErr(w, "webauthn.begin", err)
		return
	}

	/*
	 * ⚠️ KAYITLI ANAHTARLAR DIŞLANIYOR. Aynı doğrulayıcı ikinci kez
	 * kaydedilirse kullanıcı iki satır görür ve hangisinin hangi cihaz
	 * olduğunu ayırt edemez; şartname bunun için excludeCredentials'ı
	 * veriyor ve doğrulayıcı "bu zaten kayıtlı" diye kendisi reddediyor.
	 */
	exclude := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for _, c := range u.creds {
		exclude = append(exclude, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.ID,
		})
	}

	options, session, err := wa.BeginRegistration(u,
		webauthn.WithExclusions(exclude))
	if err != nil {
		s.logger.Error("webauthn registration could not start", "user", name, "error", err)
		writeErr(w, http.StatusInternalServerError, "could not start registration")
		return
	}

	s.webauthnEnroll.put(name, *session)
	writeJSON(w, http.StatusOK, options)
}

// handleWebAuthnFinish: POST /api/me/webauthn/finish
func (s *Server) handleWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	name := sessionUser(r)

	var in struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	wa, err := webauthnFor(s.externalURL)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	session, ok := s.webauthnEnroll.take(name)
	if !ok {
		// ⚠️ "Tören yok" ile "imza geçersiz" AYRI cümleler: ilki
		// çoğunlukla süre aşımı ve yapılacak şey yeniden başlamak.
		writeErr(w, http.StatusBadRequest,
			"that registration timed out; start again")
		return
	}

	u, err := s.webauthnUserFor(r, name)
	if err != nil {
		s.storeErr(w, "webauthn.finish", err)
		return
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(
		bytes.NewReader(in.Credential))
	if err != nil {
		s.logger.Warn("webauthn registration response rejected", "user", name, "error", err)
		writeErr(w, http.StatusBadRequest, "the security key's answer could not be read")
		return
	}

	cred, err := wa.CreateCredential(u, session, parsed)
	if err != nil {
		s.logger.Warn("webauthn registration failed", "user", name, "error", err)
		writeErr(w, http.StatusBadRequest, "that security key was not accepted")
		return
	}

	rec := storedFrom(cred, credentialName(in.Name))
	if err := s.store.AddWebAuthnCredential(r.Context(), name, rec); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict, "that security key is already registered")
			return
		}
		s.storeErr(w, "webauthn.finish", err)
		return
	}

	s.audit(r, "user.webauthn.add", name, "key "+rec.Name)
	writeJSON(w, http.StatusOK, map[string]any{"name": rec.Name, "id": rec.ID})
}

// handleWebAuthnRemove: POST /api/me/webauthn/remove
func (s *Server) handleWebAuthnRemove(w http.ResponseWriter, r *http.Request) {
	name := sessionUser(r)

	var in struct {
		ID string `json:"id"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.ID) == "" {
		writeErr(w, http.StatusBadRequest, "which key?")
		return
	}

	// ⚠️ SİLMEK DE TAZELİK İSTİYOR: çalınmış bir oturum, kişinin
	// anahtarını söküp yerine kendininkini koyabilirdi.
	if !s.canBeginTOTP(r) {
		writeErr(w, http.StatusForbidden, "sign in again before removing a security key")
		return
	}

	switch err := s.store.DeleteWebAuthnCredential(r.Context(), name, in.ID); {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "no such security key on this account")
		return
	default:
		s.storeErr(w, "webauthn.remove", err)
		return
	}

	s.audit(r, "user.webauthn.remove", name, "key id "+in.ID)
	w.WriteHeader(http.StatusNoContent)
}

// handleWebAuthnOnly: POST /api/me/webauthn/only
func (s *Server) handleWebAuthnOnly(w http.ResponseWriter, r *http.Request) {
	name := sessionUser(r)

	var in struct {
		Only bool `json:"only"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	if !s.canBeginTOTP(r) {
		writeErr(w, http.StatusForbidden, "sign in again before changing this")
		return
	}

	switch err := s.store.SetWebAuthnOnly(r.Context(), name, in.Only); {
	case err == nil:
	case errors.Is(err, store.ErrConflict):
		// Anahtarsız açmak, hesabı hiçbir faktörü kalmamış hâle sokardı.
		writeErr(w, http.StatusConflict, "register a security key first")
		return
	default:
		s.storeErr(w, "webauthn.only", err)
		return
	}

	detail := "codes accepted again"
	if in.Only {
		detail = "codes no longer accepted; security key required"
	}
	s.audit(r, "user.webauthn.only", name, detail)
	writeJSON(w, http.StatusOK, map[string]any{"only": in.Only})
}
