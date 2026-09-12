package httpapi

// Girişte güvenlik anahtarıyla ikinci faktör (göç 039).

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
)

/*
 * secondFactor, parolası doğrulanmış bir hesabın ikinci faktörünü
 * karşılar. Dönen false, yanıtın YAZILDIĞI ve çağıranın durması
 * gerektiği anlamına geliyor.
 *
 * ⚠️ ARA BELİRTEÇ YOK — VE BU KURAL WebAuthn İÇİN DE GEÇERLİ.
 * locallogin.go, parola ile kodu aynı istekte istiyor; sebebi orada
 * yazılı: aradaki bir belirteç, ikinci faktörünü henüz kanıtlamamış
 * birinin elinde duran bir şey olurdu. WebAuthn iki tur gerektiriyor
 * (sunucu meydan okur, anahtar imzalar) ama kuralı bozmuyor: meydan
 * okuma bir BELİRTEÇ DEĞİL, tek kullanımlık bir nonce. Elinde tutan
 * hiçbir kapı açamıyor, ve ikinci istek parolayı yine taşıyor.
 *
 * ⚠️ SIRA: ANAHTAR VARSA ÖNCE ANAHTAR. Kod yalnızca hesap "yalnızca
 * anahtar" demediyse kabul ediliyor. İkisi birlikte açıkken hesabın
 * kimlik avına dayanıklılığı kodunki kadar; bunu kapatmak kişinin
 * kararı (webauthn_only) ve panel durumu açıkça yazıyor.
 */
func (s *Server) secondFactor(w http.ResponseWriter, r *http.Request,
	username string, assertion json.RawMessage, code string,
) bool {
	creds, err := s.store.WebAuthnCredentials(r.Context(), username)
	if err != nil {
		s.logger.Error("webauthn lookup failed", "user", username, "error", err)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return false
	}
	if len(creds) == 0 {
		// Anahtarı olmayan hesap bugünkü yoldan geçiyor.
		return true
	}

	only, err := s.store.WebAuthnOnly(r.Context(), username)
	if err != nil {
		s.logger.Error("webauthn preference lookup failed", "user", username, "error", err)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return false
	}

	/*
	 * ⚠️ KOD SEÇİLDİYSE ANAHTAR YOLU HİÇ AÇILMIYOR. Kullanıcı panelde
	 * "kodumu kullanayım" dediyse elimizde bir imza olmayacak; onu
	 * TOTP yoluna bırakmak gerekiyor. "yalnızca anahtar" açıkken bu
	 * kapı kapalı, yoksa geri düşme mümkün olmazdı.
	 */
	if len(assertion) == 0 && code != "" && !only {
		return true
	}

	wa, err := webauthnFor(s.externalURL)
	if err != nil {
		/*
		 * ⚠️ YAPILANDIRILMAMIŞ WebAuthn, ANAHTARI OLAN HESABI
		 * KİLİTLİYOR — VE KİLİTLEMELİ. Sessizce koda düşseydi,
		 * external_url'i bozan bir değişiklik hesabın ikinci faktörünü
		 * zayıflatır ve kimse fark etmezdi.
		 */
		s.logger.Error("webauthn is not configured but this account has keys",
			"user", username, "error", err)
		writeErr(w, http.StatusServiceUnavailable,
			"this account signs in with a security key, and this bastion's "+
				"external URL is not set up for one")
		return false
	}

	u, err := s.webauthnUserFor(r, username)
	if err != nil {
		s.logger.Error("webauthn user could not be built", "user", username, "error", err)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return false
	}

	if len(assertion) == 0 {
		options, session, berr := wa.BeginLogin(u)
		if berr != nil {
			s.logger.Error("webauthn login could not start", "user", username, "error", berr)
			writeErr(w, http.StatusInternalServerError, "sign-in failed")
			return false
		}
		s.webauthnLogin.put(username, *session)

		/*
		 * ⚠️ 401 VE MAKİNE OKUNUR İŞARET — kod akışıyla aynı biçim.
		 * Panelin anahtar istemini çizebilmesi için "parola yanlış" ile
		 * "anahtar bekleniyor"u ayırt etmesi gerekiyor; buraya gelen
		 * taraf parolayı ZATEN kanıtladı, dolayısıyla bilgi sızmıyor.
		 */
		out := map[string]any{
			"error":             "touch your security key",
			"webauthn_required": true,
			"options":           options,
			// Panel "kodumu kullanayım" bağlantısını buna bakarak
			// çiziyor: kapalıysa hiç göstermemeli.
			"code_allowed": !only,
		}
		writeJSON(w, http.StatusUnauthorized, out)

		return false
	}

	session, ok := s.webauthnLogin.take(username)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":             "that sign-in timed out; try again",
			"webauthn_required": true,
			"code_allowed":      !only,
		})
		return false
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertion))
	if err != nil {
		s.countTOTPFailure(r, username)
		s.logger.Warn("webauthn assertion could not be read", "user", username, "error", err)
		writeErr(w, http.StatusUnauthorized, "that security key was not accepted")
		return false
	}

	cred, err := wa.ValidateLogin(u, session, parsed)
	if err != nil {
		/*
		 * ⚠️ BAŞARISIZ İMZA, YANLIŞ KODLA AYNI KOVAYA DÜŞÜYOR. İkisi de
		 * "ikinci faktörü geçemedi" demek; ayrı sayaç tutmak, ısrarlı
		 * denemeyi iki yarıya bölüp ikisini de eşikten uzak tutardı.
		 */
		s.countTOTPFailure(r, username)
		s.logger.Warn("webauthn assertion rejected", "user", username, "error", err)
		writeErr(w, http.StatusUnauthorized, "that security key was not accepted")
		return false
	}

	/*
	 * ⚠️ KLON UYARISI KAYDA GİRİYOR, GİRİŞİ DÜŞÜRMÜYOR.
	 *
	 * Kütüphane sayaç gerilediğinde bunu işaretliyor. Girişi reddetmek
	 * cazip ama yanlış olurdu: sayacı hiç artırmayan doğrulayıcılar var
	 * (platform anahtarlarının çoğu hep 0 gönderiyor) ve onlarda bayrak
	 * yanlış yere basardı. Doğru davranış, operatörün görebileceği bir
	 * iz bırakmak.
	 */
	if cred.Authenticator.CloneWarning {
		s.logger.Warn("webauthn sign count went backwards; the key may be cloned",
			"user", username)
		s.audit(r, "user.webauthn.clone_warning", username,
			"authenticator sign count went backwards")
	}

	id := base64url(cred.ID)
	if err := s.store.TouchWebAuthnCredential(r.Context(), id,
		cred.Authenticator.SignCount); err != nil {
		// Sayaç yazılamadıysa giriş yine geçerli: doğrulama zaten
		// yapıldı. Ama klon sezgisi körelir, o yüzden yüksek sesle.
		s.logger.Error("webauthn sign count not recorded",
			"user", username, "error", err)
	}

	return true
}
