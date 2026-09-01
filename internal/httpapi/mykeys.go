package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/store"
)

/*
 * Kendi anahtarını yönetme.
 *
 * NEDEN VAR: SSH tarafı anahtarla çalışıyor ama anahtar ekleyen tek uç
 * yöneticideydi. Dizini olan bir kurumda bu, dizinden kaçınmak için
 * kurulan sistemin geri getirdiği elle iş oluyordu — her kullanıcı için
 * yöneticinin tek tek anahtar girmesi.
 *
 * ⚠️ KURAL: İLK ANAHTAR SERBEST, SONRAKİLER YENİDEN KİMLİK DOĞRULAMA
 * İSTER.
 *
 * Dayanağı şu ayrım: anahtarı olmayan kullanıcı zaten SSH'a giremiyor,
 * yani ilk anahtarı eklemek normal akışın kendisi. Anahtarı OLAN bir
 * hesaba ikinci bir anahtar eklenmesi ise saldırganın kalıcılık kurma
 * hamlesinin ta kendisi: panel oturumunu ya da parolayı ele geçiren
 * biri, parola sonradan değişse bile yaşayacak bir giriş bırakır.
 */

// handleMyKeys: GET /api/me/keys — kendi anahtarlarım.
func (s *Server) handleMyKeys(w http.ResponseWriter, r *http.Request) {
	name := sessionUser(r)

	keys, err := s.store.PublicKeys(r.Context(), name)
	if err != nil {
		s.storeErr(w, "me.keys", err)
		return
	}
	stamped, err := s.store.FirstKeyAdded(r.Context(), name)
	if err != nil {
		s.storeErr(w, "me.keys", err)
		return
	}

	type row struct {
		Fingerprint string `json:"fingerprint"`
		Comment     string `json:"comment"`
		AddedAt     string `json:"added_at"`
	}
	out := make([]row, 0, len(keys))
	for _, k := range keys {
		pub, perr := ssh.ParsePublicKey(k.Blob)
		if perr != nil {
			// Saklanmış bozuk bir kayıt listeyi düşürmemeli.
			s.logger.Error("stored key unparseable", "user", name, "error", perr)
			continue
		}
		out = append(out, row{
			Fingerprint: ssh.FingerprintSHA256(pub),
			Comment:     k.Comment,
			AddedAt:     k.AddedAt.UTC().Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"keys": out,
		// Panelin ne soracağını bilmesi için: ilk anahtar mı, yoksa
		// yeniden doğrulama gerektiren bir ekleme mi?
		"reauth_required": stamped,
		// Bu hesap için yeniden doğrulama YAPILABİLİYOR mu? Yapılamıyorsa
		// panel kullanıcıyı kayıt ekranına yönlendirmeli, boş yere sır
		// sormamalı.
		"reauth_possible": s.canReauth(r.Context(), name) || s.hasTOTP(r.Context(), name),
		// Panelin HANGİ alanı göstereceği: kod mu, sır mı?
		"reauth_totp": s.hasTOTP(r.Context(), name),
	})
}

// canReauth, bu hesabın postern'in DOĞRULAYABİLECEĞİ bir kimlik
// bilgisine sahip olup olmadığı.
//
// Bugün bu yalnızca yerel sır. OIDC ile giren bir kullanıcının
// postern'de doğrulanabilir bir sırrı yok; onun için yol yöneticiden
// geçiyor ve panel bunu açıkça söylüyor.
func (s *Server) canReauth(ctx context.Context, name string) bool {
	c, err := s.store.LocalCredential(ctx, name)
	if err != nil {
		return false
	}
	/*
	 * ⚠️ DEĞİŞTİRİLMEMİŞ BİR KİMLİK BİLGİSİ YENİDEN DOĞRULAMA SAYILMAZ.
	 *
	 * must_change taşıyan değeri YÖNETİCİ üretti ve iletti; kişi onu
	 * henüz değiştirmedi, yani değer İKİ kişinin elinde. Bu dosyanın
	 * başındaki gerekçe "ikinci anahtar eklemek saldırganın kalıcılık
	 * kurma hamlesinin ta kendisi" diyor — o hamleyi, sahibinden başka
	 * birinin de bildiği bir değerle onaylamak, kontrolü tamamen boşa
	 * çıkarır.
	 *
	 * Sonuç kullanıcı için kapalı bir kapı değil: parolasını
	 * değiştirdiği an burası açılıyor.
	 */
	return !c.MustChange
}

// handleAddMyKey: POST /api/me/keys
func (s *Server) handleAddMyKey(w http.ResponseWriter, r *http.Request) {
	name := sessionUser(r)

	// Yöneticideki kuralın aynısı: kapalı bir özelliğe anahtar eklemek,
	// ayar bir gün açıldığında kimsenin kararı olmayan bir erişim
	// bırakırdı.
	if !s.publicKeyLogin {
		writeErr(w, http.StatusConflict,
			"public key login is switched off on this bastion (auth.public_key_login)")
		return
	}

	var in struct {
		AuthorizedKey string `json:"authorized_key"`
		Reauth        string `json:"reauth"`
		// Code, kimlik doğrulayıcı uygulamasından gelen TOTP kodu.
		// Yerel sırrı olmayan hesapların (SSO/dizin) tek yolu bu.
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	/*
	 * ⚠️ ZORUNLU PAROLA DEĞİŞİKLİĞİ, "İLK ANAHTAR BEDAVA" KURALINDAN
	 * ÖNCE — ve blok DIŞINDA.
	 *
	 * Bu kontrol önce `if stamped` bloğunun içindeydi ve orada YANLIŞTI:
	 * anahtarı hiç olmayan bir hesapta ilk anahtar hiçbir doğrulama
	 * istemeden ekleniyor (kural ve gerekçesi bu dosyanın başında).
	 * Yani parolasını henüz değiştirmemiş biri — değeri VEREN kişinin de
	 * bildiği biri — tek istekle kalıcı SSH erişimi kurabilirdi, ve
	 * "parolanı değiştirene kadar hiçbir şey yapamazsın" kısıtı tam
	 * olarak engellemesi gereken şeyi engellemezdi.
	 *
	 * Yönlendirici de bu ucu kısıtlı oturuma kapatıyor (weblogin.go).
	 * İkisi birden duruyor: tek bir listeye bağlı kalan bir kural,
	 * listeye eklenen bir sonraki satırla sessizce açılır.
	 *
	 * ErrNotFound "kısıt yok" demek: kimliği dizinden ya da kimlik
	 * sağlayıcıdan gelen hesabın postern'de parolası yok.
	 */
	if c, cerr := s.store.LocalCredential(r.Context(), name); cerr == nil && c.MustChange {
		writeErr(w, http.StatusForbidden,
			"change your password first — a credential you have not chosen yourself "+
				"cannot authorise adding an SSH key")
		return
	}

	stamped, err := s.store.FirstKeyAdded(r.Context(), name)
	if err != nil {
		s.storeErr(w, "me.keys.add", err)
		return
	}

	if stamped {
		/*
		 * ⚠️ İKİ YOL, TEK KAPI. İkinci faktör varsa kod isteniyor;
		 * yoksa yerel sır. Sıra TOTP'den yana çünkü onu bağlamış
		 * kullanıcı bilinçli olarak "beni bununla doğrula" demiştir —
		 * ve TOTP tek kullanımlık, parola değil.
		 *
		 * Hiçbiri yoksa (SSO hesabı, henüz kayıt yapmamış) kullanıcı
		 * artık yöneticiye değil, KENDİ kayıt ekranına yönlendiriliyor:
		 * bu paketin var olma sebebi tam olarak o çıkmazdı.
		 */
		if s.hasTOTP(r.Context(), name) {
			if !s.spendTOTP(w, r, name, in.Code) {
				return
			}
		} else if !s.checkLocalSecret(w, r, name, in.Reauth, "adding a further key") {
			return
		}
	}

	pub, comment, okKey := parseAuthorizedKey(w, in.AuthorizedKey)
	if !okKey {
		return
	}

	if err := s.store.AddPublicKey(r.Context(), name, pub.Marshal(), comment); err != nil {
		s.storeErr(w, "me.keys.add", err)
		return
	}
	if err := s.store.MarkFirstKeyAdded(r.Context(), name, time.Now()); err != nil {
		s.storeErr(w, "me.keys.add", err)
		return
	}

	// ⚠️ HER EKLEME DENETİM KAYDINA. Bu bir YETKİ VERME noktası:
	// eklenen anahtar, kullanıcının rollerinin ulaştığı her makineye
	// giriyor. Parmak izi yazılıyor ki sonradan "hangi anahtar" sorusu
	// cevaplanabilsin.
	if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
		Actor: name, Via: "web", Action: "user.key_add_self", Entity: name,
		Details: "self-service key " + ssh.FingerprintSHA256(pub) +
			map[bool]string{true: " (re-authenticated)", false: " (first key)"}[stamped],
	}); aerr != nil {
		s.logger.Error("audit write failed", "error", aerr)
	}

	s.logger.Info("self-service key added", "user", name,
		"fingerprint", ssh.FingerprintSHA256(pub), "reauthenticated", stamped)
	ok(w)
}

/*
 * handleRemoveMyKey: POST /api/me/keys/remove
 *
 * Silme yeniden doğrulama İSTEMİYOR: erişimi azaltan bir işlem ve
 * ele geçirilmiş bir anahtarı hızlıca kaldırabilmek gerekiyor.
 *
 * ⚠️ Bunun sil-ve-ekle ile kuralı atlatmaya yol açmamasının sebebi,
 * kapının anahtar SAYISINA değil bir kez konan DAMGAYA bakması
 * (store.FirstKeyAdded). Sayıya bakan bir kural burada delinirdi.
 */
func (s *Server) handleRemoveMyKey(w http.ResponseWriter, r *http.Request) {
	name := sessionUser(r)

	var in struct {
		AuthorizedKey string `json:"authorized_key"`
		/*
		 * ⚠️ PARMAK İZİ EKLENDİ ve asıl kullanılan yol bu.
		 *
		 * Uç yalnızca anahtar METNİNİ kabul ediyordu ve liste ucu
		 * (GET /api/me/keys) metni DÖNDÜRMÜYOR — yalnızca parmak izi.
		 * Yani panelin, silme ucunun istediği değere hiçbir zaman
		 * sahip olmadığı bir uçtu: yazılmış, denetlenmiş ve
		 * çağrılamaz. Sonuç, anahtarının ele geçtiğini fark eden
		 * kullanıcının onu iptal edememesiydi — mykeys.go'nun kendi
		 * gerekçesi ikinci anahtarı "saldırganın kalıcılık kurma
		 * hamlesi" diye tanımlarken.
		 */
		Fingerprint string `json:"fingerprint"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	blob, okBlob := s.removeKeyBlob(w, r, name, in.AuthorizedKey, in.Fingerprint)
	if !okBlob {
		return
	}
	pub, perr := ssh.ParsePublicKey(blob)
	if perr != nil {
		s.storeErr(w, "me.keys.remove", perr)
		return
	}

	if err := s.store.RemovePublicKey(r.Context(), name, pub.Marshal()); err != nil {
		s.storeErr(w, "me.keys.remove", err)
		return
	}
	if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
		Actor: name, Via: "web", Action: "user.key_remove_self", Entity: name,
		Details: "self-service key " + ssh.FingerprintSHA256(pub) + " removed",
	}); aerr != nil {
		s.logger.Error("audit write failed", "error", aerr)
	}
	ok(w)
}

/*
 * checkLocalSecret, postern'in KENDİ sırrıyla yeniden doğrular.
 *
 * ⚠️ TEK BİR UYGULAMA OLMASI ŞART. Bu kontrol iki yerden çağrılıyor —
 * ikinci anahtar eklemek ve ikinci faktör bağlamak — ve ikisi de aynı
 * şeyi koruyor: kalıcılık kurmak. İkinci bir kopya yazılsaydı, hız
 * sınırını ya da artan gecikmeyi birinde unutmak yeterdi: saldırgan
 * zayıf olan uçtan dener.
 *
 * what, denetim kaydına giren "ne reddedildi" metni.
 */
func (s *Server) checkLocalSecret(w http.ResponseWriter, r *http.Request, name, secret, what string) bool {
	cred, verr := s.store.LocalCredential(r.Context(), name)
	switch {
	case errors.Is(verr, store.ErrNotFound):
		// Doğrulayacak bir sır yok: bu hesabın kimliği başka bir
		// yerden geliyor. Uydurma bir onay yerine dürüst bir yol
		// gösteriyoruz — yönetici ucu zaten var.
		writeErr(w, http.StatusForbidden,
			"this account has no credential of its own for postern to re-check "+
				"you with; enrol an authenticator, or ask an administrator")
		return false
	case verr != nil:
		s.storeErr(w, "me.reauth", verr)
		return false
	}

	if !s.localLimit.allow(s.clientKey(r)) {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many attempts; try again in a minute")
		return false
	}

	/*
	 * ⚠️ ARTAN GECİKME BURADA DA.
	 *
	 * Bu uç, giriş kapısıyla AYNI değeri doğruluyor. Gecikme yalnızca
	 * /auth/local'e konsaydı, tahmin eden kişi iki uç arasında
	 * dönüşümlü deneyerek onu tamamen atlardı — üstelik buradaki
	 * denemeler oturumlu olduğu için daha az göze batarak. Sayaç
	 * ORTAK: aynı hesap, aynı adres, aynı kova.
	 */
	bkey := backoffKey(name, s.clientKey(r))
	if wait := s.guessBackoff.retryAfter(bkey); wait > 0 {
		secs := int(wait.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf(
			"too many failed attempts from here; try again in %d seconds", secs))
		return false
	}

	select {
	case s.localSlots <- struct{}{}:
		defer func() { <-s.localSlots }()
	default:
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "busy; try again shortly")
		return false
	}

	if !verifyCredential(cred, secret) {
		// Muafiyetin gerekçesi locallogin.go'da: sır tutan hesaplar
		// gecikmiyor, yoksa vekil arkasında bir yabancı acil durum
		// yöneticisini dışarıda tutabilirdi.
		if cred.Chosen {
			s.guessBackoff.fail(bkey)
		}
		s.logger.Warn("re-auth failed", "user", name, "for", what)
		if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
			Actor: name, Via: "web", Action: "user.key_reauth_failed", Entity: name,
			Details: what + " was refused",
		}); aerr != nil {
			s.logger.Error("audit write failed", "error", aerr)
		}
		writeErr(w, http.StatusUnauthorized, "wrong secret")
		return false
	}
	s.guessBackoff.succeed(bkey)
	return true
}

// hasTOTP, hesabın DOĞRULANMIŞ bir ikinci faktörü var mı.
//
// Doğrulanmamış kayıt sayılmıyor: QR'ı hiç okutmamış kullanıcıdan kod
// istemek, onu kendi hesabının dışında bırakırdı.
func (s *Server) hasTOTP(ctx context.Context, name string) bool {
	c, err := s.store.TOTP(ctx, name)
	return err == nil && c.Confirmed
}
