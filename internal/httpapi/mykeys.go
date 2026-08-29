package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/auth"
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
		// panel kullanıcıyı yöneticiye yönlendirmeli, boş yere sır
		// sormamalı.
		"reauth_possible": s.canReauth(r.Context(), name),
	})
}

// canReauth, bu hesabın postern'in DOĞRULAYABİLECEĞİ bir kimlik
// bilgisine sahip olup olmadığı.
//
// Bugün bu yalnızca yerel sır. OIDC ile giren bir kullanıcının
// postern'de doğrulanabilir bir sırrı yok; onun için yol yöneticiden
// geçiyor ve panel bunu açıkça söylüyor.
func (s *Server) canReauth(ctx context.Context, name string) bool {
	_, err := s.store.LocalCredential(ctx, name)
	return err == nil
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
	}
	if !readJSON(w, r, &in) {
		return
	}

	stamped, err := s.store.FirstKeyAdded(r.Context(), name)
	if err != nil {
		s.storeErr(w, "me.keys.add", err)
		return
	}

	if stamped {
		verifier, verr := s.store.LocalCredential(r.Context(), name)
		switch {
		case errors.Is(verr, store.ErrNotFound):
			// Doğrulayacak bir sır yok: bu hesabın kimliği başka bir
			// yerden geliyor. Uydurma bir onay yerine dürüst bir yol
			// gösteriyoruz — yönetici ucu zaten var.
			writeErr(w, http.StatusForbidden,
				"this account already has a key, and postern has no credential of its own "+
					"to re-check you with; ask an administrator to add it")
			return
		case verr != nil:
			s.storeErr(w, "me.keys.add", verr)
			return
		}

		if !s.localLimit.allow(clientKey(r)) {
			w.Header().Set("Retry-After", "60")
			writeErr(w, http.StatusTooManyRequests, "too many attempts; try again in a minute")
			return
		}
		select {
		case s.localSlots <- struct{}{}:
			defer func() { <-s.localSlots }()
		default:
			w.Header().Set("Retry-After", "5")
			writeErr(w, http.StatusServiceUnavailable, "busy; try again shortly")
			return
		}

		if !auth.VerifyLocalSecret(verifier, in.Reauth) {
			s.logger.Warn("key add refused: re-auth failed", "user", name)
			if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
				Actor: name, Via: "web", Action: "user.key_reauth_failed", Entity: name,
				Details: "adding a further key was refused",
			}); aerr != nil {
				s.logger.Error("audit write failed", "error", aerr)
			}
			writeErr(w, http.StatusUnauthorized, "wrong secret")
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
	}
	if !readJSON(w, r, &in) {
		return
	}
	pub, _, okKey := parseAuthorizedKey(w, in.AuthorizedKey)
	if !okKey {
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
