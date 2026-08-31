package httpapi

// OIDC ayarlarının yönetim yüzeyi.
//
// ⚠️ KENDİ UCU VAR, genel ayar ucundan yazılamıyor. auth.source ve
// ldap.admin_group ile aynı gerekçe: bu değerler postern'in KİME
// GÜVENDİĞİNİ belirliyor ve yanlış bir değer, kimsenin giremediği bir
// panel bırakıyor. Doğrulamasız bir yazma ucundan geçmemeliler.

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/store"
)

func (s *Server) registerOIDCRoutes(mux *http.ServeMux) {
	admin := func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	}
	mux.Handle("GET /api/admin/oidc", admin(s.adminOIDCStatus))
	mux.Handle("PUT /api/admin/oidc", admin(s.adminOIDCSet))
}

/*
 * adminOIDCStatus: GET /api/admin/oidc
 *
 * ⚠️ İSTEMCİ SIRRI DÖNMÜYOR, yalnızca VAR OLUP OLMADIĞI. Panelin
 * okuyabildiği bir sır, panele erişen herkesin okuyabildiği bir sırdır —
 * LDAP bind parolasındaki kararın aynısı.
 */
func (s *Server) adminOIDCStatus(w http.ResponseWriter, r *http.Request) {
	stored, err := auth.LoadOIDC(r.Context(), s.store)
	if err != nil && !errors.Is(err, auth.ErrOIDCNotConfigured) {
		// Yarım yapılandırma: alanları yine gösteriyoruz ki operatör
		// neyin eksik olduğunu görsün.
		s.logger.Warn("oidc settings unusable", "error", err)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"issuer_url": stored.IssuerURL,
		"client_id":  stored.ClientID,
		// Sır GERİ OKUNMUYOR; yalnızca varlığı.
		"client_secret_set": stored.ClientSecret != "",
		"groups_claim":      stored.GroupsClaim,
		"scopes":            stored.Scopes,
		"managed_in_db":     auth.OIDCManagedInDB(r.Context(), s.store),
		/*
		 * ⚠️ İKİ AYRI DURUM. "Ayarlı" ile "çalışıyor" aynı ekranı hak
		 * etmiyor: ilki operatörün yazdığı, ikincisi sağlayıcının
		 * cevap verdiği. Karıştırmak, ulaşılamayan bir sağlayıcıyı
		 * "yanlış ayarladım" diye aratırdı.
		 */
		"configured": s.oidc.Configured(),
		"live":       s.oidc.Live(),
	})
}

/*
 * adminOIDCSet: PUT /api/admin/oidc
 *
 * ⚠️ SIRA KRİTİK VE ŞU: yaz → ESKİ İSTEMCİYİ DÜŞÜR → yeniden kurmayı
 * dene → başarılıysa yerleştir.
 *
 * Düşürme, herhangi bir ağ çağrısından ÖNCE oluyor. Aksi hâlde yeni
 * sağlayıcı ulaşılamadığında ESKİ istemci ayakta kalırdı ve operatör,
 * istemci sırrını değiştirdikten sonra eski sırla girişlerin sürdüğünü
 * görürdü — iptal ettiğini sanarak.
 *
 * ⚠️ Sonuç "kurulamadı" olsa bile istek BAŞARILI dönüyor (live:false).
 * Hata döndürmek, ulaşılamayan bir sağlayıcı yüzünden ayarların hiç
 * kaydedilememesi demekti: operatör yazdığını kaybeder ve düzeltemez.
 */
func (s *Server) adminOIDCSet(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IssuerURL string  `json:"issuer_url"`
		ClientID  string  `json:"client_id"`
		Secret    *string `json:"client_secret"`
		// ⚠️ İşaretçi: "gönderilmedi" ile "boşaltıldı" ayrı şeyler.
		// Boş dize burada anlamlı — "varsayılana dön" demek.
		GroupsClaim *string `json:"groups_claim"`
		Scopes      *string `json:"scopes"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	issuer := strings.TrimSpace(in.IssuerURL)
	clientID := strings.TrimSpace(in.ClientID)
	if issuer == "" || clientID == "" {
		writeErr(w, http.StatusBadRequest,
			"the issuer address and client id are both required")
		return
	}
	if !strings.HasPrefix(issuer, "https://") && !isLoopbackURL(issuer) {
		// ⚠️ Düz http yalnızca loopback'te — ldap.checkScheme ile aynı
		// karar: token ve istemci sırrı ağda düz metin gezmemeli.
		writeErr(w, http.StatusBadRequest,
			"the issuer must be https:// (plain http is only accepted for loopback)")
		return
	}

	prev, _ := auth.LoadOIDC(r.Context(), s.store)

	/*
	 * ⚠️ HEDEF DEĞİŞİRSE İSTEMCİ SIRRI DÜŞER.
	 *
	 * ldap.url'de verilen kararın aynısı ve aynı saldırıyı kapatıyor:
	 * panel yöneticisi issuer'ı kendi sunucusuna çevirip saklanan sırrı
	 * oraya gönderemesin. Sıra tersine — önce sırrı düşür, sonra adresi
	 * yaz — ki arada kalan bir koşu, yeni adresi eski sırla eşleştirmiş
	 * olmasın.
	 */
	if prev.IssuerURL != "" && (prev.IssuerURL != issuer || prev.ClientID != clientID) {
		if derr := s.store.DeleteSetting(r.Context(), auth.KeyOIDCClientSecret); derr != nil &&
			!errors.Is(derr, store.ErrNotFound) {
			s.storeErr(w, "oidc.set", derr)
			return
		}
		s.logger.Warn("oidc target changed; stored client secret dropped",
			"actor", sessionUser(r), "from", prev.IssuerURL, "to", issuer)
		s.audit(r, "oidc.target_changed", issuer,
			"client secret cleared because the provider or client id changed")
	}

	actor := sessionUser(r)

	/*
	 * ⚠️ SAĞLAYICIYA ÖZEL İKİ ALAN.
	 *
	 * İkisi de "gönderilmediyse dokunma, boş gönderildiyse varsayılana
	 * dön" kuralında. Boşu "sil" saymak varsayılana dönmekle aynı şey
	 * burada — çünkü ikisinin de okuma tarafında bir varsayılanı var
	 * (oidc.go). Sırdan farkı bu: orada boş, geri getirilemeyecek bir
	 * kayıp olurdu.
	 */
	for key, ptr := range map[string]*string{
		auth.KeyOIDCGroupsClaim: in.GroupsClaim,
		auth.KeyOIDCScopes:      in.Scopes,
	} {
		if ptr == nil {
			continue
		}
		v := strings.TrimSpace(*ptr)
		if v == "" {
			if derr := s.store.DeleteSetting(r.Context(), key); derr != nil &&
				!errors.Is(derr, store.ErrNotFound) {
				s.storeErr(w, "oidc.set", derr)
				return
			}
			continue
		}
		if err := s.store.SetSetting(r.Context(), key, v, false, actor); err != nil {
			s.storeErr(w, "oidc.set", err)
			return
		}
	}

	for key, val := range map[string]string{
		auth.KeyOIDCIssuer:   issuer,
		auth.KeyOIDCClientID: clientID,
		auth.KeyOIDCManaged:  "1",
	} {
		if err := s.store.SetSetting(r.Context(), key, val, false, actor); err != nil {
			s.storeErr(w, "oidc.set", err)
			return
		}
	}
	// Sır YALNIZCA gönderildiyse yazılıyor: alan yoksa "değiştirme"
	// demek. Boş dize göndermek de "temizle" DEĞİL — public client
	// kurulumu geçerli ve sırrın olmaması normal, ama onu kazayla
	// silmek istemiyoruz.
	if in.Secret != nil {
		if err := s.store.SetSetting(r.Context(), auth.KeyOIDCClientSecret,
			*in.Secret, true, actor); err != nil {
			if strings.Contains(err.Error(), "secret key not configured") {
				writeErr(w, http.StatusBadRequest,
					"cannot store secrets: run `postern secret init` on the bastion host first")
				return
			}
			s.storeErr(w, "oidc.set", err)
			return
		}
	}
	s.audit(r, "oidc.set", issuer, "client id "+clientID)

	live, why := s.reloadOIDC(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "live": live, "error": why,
	})
}

/*
 * reloadOIDC, saklanan ayarlardan istemciyi YENİDEN kurar.
 *
 * ⚠️ ÖNCE DÜŞÜR, SONRA KUR. Aradaki fark bir güvenlik farkı: kurma
 * başarısız olursa sonuç "eski istemci hâlâ ayakta" değil,
 * "yapılandırma değişti, henüz çalışmıyor" olmalı.
 */
func (s *Server) reloadOIDC(ctx context.Context) (bool, string) {
	s.oidc.Clear()
	s.oidc.SetConfigured(true)

	stored, err := auth.LoadOIDC(ctx, s.store)
	if err != nil {
		return false, err.Error()
	}
	client, err := auth.NewOIDC(ctx, auth.OIDCConfig{
		IssuerURL:    stored.IssuerURL,
		ClientID:     stored.ClientID,
		ClientSecret: stored.ClientSecret,
		GroupsClaim:  stored.GroupsClaim,
		Scopes:       stored.Scopes,
		// ⚠️ Dönüş adresi ALTYAPI, ayar değil: postern'in dışarıdan
		// göründüğü adresten türüyor (http.external_url) ve panelden
		// değiştirilemez. Değiştirilebilseydi, sağlayıcıdan dönen code
		// başka bir yere yönlendirilebilirdi.
		RedirectURL: strings.TrimRight(s.externalURL, "/") + "/auth/callback",
	})
	if err != nil {
		s.logger.Error("oidc reload failed", "issuer", stored.IssuerURL, "error", err)
		return false, err.Error()
	}
	s.oidc.Install(client)
	s.logger.Info("oidc provider reloaded", "issuer", stored.IssuerURL)
	return true, ""
}

// isLoopbackURL, adres loopback mı? (ldap.isLoopback ile aynı gerekçe.)
func isLoopbackURL(raw string) bool {
	l := strings.ToLower(raw)
	return strings.HasPrefix(l, "http://127.0.0.1") ||
		strings.HasPrefix(l, "http://[::1]") ||
		strings.HasPrefix(l, "http://localhost")
}
