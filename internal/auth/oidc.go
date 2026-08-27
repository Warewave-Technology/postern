// Package auth implements postern's web-side authentication: OIDC login
// (S3.2), the out-of-band SSH flow that uses it (S3.3) and TOTP (S5).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	// ErrStateMismatch: callback'teki state, bu girişim için üretilenle
	// aynı değil. Bu bir CSRF işaretidir — Warpgate'in CVE-2026-44347'si
	// tam olarak bu kontrolün yokluğuydu: saldırgan kendi login'inin
	// callback'ini kurbanın oturumuna yedirebiliyordu.
	ErrStateMismatch = errors.New("auth: state mismatch")

	// ErrNonceMismatch: ID token'daki nonce beklenenle aynı değil —
	// token bu giriş DENEMESİ için kesilmemiş (tekrar oynatma işareti).
	ErrNonceMismatch = errors.New("auth: nonce mismatch")

	errNotImplemented = errors.New("auth: not implemented")
)

// OIDCConfig, bir OpenID Connect sağlayıcısına bağlanmak için gerekenler.
type OIDCConfig struct {
	// IssuerURL, sağlayıcının kök adresi. Discovery belgesi
	// <issuer>/.well-known/openid-configuration adresinden okunur; token
	// içindeki "iss" claim'i de BİREBİR bununla karşılaştırılır.
	IssuerURL string

	// ClientID, postern'in sağlayıcıdaki kaydı. ID token'ın "aud"
	// claim'i bu olmak zorunda — go-oidc doğruluyor.
	ClientID string

	// ClientSecret boş olabilir: CLI/OOB akışında postern "public
	// client"tır, sırrı yoktur; onun yerini PKCE tutar.
	ClientSecret string

	// RedirectURL, sağlayıcının code'u geri getireceği adres. Sağlayıcı
	// tarafında kayıtlı olanla birebir aynı olmalı.
	RedirectURL string

	// GroupsClaim, grup adlarını taşıyan claim. Boşsa "groups".
	//
	// YAPILANDIRILABİLİR olması bilinçli: Warpgate'in sabit
	// "warpgate_roles" adı, insanların gruplarını "groups" claim'ine
	// koyup hiçbir eşleşme görmemesinin ve sebebini bulamamasının
	// kaynağı (issue #1283). Her IdP farklı ad kullanır: Keycloak
	// "groups", Entra "roles", bazı kurulumlar "memberOf".
	GroupsClaim string
}

// defaultGroupsClaim, GroupsClaim boş bırakıldığında kullanılan ad.
const defaultGroupsClaim = "groups"

// OIDC, tek bir sağlayıcıya karşı giriş akışı yürütür.
//
// Alanlar NewOIDC'de dolduruluyor; sonrasında salt okunur — aynı OIDC
// değeri eşzamanlı akışlarca paylaşılabilir.
type OIDC struct {
	cfg      OIDCConfig
	provider *oidc.Provider
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// Identity, doğrulanmış bir ID token'dan çıkan kimlik.
//
// S3.3 bunu postern kullanıcısına e-posta üzerinden bağlayacak
// (users.email — o sütun ilk günden bunun için vardı).
type Identity struct {
	// Issuer ve Subject BİRLİKTE kimliğin KALICI anahtarıdır ("iss" +
	// "sub"). OIDC'de sub sağlayıcı içinde yeniden atanmaz.
	//
	// ⚠️ EŞLEŞTİRME BUNLARLA YAPILIR, Username ile DEĞİL. Username
	// preferred_username claim'inden geliyor ve birçok sağlayıcıda
	// kullanıcının kendi değiştirebildiği bir alan; onunla eşleştirmek,
	// adını değiştirebilen herkese var olan bir postern hesabını
	// (is_admin bayrağı dahil) devretmek demekti.
	Issuer  string
	Subject string

	// Email, eşleştirmede kullanılacak adres. yalnızca email_verified
	// true ise doldurulur — doğrulanmamış e-posta, sahibi olmayan bir
	// iddiadır ve kimlik eşleştirmesinde kullanılamaz.
	Email string

	// Username, IdP'nin verdiği kullanıcı adı (preferred_username).
	// JIT sağlamada hem postern kullanıcı adı hem hedeflerdeki hesap adı
	// olacak — kurumsal ortamda "isim.soyisim".
	Username string

	// Groups, IdP'nin bildirdiği grup adları. Hangi claim'den okunacağı
	// yapılandırılabilir (OIDCConfig.GroupsClaim).
	Groups []string
}

// AuthRequest, TEK bir giriş denemesinin durumu.
//
// Begin üretir, çağıran saklar (S3.3'te bekleyen SSH bağlantısının
// yanında), Exchange tüketir. TEK KULLANIMLIKTIR: başarılı ya da
// başarısız, bir Exchange'den sonra atılmalı — aynı state'in ikinci kez
// kabulü, tekrar oynatmaya kapı açar. (Saklama ve süre aşımı S3.3'ün
// işi; bu paket yalnızca protokolü bilir.)
type AuthRequest struct {
	// State, callback'i BU denemeye bağlayan CSRF değeri. URL'ye gider,
	// callback'te geri gelir, Exchange'de karşılaştırılır.
	State string

	// Nonce, ID token'ı bu denemeye bağlayan değer. URL'ye gider,
	// sağlayıcı token'ın İÇİNE koyar, VerifyIDToken karşılaştırır.
	// State kanalı korur, nonce token'ı korur — ikisi aynı şey değil.
	Nonce string

	// Verifier, PKCE'nin sırrı. URL'ye SHA-256 özeti gider
	// (code_challenge), token isteğinde kendisi gider. Code'u çalan
	// biri verifier olmadan token alamaz.
	Verifier string

	// URL, kullanıcının tarayıcıda açacağı yetkilendirme adresi.
	URL string
}

func NewOIDC(ctx context.Context, cfg OIDCConfig) (*OIDC, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth.NewOIDC: %w", err)
	}

	o := OIDC{
		cfg:      cfg,
		provider: provider,
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}
	return &o, nil
}

func (o *OIDC) Begin() (AuthRequest, error) {
	var authReq AuthRequest

	state, err := newID()
	if err != nil {
		return authReq, fmt.Errorf("auth.Begin: %w", err)
	}

	nonce, err := newID()
	if err != nil {
		return authReq, fmt.Errorf("auth.Begin: %w", err)
	}

	verifier, err := newID()
	if err != nil {
		return authReq, fmt.Errorf("auth.Begin: %w", err)
	}

	authReq.State = state
	authReq.Nonce = nonce
	authReq.Verifier = verifier
	authReq.URL = o.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))

	return authReq, nil
}

func (o *OIDC) Exchange(ctx context.Context, req AuthRequest, gotState, code string) (Identity, error) {
	var identity Identity

	if subtle.ConstantTimeCompare([]byte(req.State), []byte(gotState)) != 1 {
		return identity, ErrStateMismatch
	}

	token, err := o.oauth.Exchange(ctx, code, oauth2.VerifierOption(req.Verifier))
	if err != nil {
		return identity, fmt.Errorf("auth.Exchange: %w", err)
	}

	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		return identity, fmt.Errorf("auth.Exchange: no id_token in response (missing openid scope?)")
	}

	return o.VerifyIDToken(ctx, rawID, req.Nonce)
}

func (o *OIDC) VerifyIDToken(ctx context.Context, raw, expectedNonce string) (Identity, error) {
	var identity Identity

	idToken, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return identity, fmt.Errorf("auth.VerifyIDToken: %w", err)
	}

	if expectedNonce != "" {
		if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(expectedNonce)) != 1 {
			return identity, ErrNonceMismatch
		}
	}

	var c struct {
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&c); err != nil {
		return identity, fmt.Errorf("auth.VerifyIDToken: %w", err)
	}

	identity.Issuer = idToken.Issuer
	identity.Subject = idToken.Subject
	identity.Username = c.PreferredUsername

	if c.EmailVerified {
		identity.Email = c.Email
	}

	// Gruplar yapılandırılmış claim'den okunuyor: adı sabit olmadığı
	// için ham claim haritasına bakıp ilgili anahtarı çıkarıyoruz.
	groups, err := extractGroups(idToken, o.groupsClaim())
	if err != nil {
		return identity, fmt.Errorf("auth.VerifyIDToken: %w", err)
	}
	identity.Groups = groups

	return identity, nil
}

func newID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth.newID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// groupsClaim, yapılandırılmış claim adını ya da varsayılanı döner.
func (o *OIDC) groupsClaim() string {
	if o.cfg.GroupsClaim != "" {
		return o.cfg.GroupsClaim
	}
	return defaultGroupsClaim
}

// extractGroups, ID token'daki grup claim'ini string dizisine çevirir.
//
// Claim'in YOKLUĞU hata değil: kullanıcı hiçbir grupta olmayabilir ya da
// gruplar UserInfo'dan gelebilir. Ama VARSA ve beklenmedik bir tipteyse
// hata veriyoruz — sessizce boş liste dönmek, yöneticinin "eşleme neden
// çalışmıyor" sorusunu cevapsız bırakan tam olarak o davranış.
func extractGroups(idToken *oidc.IDToken, claim string) ([]string, error) {
	var raw map[string]any
	if err := idToken.Claims(&raw); err != nil {
		return nil, err
	}

	value, ok := raw[claim]
	if !ok || value == nil {
		return nil, nil
	}

	switch v := value.(type) {
	case []any:
		groups := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("claim %q contains a non-string element", claim)
			}
			groups = append(groups, s)
		}
		return groups, nil
	case string:
		// Bazı sağlayıcılar tek grubu düz string olarak gönderir.
		return []string{v}, nil
	default:
		return nil, fmt.Errorf("claim %q is neither a string nor a list of strings", claim)
	}
}

// GroupSource, kullanıcının grup üyeliklerini veren kaynak.
//
// İki gerçekleştirmesi var ve ikisi de aynı şeyi üretir — bir grup adı
// listesi. Senkronizasyon kodu hangisinden geldiğini BİLMEZ; policy'nin
// model.User'a bakıp kaynağı bilmemesiyle aynı desen, bir kat yukarıda.
//
//   - ClaimGroups: grupları ID token'ın claim'inden okur (S5.2).
//   - ldap.Source: LDAP dizinine sorar (S5.3).
//
// LDAP'ın kazandırdığı şey tazelik: token'daki claim giriş anında
// dondurulmuştur, LDAP ise her sorguda güncel cevap verir.
type GroupSource interface {
	Groups(ctx context.Context, id Identity) ([]string, error)
}

// ClaimGroups, grupları kimliğin kendisinden okur — yani ID token'dan.
// LDAP yapılandırılmadığında kullanılan varsayılan kaynak.
type ClaimGroups struct{}

func (ClaimGroups) Groups(_ context.Context, id Identity) ([]string, error) {
	return id.Groups, nil
}

// SwitchableGroupSource, çalışırken değiştirilebilen grup kaynağı.
//
// NEDEN GEREKLİ: LDAP ayarları panelden değiştirilebiliyor, ama grup
// kaynağını SSH tarafı (sshd.Server) ve web tarafı (httpapi.Server) ayrı
// ayrı tutuyor. İkisine ayrı nesne verseydik, panelden yapılan bir
// değişiklik yalnızca web'e işler ve SSH'tan giren kullanıcı eski
// kaynaktan yetki alırdı — "iki kapı, tek gerçek" kuralının tam
// karşıtı. Bu sarmalayıcıyı ikisi de paylaşıyor: Set bir kez çağrılır,
// her iki kapı da yeni kaynağı görür.
type SwitchableGroupSource struct {
	mu  sync.RWMutex
	src GroupSource
}

// NewSwitchableGroupSource, verilen kaynakla başlar.
func NewSwitchableGroupSource(initial GroupSource) *SwitchableGroupSource {
	return &SwitchableGroupSource{src: initial}
}

func (s *SwitchableGroupSource) Groups(ctx context.Context, id Identity) ([]string, error) {
	s.mu.RLock()
	src := s.src
	s.mu.RUnlock()
	return src.Groups(ctx, id)
}

// Set, kaynağı değiştirir. Süregelen sorgular eski kaynakla biter;
// sonrakiler yenisini kullanır.
func (s *SwitchableGroupSource) Set(src GroupSource) {
	s.mu.Lock()
	s.src = src
	s.mu.Unlock()
}
