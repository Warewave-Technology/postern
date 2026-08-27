package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
)

const (
	alphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	codeLength = 8
)

var (
	// ErrLoginDenied: giriş denemesi onaylanmadan yakıldı — yanlış
	// güvenlik kodu, süre aşımı ya da tekrar kullanım girişimi.
	ErrLoginDenied = errors.New("auth: login denied")

	// ErrUnknownAttempt: bu state'e ait bekleyen bir deneme yok (hiç
	// olmadı, süresi doldu ya da çoktan sonuçlandı).
	ErrUnknownAttempt = errors.New("auth: unknown login attempt")
)

// Logins, bekleyen OOB giriş denemelerinin kaydı.
//
// İki dünyayı buluşturur: SSH tarafı bir Attempt başlatıp Wait ile bekler;
// HTTP tarafı (tarayıcı callback'i) Lookup → [Exchange] → Park → Confirm
// zinciriyle kimliği teslim eder. Exchange'in kendisi BURADA DEĞİL: bu tip
// yalnızca eşzamanlılık ve yaşam döngüsü bilir, ağ bilmez — birim testleri
// de bu sayede IdP'siz koşar.
//
// YAŞAM DÖNGÜSÜ — her deneme bu çizgide tek yönlü ilerler:
//
//	Start ──► bekliyor ──Park──► kimlik parkta ──Confirm──► teslim ✓
//	             │                    │
//	          (timeout/Drop)      (yanlış kod / ikinci Park)
//	             ▼                    ▼
//	           yandı ✗              yandı ✗
//
// Yanan deneme geri dönmez: aynı state ile ikinci bir şans yok. Tekrar
// oynatmanın (replay) panzehiri sürecin kendisini tek kullanımlık yapmak.
type Logins struct {
	oidc *OIDC

	mu      sync.Mutex
	byState map[string]*Attempt // canlı denemeler; anahtar = state
}

// Attempt, tek bir OOB giriş denemesinin SSH tarafındaki ucu.
type Attempt struct {
	// URL, kullanıcının tarayıcıda açacağı adres (AuthRequest.URL).
	URL string

	// UserCode, terminale basılan güvenlik kodu. Tarayıcıdaki onay formuna
	// AYNEN yazılmalı. Varlık sebebi: saldırgan KENDİ login linkini kurbana
	// yollarsa, kurban girişi tamamlar ve saldırganın bekleyen SSH oturumu
	// kurbanın kimliğiyle onaylanırdı. Kod, terminali göreni tarayıcıda
	// onaylayana bağlar — linki gören değil, TERMİNALİ gören onaylayabilir.
	UserCode string

	state  string      // haritadaki anahtarım — Drop bunsuz beni bulamaz
	req    AuthRequest // Lookup bunu verecek (Exchange'e lazım)
	logins *Logins     // Wait'in defer'lı Drop'u için geri işaretçi

	parked *Identity       // Park koydu, Confirm teslim edecek
	done   bool            // uç duruma vardı mı (teslim YA DA yanma)
	result chan waitResult // Wait'in dinlediği TEK kanal, tamponu 1
}

type waitResult struct {
	id  Identity
	err error
}

func NewLogins(o *OIDC) *Logins {
	return &Logins{oidc: o, byState: make(map[string]*Attempt)}
}

func (l *Logins) Start() (*Attempt, error) {
	code, err := newCode()
	if err != nil {
		return nil, fmt.Errorf("auth.pending.Start: %w", err)
	}

	req, err := l.oidc.Begin()
	if err != nil {
		return nil, fmt.Errorf("auth.pending.Start: %w", err)
	}

	a := &Attempt{
		URL:      req.URL,
		UserCode: code,
		state:    req.State, // haritanın anahtarı — URL'den sökmek yok, elimizde zaten
		req:      req,
		logins:   l,
		result:   make(chan waitResult, 1), // ⚠️ tamponu 1 — unutulursa her şey kilitlenir
	}

	l.mu.Lock()
	l.byState[a.state] = a
	l.mu.Unlock()

	return a, nil
}

func (l *Logins) Lookup(state string) (AuthRequest, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.byState[state]
	if ok {
		return a.req, true
	}

	return AuthRequest{}, false
}

func (l *Logins) Park(state string, id Identity) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.byState[state]
	if !ok {
		return ErrUnknownAttempt
	}

	if a.parked != nil {
		l.finish(a, waitResult{err: ErrLoginDenied})
		return ErrUnknownAttempt
	}

	a.parked = &id

	return nil
}

func (l *Logins) Confirm(state, userCode string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.byState[state]
	if !ok || a.parked == nil {
		return ErrUnknownAttempt
	}

	if subtle.ConstantTimeCompare([]byte(userCode), []byte(a.UserCode)) != 1 {
		l.finish(a, waitResult{err: ErrLoginDenied})
		return ErrLoginDenied
	}

	l.finish(a, waitResult{id: *a.parked})

	return nil
}

func (a *Attempt) Wait(ctx context.Context) (Identity, error) {
	defer a.logins.Drop(a)

	select {
	case r := <-a.result:
		return r.id, r.err

	case <-ctx.Done():
		return Identity{}, ctx.Err()
	}
}

func (l *Logins) Drop(a *Attempt) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.finish(a, waitResult{err: ErrLoginDenied})
}

func (l *Logins) finish(a *Attempt, res waitResult) {
	if a.done {
		return
	}
	a.done = true
	delete(l.byState, a.state)
	a.result <- res // tampon 1 + tek gönderim garantisi: asla bloklanmaz
}

func newCode() (string, error) {
	var builder strings.Builder

	maxRange := big.NewInt(int64(len(alphabet)))
	for i := 0; i < codeLength; i++ {
		// Yarıda tire: telefon ekranından okunup elle yazılacak bir değer
		// için dörtlü gruplar tek blok 8 karakterden belirgin şekilde az
		// hata üretir. Confirm karşılaştırması tireyi de içerir — form
		// alanındaki placeholder aynı biçimi gösteriyor.
		if i == codeLength/2 {
			builder.WriteByte('-')
		}
		idx, err := rand.Int(rand.Reader, maxRange)
		if err != nil {
			return "", err
		}

		builder.WriteByte(alphabet[idx.Int64()])
	}

	return builder.String(), nil
}
