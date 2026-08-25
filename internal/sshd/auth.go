package sshd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/warewave/postern/internal/store"
	"golang.org/x/crypto/ssh"
)

// publicKeyCallback, anahtarın sahibini veritabanından bulur ve doğrulanmış
// adı Permissions'a koyar. Bilinmeyen anahtar "access denied"; veritabanı
// arızası ise zinciri korunmuş hâliyle yukarı çıkar — ikisi log'da ayrışmalı.
//
// context.Background(): x/crypto/ssh bu callback'e ctx geçirmiyor (API,
// context'ten eski). Oturuma bağlı bir iptal mekanizması burada yok.
func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	u, err := s.db.UserByPublicKey(context.Background(), key.Marshal())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("auth.publicKeyCallback[%s][%s]: access denied", conn.RemoteAddr(), ssh.FingerprintSHA256(key))
		}
		return nil, fmt.Errorf("auth.publicKeyCallback[%s]: %w", conn.RemoteAddr(), err)
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"postern-user": u.Name,
		},
	}, nil
}

// keyboardInteractiveCallback, OOB girişinin SSH ucu (S3.3): terminale
// login linki + güvenlik kodu basar, tarayıcı onayını bekler, doğrulanmış
// e-postayı postern kullanıcısına bağlar.
//
// publicKeyCallback ile AYNI Permissions şeklini üretir — channel.go'nun
// tek tanıdığı anahtar "postern-user", iki giriş yolu da aynı kapıya çıkar.
func (s *Server) keyboardInteractiveCallback(conn ssh.ConnMetadata,
	client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	a, err := s.logins.Start()
	if err != nil {
		return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: %w", conn.RemoteAddr(), err)
	}
	// Drop, Wait'ten HANGİ yolla çıkarsak çıkalım denemeyi yakar; başarı
	// yolunda Confirm zaten düşürdü, Drop idempotent — ikinci çağrı no-op.
	defer s.logins.Drop(a)

	// Challenge'ın hatası "istemci gitti" demektir: linki hiç görmemiş
	// olabilir. Wait'e girip tarayıcı onayı beklemek, terk edilmiş bir
	// handshake goroutine'ini s.oobTimeout boyunca yaşatmak olurdu.
	if _, err := client("", "postern login\n\n  "+a.URL+"\n\n  security code: "+
		a.UserCode+"\n\nOpen the link, sign in, and type the code.",
		nil, nil); err != nil {
		return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: challenge: %w", conn.RemoteAddr(), err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.oobTimeout)
	defer cancel()

	id, err := a.Wait(ctx)
	if err != nil {
		// İki olay ayrışsın: süre doldu mu, onay mı reddedildi? İkisi de
		// istemciye "access denied" görünür ama log farkı bilmeli.
		event := "oob login denied"
		if errors.Is(err, context.DeadlineExceeded) {
			event = "oob login timed out"
		}
		return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: %s: %w", conn.RemoteAddr(), event, err)
	}

	if id.Email == "" {
		// err burada NİL — kendi mesajı olmak zorunda. Doğrulanmamış
		// e-posta Identity'ye hiç binmediği için bu dal "IdP e-postayı
		// doğrulamamış" demek: eşleştirilecek kimlik yok.
		return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: identity has no verified email", conn.RemoteAddr())
	}

	// Wait'in ctx'i giriş beklemek için biçilmişti ve işi bitti; sorgu
	// için taze, kısa bir süre. Background kullanmak da olurdu ama asılı
	// bir veritabanı bu goroutine'i sonsuza dek tutardı.
	qctx, qcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer qcancel()

	u, err := s.db.UserByEmail(qctx, id.Email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// "IdP'de hesap var" ≠ "postern'de hesap var". Ret; arıza değil.
			return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: no postern user for verified email: access denied", conn.RemoteAddr())
		}
		// Arıza: zincir korunur, log gerçek sebebi görür.
		return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: %w", conn.RemoteAddr(), err)
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"postern-user": u.Name,
		},
	}, nil
}
