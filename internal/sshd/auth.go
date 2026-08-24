package sshd

import (
	"context"
	"errors"
	"fmt"

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
	// publicKeyCallback, anahtarın sahibini veritabanından bulur ve doğrulanmış
	// adı Permissions'a koyar. Bilinmeyen anahtar "access denied"; veritabanı
	// arızası ise zinciri korunmuş hâliyle yukarı çıkar — ikisi log'da ayrışmalı.
	//
	// context.Background(): x/crypto/ssh bu callback'e ctx geçirmiyor (API,
	// context'ten eski). Oturuma bağlı bir iptal mekanizması burada yok.
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
