package sshd

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	for _, user := range s.cfg.Users {
		for _, publicKey := range user.PublicKeys {
			providedPublicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
			if err != nil {
				return nil, fmt.Errorf("auth.publicKeyCallback[%s]: %w", conn.RemoteAddr(), err)
			}

			if bytes.Equal(key.Marshal(), providedPublicKey.Marshal()) {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"postern-user": user.Name,
					},
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("auth.publicKeyCallback[%s][%s]: access denied", conn.RemoteAddr(), ssh.FingerprintSHA256(key))
}
