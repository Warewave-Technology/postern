package upstream

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

// hostKeyCallback returns a callback accepting EXACTLY the host key given
// in the config (authorized-keys single-line format: "ssh-ed25519 AAAA...").
func hostKeyCallback(expected string) (ssh.HostKeyCallback, []string, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(expected))
	if err != nil {
		return nil, nil, fmt.Errorf("upstream.hostKeyCallback: %w", err)
	}

	return ssh.FixedHostKey(publicKey), []string{publicKey.Type()}, nil
}
