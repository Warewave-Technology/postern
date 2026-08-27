// Package ca owns postern's SSH certificate authority: the CA key's
// lifecycle and (from S2.2 on) certificate signing.
package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// CA holds the signing key. Bir postern kurulumunda tek bir CA vardır.
type CA struct {
	signer ssh.Signer
}

// Init generates a new CA key at path and returns the ready CA.
func Init(path string) (*CA, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca.Init: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return nil, fmt.Errorf("ca.Init: %w", err)
	}

	// #nosec G304 -- yol config'teki ca.key_file; operatör girdisi
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("ca.Init: %w", err)
	}
	defer f.Close()

	err = pem.Encode(f, pemBlock)
	if err != nil {
		return nil, fmt.Errorf("ca.Init: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("ca.Init: %w", err)
	}

	return &CA{signer: signer}, nil
}

// Load reads an existing CA key from path.
func Load(path string) (*CA, error) {
	stats, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("ca.Load: %w, path: %s", err, path)
	}

	filePerm := stats.Mode().Perm()
	leakingBits := filePerm & 0077

	if leakingBits != 0 {
		return nil, fmt.Errorf("ca.Load: permissions %#o are too open, path: %s", filePerm, path)
	}

	// #nosec G304 -- yol config'teki ca.key_file; operatör girdisi
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca.Load: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("ca.Load: %w", err)
	}

	return &CA{signer: signer}, nil
}

// PublicKey returns the CA's public half — the content targets put in
// TrustedUserCAKeys.
func (c *CA) PublicKey() ssh.PublicKey {
	return c.signer.PublicKey()
}

// AuthorizedKey returns the public key as a single authorized-keys line,
// ready to be pasted into /etc/ssh/postern_ca.pub.
func (c *CA) AuthorizedKey() string {
	return string(ssh.MarshalAuthorizedKey(c.PublicKey()))
}

// NOT — S2.2 (`sign.go`) SENİN dosyan (plan §0). Bu paket ona şunları
// hazırlıyor: c.signer aynı pakette olduğu için doğrudan erişilebilir.
// Sertifika imzalamanın kuralları planda S2.2'de madde madde yazılı;
// oraya geldiğimizde test iskeletini ben vereceğim, kodu sen yazacaksın.
