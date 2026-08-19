package ca

import (
	"crypto/rand"
	"fmt"
	"maps"
	"math/big"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	timeShiftSec = 60 * time.Second
)

type CertRequest struct {
	PublicKey ssh.PublicKey

	KeyID string

	Principals []string

	ValidFor time.Duration

	Extensions map[string]string
}

func (c *CA) Sign(req CertRequest) (*ssh.Certificate, error) {
	if len(req.Principals) == 0 {
		return nil, fmt.Errorf("ca.Sign: req.Principals has no member")
	}

	if req.KeyID == "" {
		return nil, fmt.Errorf("ca.Sign: req.KeyID is empty")
	}

	if req.PublicKey == nil {
		return nil, fmt.Errorf("ca.Sign: req.PublicKey is empty")
	}

	if req.ValidFor <= timeShiftSec {
		return nil, fmt.Errorf("ca.Sign: cert lifetime too short")
	}

	validAfter := time.Now().Add(-timeShiftSec)
	validBefore := validAfter.Add(req.ValidFor)

	serial, err := generateRandomSerial64()
	if err != nil {
		return nil, fmt.Errorf("ca.Sign: %w", err)
	}

	sshPermissionExtensions := map[string]string{
		"permit-pty": "",
	}
	if len(req.Extensions) > 0 {
		maps.Copy(sshPermissionExtensions, req.Extensions)
	}

	cert := ssh.Certificate{
		Key:             req.PublicKey,
		CertType:        ssh.UserCert,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		ValidPrincipals: req.Principals,
		Serial:          serial,
		KeyId:           req.KeyID,
		Permissions:     ssh.Permissions{Extensions: sshPermissionExtensions},
	}

	err = cert.SignCert(rand.Reader, c.signer)
	if err != nil {
		return nil, fmt.Errorf("ca.Sign: %w", err)
	}

	return &cert, nil
}

func generateRandomSerial64() (uint64, error) {
	// OpenSSH uses a uint64 (8 bytes) for certificate serial tracking numbers
	max := new(big.Int).SetUint64(18446744073709551615) // Max uint64
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}
	return n.Uint64(), nil
}
