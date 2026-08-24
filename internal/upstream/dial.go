// Package upstream implements the outbound (client-side) half of the
// bastion: dialing targets and opening channels on their behalf.
package upstream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/ca"
	"github.com/warewave/postern/internal/model"
)

// Conn is an established SSH connection to a target.
type Conn struct {
	client *ssh.Client
	target model.Target
}

// Client exposes the underlying SSH client
func (c *Conn) Client() *ssh.Client { return c.client }

// Close closes the connection to the target.
func (c *Conn) Close() error {
	if c != nil && c.client != nil {
		return c.client.Close()
	}

	return nil
}

const certValidFor = 5 * time.Minute

type Identity struct {
	PosternUser string

	OSUser string
}

// DialWithCert connects to t using a freshly minted, short-lived certificate
// instead of a static key.
func DialWithCert(ctx context.Context, t model.Target, identity Identity, authority *ca.CA) (*Conn, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	ephemeralSigner, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	cert, err := authority.Sign(ca.CertRequest{
		PublicKey:  ephemeralSigner.PublicKey(),
		KeyID:      identity.PosternUser,
		Principals: []string{identity.OSUser},
		ValidFor:   certValidFor,
		Extensions: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	signer, err := ssh.NewCertSigner(cert, ephemeralSigner)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	conn, err := dialer(ctx, t, identity.OSUser, signer)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	return conn, nil
}

// dialer, hedefe bağlanmanın ortak yolu. Kullanıcı adı PARAMETRE: sertifika
// modelinde hangi hesapla açılacağı config'in değil, oturumun kararıdır
// (policy.Authorize üretir) ve sertifikanın principal'ıyla aynı olmak
// zorundadır.
func dialer(ctx context.Context, t model.Target, user string, signer ssh.Signer) (*Conn, error) {
	cb, algos, err := hostKeyCallback(t.HostKey)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	ccfg := &ssh.ClientConfig{
		User:              user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   cb,
		HostKeyAlgorithms: algos,
	}

	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))

	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	stop := context.AfterFunc(ctx, func() { nc.Close() })
	defer stop()

	c, chans, reqs, err := ssh.NewClientConn(nc, addr, ccfg)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	client := ssh.NewClient(c, chans, reqs)

	return &Conn{client: client, target: t}, nil
}
