// Package upstream implements the outbound (client-side) half of the
// bastion: dialing targets and opening channels on their behalf.
package upstream

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/config"
)

// Conn is an established SSH connection to a target.
type Conn struct {
	client *ssh.Client
	target config.TargetConfig
}

// Dial connects to target t as an SSH client, authenticating with the key
// at t.KeyFile. The target's host key MUST match t.HostKey.
func Dial(ctx context.Context, t config.TargetConfig) (*Conn, error) {
	data, err := os.ReadFile(t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	cb, algos, err := hostKeyCallback(t.HostKey)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	ccfg := &ssh.ClientConfig{
		User:              t.User,
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

// Client exposes the underlying SSH client — S1.4 testleri session açmak,
// S1.5 broker'ı hedefte kanal açmak için kullanacak.
func (c *Conn) Client() *ssh.Client { return c.client }

// Close closes the connection to the target.
func (c *Conn) Close() error {
	if c != nil && c.client != nil {
		return c.client.Close()
	}

	return nil
}
