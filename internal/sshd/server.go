// Package sshd implements the inbound (server-side) half of the bastion:
// listener, handshake, authentication and channel dispatch.
package sshd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/record"
)

// Server accepts inbound SSH connections on behalf of the bastion.
type Server struct {
	cfg    *config.Config
	signer ssh.Signer // bastion'ın kendi host key'i
	logger *slog.Logger
	rStore *record.Store
}

// New loads the host key from cfg.HostKey and prepares the server.
func New(cfg *config.Config, logger *slog.Logger) (*Server, error) {
	data, err := os.ReadFile(cfg.HostKey)
	if err != nil {
		return nil, fmt.Errorf("sshd.New: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("sshd.New: %w", err)
	}

	store, err := record.NewStore(cfg.Recording.Dir)
	if err != nil {
		return nil, fmt.Errorf("sshd.New: %w", err)
	}

	return &Server{cfg: cfg, signer: signer, logger: logger, rStore: store}, nil
}

// ListenAndServe listens on cfg.Listen.Addr and hands the listener to Serve.
func (s *Server) ListenAndServe(ctx context.Context) error {
	l, err := net.Listen("tcp", s.cfg.Listen.Addr)
	if err != nil {
		return err
	}

	return s.Serve(ctx, l)
}

// Serve accepts connections from l until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	stopped := make(chan struct{})
	defer close(stopped)

	go func() {
		select {
		case <-ctx.Done():
			l.Close()
		case <-stopped:
		}
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}

		go s.handleConn(ctx, conn)
	}
}

// handleConn runs the SSH handshake and (from S1.5 on) dispatches channels.
func (s *Server) handleConn(ctx context.Context, nConn net.Conn) {
	defer nConn.Close()

	scfg, err := s.serverConfig()
	if err != nil {
		s.logger.Error("handleConn.serverConfig", "err", err)
		return
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, scfg)
	if err != nil {
		s.logger.Warn("handleConn.NewServerConn", "err", err)
		return
	}

	s.logger.Info("ssh handshake ok",
		"user", sshConn.User(),
		"postern_user", sshConn.Permissions.Extensions["postern-user"],
		"remote", sshConn.RemoteAddr(),
	)

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		go s.handleChannel(ctx, sshConn, newChan)
	}
}

// serverConfig builds the ssh.ServerConfig used for handshakes.
func (s *Server) serverConfig() (*ssh.ServerConfig, error) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: s.publicKeyCallback,
		ServerVersion:     "SSH-2.0-postern",
	}
	cfg.AddHostKey(s.signer)
	return cfg, nil
}
