// Package sshd implements the inbound (server-side) half of the bastion:
// listener, handshake, authentication and channel dispatch.
package sshd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ca"
	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/proxy"
	"github.com/warewave/postern/internal/record"
	"github.com/warewave/postern/internal/store"
)

// oobTimeout, tarayıcı onayı için üst sınır. Çok kısa olursa insan
// yetişemez (telefonda MFA var), çok uzun olursa yarım denemeler handshake
// goroutine'lerini bekletir.
const oobTimeout = 2 * time.Minute

// Server accepts inbound SSH connections on behalf of the bastion.
type Server struct {
	cfg    *config.Config
	signer ssh.Signer // bastion'ın kendi host key'i
	logger *slog.Logger

	rStore *record.Store
	db     *store.Store

	authority *ca.CA

	// logins nil değilse keyboard-interactive OOB girişi açık: anahtarı
	// olmayan insanlar tarayıcıda OIDC ile girer. Public key yolu her
	// durumda çalışmaya devam eder (makineler/otomasyon).
	logins     *auth.Logins
	oobTimeout time.Duration

	// groups, OOB girişinde kullanılacak grup kaynağı. httpapi ile AYNI
	// olmalı: iki kapı aynı yetkiyi vermeli.
	groups auth.GroupSource
}

// UseGroupSource, grup kaynağını değiştirir (LDAP için).
// Dinlemeye başlamadan ÖNCE çağrılmalı.
func (s *Server) UseGroupSource(src auth.GroupSource) { s.groups = src }

// ProxyDeps, oturum akışının ihtiyaç duyduğu altyapıyı döner.
//
// httpapi ile PAYLAŞILIR: web terminali ve SSH aynı store'u, aynı kayıt
// dizinini ve aynı CA'yı kullanmalı — iki kapı, tek gerçek.
func (s *Server) ProxyDeps() proxy.Deps {
	return proxy.Deps{
		Store:       s.db,
		Records:     s.rStore,
		Authority:   s.authority,
		Logger:      s.logger,
		RecordInput: s.cfg.Recording.RecordInput,
		Requests:    proxy.RequestPolicy{AcceptEnv: s.cfg.Session.AcceptEnv},
	}
}

// EnableOOB, tarayıcı destekli girişi açar. serve, config'te oidc+http
// varsa çağırır; testler ve OIDC'siz kurulumlar hiç çağırmaz.
// timeout 0 ise varsayılan (oobTimeout) kullanılır — testler kısaltabilir.
//
// Dinlemeye başlamadan ÖNCE çağrılmalı: alanlar kilitsiz, eşzamanlı
// handshake'lerle yarışmamalı.
func (s *Server) EnableOOB(logins *auth.Logins, timeout time.Duration) {
	if timeout <= 0 {
		timeout = oobTimeout
	}
	s.logins = logins
	s.oobTimeout = timeout
}

// New prepares the server.
func New(cfg *config.Config, db *store.Store, logger *slog.Logger) (*Server, error) {
	data, err := os.ReadFile(cfg.HostKey)
	if err != nil {
		return nil, fmt.Errorf("sshd.New: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("sshd.New: %w", err)
	}

	recStore, err := record.NewStore(cfg.Recording.Dir)
	if err != nil {
		return nil, fmt.Errorf("sshd.New: %w", err)
	}

	caAuthority, err := ca.Load(cfg.CA.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("sshd.New: %w", err)
	}

	return &Server{
		cfg: cfg, signer: signer, logger: logger,
		rStore: recStore, db: db, authority: caAuthority,
		groups: auth.ClaimGroups{},
	}, nil
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
	if s.logins != nil {
		// nil kaldıkça istemciye bu yöntem hiç sunulmaz — OIDC'siz
		// kurulum eskisi gibi yalnızca public key konuşur.
		cfg.KeyboardInteractiveCallback = s.keyboardInteractiveCallback
	}
	cfg.AddHostKey(s.signer)
	return cfg, nil
}
