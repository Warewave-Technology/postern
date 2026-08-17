package sshd

import (
	"context"
	"time"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/proxy"
	"github.com/warewave/postern/internal/record"
	"github.com/warewave/postern/internal/upstream"
	"golang.org/x/crypto/ssh"
)

// handleChannel serves one inbound channel request: resolve the target, dial
// it, then broker the two channels until the session ends.
func (s *Server) handleChannel(ctx context.Context, sshConn *ssh.ServerConn, newChan ssh.NewChannel) {
	if newChan.ChannelType() != "session" {
		newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}

	route, err := ParseUsername(sshConn.User())
	if err != nil {
		newChan.Reject(ssh.Prohibited, "access denied")
		return
	}

	if sshConn.Permissions == nil || route.User != sshConn.Permissions.Extensions["postern-user"] {
		newChan.Reject(ssh.Prohibited, "access denied")
		return
	}

	var target config.TargetConfig
	var found bool

	for _, t := range s.cfg.Targets {
		if t.Name == route.Target {
			target = t
			found = true
			break
		}
	}

	if !found {
		newChan.Reject(ssh.ConnectionFailed, "unknown target")
		return
	}

	conn, err := upstream.Dial(ctx, target)
	if err != nil {
		s.logger.Error("sshd.handleChannel.upstream.dial",
			"error", err,
			"target", target.Name,
			"user", route.User,
		)
		newChan.Reject(ssh.ConnectionFailed, "connection failed")
		return
	}
	defer conn.Close()

	up, upR, err := conn.OpenSession()
	if err != nil {
		s.logger.Error("sshd.handleChannel.conn.opensession",
			"error", err,
			"target", target.Name,
			"user", route.User,
		)
		newChan.Reject(ssh.ConnectionFailed, "connection failed")
		return
	}

	id, err := record.NewSessionID()
	if err != nil {
		s.logger.Error("sshd.handleChannel.record.uuid",
			"error", err,
			"target", target.Name,
			"user", route.User,
		)
		newChan.Reject(ssh.ConnectionFailed, "recording unavailable")
		return
	}

	f, path, err := s.rStore.Create(id)
	if err != nil {
		s.logger.Error("sshd.handleChannel.record.folder_create",
			"error", err,
			"target", target.Name,
			"user", route.User,
		)
		newChan.Reject(ssh.ConnectionFailed, "recording unavailable")
		return
	}

	// TERM pty-req ile gelir, yani başlık yazılırken henüz bilinmiyor: boş
	// string yazmaktansa alanı hiç koymuyoruz (omitempty). Boyut da 80x24
	// varsayılanıyla başlar, broker pty-req'i görünce Resize ile düzeltir.
	rec, err := record.NewWriter(f, 80, 24, nil)
	if err != nil {
		s.logger.Error("sshd.handleChannel.record.rec",
			"error", err,
			"target", target.Name,
			"user", route.User,
		)
		newChan.Reject(ssh.ConnectionFailed, "recording unavailable")
		return
	}

	// Kapanış ve kayıt sağlığı tek yerde. Err() ancak Close'dan SONRA
	// anlamlıdır: yapışkan hata oturum boyunca birikir ve adaptörler kayıt
	// arızasını yutup oturumu yaşatır — bu satır olmazsa bozuk kayıt tamamen
	// sessiz kalır.
	defer func() {
		if cerr := rec.Close(); cerr != nil {
			s.logger.Error("recording close failed",
				"error", cerr,
				"target", target.Name,
				"user", route.User,
				"id", id,
			)
		}
		if rerr := rec.Err(); rerr != nil {
			s.logger.Error("recording degraded — session was not fully captured",
				"error", rerr,
				"target", target.Name,
				"user", route.User,
				"id", id,
				"record_path", path,
			)
		}
	}()

	down, downR, err := newChan.Accept()
	if err != nil {
		s.logger.Error("sshd.handleChannel.channel.accept",
			"error", err,
			"target", target.Name,
			"user", route.User,
		)
		return
	}

	start := time.Now()
	s.logger.Info("session started",
		"target", target.Name,
		"user", route.User,
		"id", id,
		"record_path", path,
	)
	err = proxy.New(down, downR, up, upR, rec, s.cfg.Recording.RecordInput, s.logger).Run(ctx)
	if err != nil {
		s.logger.Error("sshd.handleChannel.proxy.run",
			"error", err,
			"target", target.Name,
			"user", route.User,
		)
	}
	s.logger.Info("session ended",
		"target", target.Name,
		"user", route.User,
		"duration", time.Since(start),
		"id", id,
		"record_path", path,
	)
}
