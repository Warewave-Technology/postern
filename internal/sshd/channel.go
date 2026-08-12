package sshd

import (
	"context"
	"time"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/proxy"
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
	)
	err = proxy.New(down, downR, up, upR, s.logger).Run(ctx)
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
	)
}
