package sshd

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/warewave/postern/internal/policy"
	"github.com/warewave/postern/internal/proxy"
	"github.com/warewave/postern/internal/record"
	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/upstream"
	"golang.org/x/crypto/ssh"
)

// handleChannel serves one inbound channel request: resolve the target, dial
// it, then broker the two channels until the session ends.
//
// LOG SÖZLEŞMESİ — bu dosyadaki satırlar bu kurallara uyar:
//
//   - MESAJ kısa, sabit ve insan okunur bir OLAY ADIDIR ("access denied by
//     policy"), kod yolu değil ("sshd.handleChannel.upstream.dial"). Kod
//     yolunu zaten dosya/satır verir; mesaj NE OLDUĞUNU söylemeli. Aynı
//     mesajı üç farklı olay için kullanmak, log'u okunamaz hale getirir.
//
//   - ALAN ADLARI snake_case ve bütün satırlarda AYNI: user, target,
//     os_user, session_id, record_path, remote, error. Aynı kavramı iki
//     ayrı adla yazmak (user/username) log aramayı imkânsızlaştırır.
//
//   - SEVİYE: Error = "birinin müdahale etmesi gerek" (disk doldu, hedef
//     erişilemiyor). Yetki reddi bir arıza DEĞİL, güvenlik olayıdır → Warn.
//     Rutin akış → Info.
//
//   - KİMLİK her zaman DOĞRULANMIŞ addır (postern-user), istemcinin iddia
//     ettiği değil. İddia edilen ad ancak "uyuşmazlık" olayında, ayrı bir
//     alanla loglanır.
//
//   - Ortak alanlar logger'a bir kez With ile bağlanır; her satırda elle
//     tekrarlanmaz. Tekrar eden alanlar er geç birbirinden ayrışır.
//
//   - Saldırgan kontrolündeki ham girdi (kullanıcı adının tamamı) log'a
//     KOYULMAZ; sebep yeterlidir. slog değerleri tırnaklar, ama gereksiz
//     veriyi taşımamak daha iyidir.
func (s *Server) handleChannel(ctx context.Context, sshConn *ssh.ServerConn, newChan ssh.NewChannel) {
	// remote bütün satırlarda işe yarar: aynı kullanıcının farklı yerlerden
	// gelen denemelerini ayırt eder.
	log := s.logger.With("remote", sshConn.RemoteAddr().String())

	if newChan.ChannelType() != "session" {
		log.Warn("channel type rejected", "channel_type", newChan.ChannelType())
		newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}

	route, err := ParseUsername(sshConn.User())
	if err != nil {
		log.Warn("username rejected", "error", err)
		newChan.Reject(ssh.Prohibited, "access denied")
		return
	}

	if sshConn.Permissions == nil || route.User != sshConn.Permissions.Extensions["postern-user"] {
		// Kimlik uyuşmazlığı: istemci başka birinin adıyla oturum açmaya
		// çalışıyor. İddia edilen ad burada ayrı bir alanla loglanır.
		log.Warn("identity mismatch", "claimed_user", route.User)
		newChan.Reject(ssh.Prohibited, "access denied")
		return
	}

	target, err := s.db.Target(ctx, route.Target)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			log.Warn("target not found", "target", route.Target, "error", err)
			newChan.Reject(ssh.ConnectionFailed, "connection failed")
			return
		}
		log.Error("target lookup failed", "target", route.Target, "error", err)
		newChan.Reject(ssh.ConnectionFailed, "connection failed")
		return
	}

	posternUser := sshConn.Permissions.Extensions["postern-user"]

	// Bundan sonrası tek bir oturuma ait: kimlik ve hedef her satırda olsun.
	log = log.With("user", posternUser, "target", target.Name)

	u, err := s.db.User(ctx, posternUser)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			log.Warn("user not found")
			newChan.Reject(ssh.ConnectionFailed, "access denied")
			return
		}
		log.Error("user lookup failed", "error", err)
		newChan.Reject(ssh.ConnectionFailed, "connection failed")
		return
	}

	d := policy.Authorize(u, target, "")
	if !d.Allowed {
		// Reason politikanın kendi cümlesi; audit'te "neden reddedildi"
		// sorusunun cevabı bu. İstemciye gitmez, yalnızca log'a.
		log.Warn("access denied by policy", "reason", d.Reason)
		newChan.Reject(ssh.ConnectionFailed, "access denied")
		return
	}

	conn, err := upstream.DialWithCert(ctx, target, upstream.Identity{
		PosternUser: posternUser,
		OSUser:      d.OSUser,
	}, s.authority)
	if err != nil {
		log.Error("target dial failed", "error", err, "os_user", d.OSUser)
		newChan.Reject(ssh.ConnectionFailed, "connection failed")
		return
	}
	defer conn.Close()

	up, upR, err := conn.OpenSession()
	if err != nil {
		log.Error("upstream session open failed", "error", err)
		newChan.Reject(ssh.ConnectionFailed, "connection failed")
		return
	}

	id, err := record.NewSessionID()
	if err != nil {
		log.Error("session id generation failed", "error", err)
		newChan.Reject(ssh.ConnectionFailed, "recording unavailable")
		return
	}

	f, path, err := s.rStore.Create(id)
	if err != nil {
		log.Error("recording file create failed", "error", err)
		newChan.Reject(ssh.ConnectionFailed, "recording unavailable")
		return
	}

	// TERM pty-req ile gelir, yani başlık yazılırken henüz bilinmiyor: boş
	// string yazmaktansa alanı hiç koymuyoruz (omitempty). Boyut da 80x24
	// varsayılanıyla başlar, broker pty-req'i görünce Resize ile düzeltir.
	rec, err := record.NewWriter(f, 80, 24, nil)
	if err != nil {
		log.Error("recorder init failed", "error", err)
		newChan.Reject(ssh.ConnectionFailed, "recording unavailable")
		return
	}

	// Kapanış ve kayıt sağlığı tek yerde. Err() ancak Close'dan SONRA
	// anlamlıdır: yapışkan hata oturum boyunca birikir ve adaptörler kayıt
	// arızasını yutup oturumu yaşatır — bu satır olmazsa bozuk kayıt tamamen
	// sessiz kalır.
	// id ve kayıt yolu artık biliniyor: oturumun geri kalanında her satırda
	// bulunsunlar. S3'te bu üçlü (user, target, session_id) sessions
	// tablosunun anahtarları olacak.
	log = log.With("session_id", id, "record_path", path)

	defer func() {
		if cerr := rec.Close(); cerr != nil {
			log.Error("recording close failed", "error", cerr)
		}
		if rerr := rec.Err(); rerr != nil {
			log.Error("recording degraded, session not fully captured", "error", rerr)
		}
	}()

	start := time.Now()

	host, _, err := net.SplitHostPort(sshConn.Conn.RemoteAddr().String())
	if err != nil {
		log.Error("remote addr parse failed", "error", err)
		newChan.Reject(ssh.ConnectionFailed, "session unavailable")
		return
	}

	err = s.db.StartSession(ctx, store.SessionStart{
		ID: id, Username: posternUser, TargetName: target.Name,
		OSUser: d.OSUser, SrcIP: host, StartedAt: start,
		RecordingPath: path,
	})
	if err != nil {
		log.Error("start session failed", "error", err)
		newChan.Reject(ssh.ConnectionFailed, "session unavailable")
		return
	}
	defer func() {
		if serr := s.db.EndSession(context.WithoutCancel(ctx), id, time.Now()); serr != nil {
			log.Error("end session failed", "error", serr)
		}
	}()

	down, downR, err := newChan.Accept()
	if err != nil {
		log.Error("channel accept failed", "error", err)
		return
	}

	log.Info("session started", "os_user", d.OSUser)
	err = proxy.New(down, downR, up, upR, rec, s.cfg.Recording.RecordInput, s.logger).Run(ctx)
	if err != nil {
		log.Error("session broker failed", "error", err)
	}

	err = s.db.EndSession(context.WithoutCancel(ctx), id, time.Now())
	if err != nil {
		log.Error("end session failed", "error", err)
	}

	log.Info("session ended", "os_user", d.OSUser, "duration", time.Since(start))
}
