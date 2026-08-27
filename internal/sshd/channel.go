package sshd

import (
	"context"
	"errors"
	"net"

	"github.com/warewave/postern/internal/proxy"
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

	posternUser := sshConn.Permissions.Extensions["postern-user"]

	// Bundan sonrası tek bir oturuma ait: kimlik ve hedef her satırda olsun.
	//
	// route.Target SALDIRGAN KONTROLÜNDE: ParseUsername bilerek kayıpsız
	// ve satır sonu, NUL, ESC geçirebiliyor. Bunu loglamayı güvenli kılan
	// şey slog'un TextHandler'ının alıntılaması — ölçüldü: 0x00-0x1f'in
	// tamamı kaçışlanıyor, sahte bir log satırı enjekte edilemiyor ve
	// satır bölünemiyor. Bağımlılık burada yazılı çünkü alıntılamayan
	// bir handler'a geçmek bunu sessizce bozardı.
	log = log.With("user", posternUser, "target", route.Target)

	host, _, err := net.SplitHostPort(sshConn.RemoteAddr().String())
	if err != nil {
		log.Error("remote addr parse failed", "error", err)
		newChan.Reject(ssh.ConnectionFailed, "session unavailable")
		return
	}

	// Yetki, bağlantı, kayıt ve denetim satırı: hepsi proxy.Open'da.
	// Web terminali AYNI çağrıyı yapıyor — iki kapı, tek akış.
	sess, err := proxy.Open(ctx, s.ProxyDeps(), proxy.Request{
		Username:   posternUser,
		TargetName: route.Target,
		SrcIP:      host,
	})
	if err != nil {
		// Open olayı zaten kendi logladı; burada yalnızca istemciye ne
		// söyleyeceğimize karar veriyoruz. Ret ile arıza ayrı cümleler:
		// kullanıcı "yetkim yok" ile "sistem bozuk"u ayırt edebilmeli.
		if errors.Is(err, proxy.ErrAccessDenied) {
			newChan.Reject(ssh.ConnectionFailed, "access denied")
			return
		}
		newChan.Reject(ssh.ConnectionFailed, "connection failed")
		return
	}
	defer sess.Close(ctx)

	down, downR, err := newChan.Accept()
	if err != nil {
		// Accept başarısız: defer'daki Close denetim satırını kapatır,
		// kayıt sonsuza dek "running" kalmaz.
		sess.Log.Error("channel accept failed", "error", err)
		return
	}

	if err := sess.Run(ctx, down, downR); err != nil {
		sess.Log.Error("session broker failed", "error", err)
	}
}
