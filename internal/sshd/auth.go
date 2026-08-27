package sshd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/store"
	"golang.org/x/crypto/ssh"
)

// publicKeyCallback, anahtarın sahibini veritabanından bulur ve doğrulanmış
// adı Permissions'a koyar. Bilinmeyen anahtar "access denied"; veritabanı
// arızası ise zinciri korunmuş hâliyle yukarı çıkar — ikisi log'da ayrışmalı.
//
// context.Background(): x/crypto/ssh bu callback'e ctx geçirmiyor (API,
// context'ten eski). Oturuma bağlı bir iptal mekanizması burada yok.
func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	u, err := s.db.UserByPublicKey(context.Background(), key.Marshal())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("auth.publicKeyCallback[%s][%s]: access denied", conn.RemoteAddr(), ssh.FingerprintSHA256(key))
		}
		return nil, fmt.Errorf("auth.publicKeyCallback[%s]: %w", conn.RemoteAddr(), err)
	}

	// SSO'ya bağlı kullanıcı anahtarla giremez.
	//
	// İki şeyi birden korur: IdP'de kapatılan hesabın erişimi GERÇEKTEN
	// biter (anahtar kapısı IdP'ye bakmıyordu), ve yetki tazeliği korunur
	// (roller yalnızca SSO girişinde senkronize ediliyor).
	if u.SSOOnly {
		s.logger.Warn("public key rejected for sso-only user",
			"user", u.Name, "remote", conn.RemoteAddr().String())
		return nil, fmt.Errorf("auth.publicKeyCallback[%s]: user %s is sso-only: access denied", conn.RemoteAddr(), u.Name)
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"postern-user": u.Name,
		},
	}, nil
}

// keyboardInteractiveCallback, OOB girişinin SSH ucu (S3.3): terminale
// login linki + güvenlik kodu basar, tarayıcı onayını bekler, doğrulanmış
// e-postayı postern kullanıcısına bağlar.
//
// publicKeyCallback ile AYNI Permissions şeklini üretir — channel.go'nun
// tek tanıdığı anahtar "postern-user", iki giriş yolu da aynı kapıya çıkar.
// nConn, handshake son tarihini uzatabilmek için gerekiyor: OOB onayı
// handshake'in İÇİNDE bekleniyor ve o süre listen.handshake_timeout'tan
// uzun. Kapatma (closure) ile veriliyor çünkü ssh.ServerConfig'in
// imzasında ham bağlantı yok.
func (s *Server) keyboardInteractiveCallbackFor(nConn deadlineSetter) func(
	ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata,
		client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		return s.keyboardInteractive(nConn, conn, client)
	}
}

func (s *Server) keyboardInteractive(nConn deadlineSetter, conn ssh.ConnMetadata,
	client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	a, err := s.logins.Start()
	if err != nil {
		// Kota dolması bir arıza DEĞİL, uygulanan bir sınır. Log'da
		// ayrışsın ki operatör "IdP bozuldu" ile "yük altındayız"ı
		// karıştırmasın.
		if errors.Is(err, auth.ErrTooManyPending) {
			s.logger.Warn("oob login refused: too many pending",
				"remote", conn.RemoteAddr())
		}
		return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: %w", conn.RemoteAddr(), err)
	}
	// Drop, Wait'ten HANGİ yolla çıkarsak çıkalım denemeyi yakar; başarı
	// yolunda Confirm zaten düşürdü, Drop idempotent — ikinci çağrı no-op.
	defer s.logins.Drop(a)

	// Handshake süresini onayı kapsayacak kadar uzat.
	//
	// ⚠️ SIRA ÖNEMLİ: uzatma challenge'dan ÖNCE olmalı. İstemcinin
	// keyboard-interactive geri çağrısı içinde bloke olması meşrudur —
	// bazı istemciler tarayıcı onayını orada bekler — ve o durumda
	// challenge'dan SONRA uzatmak çok geç kalır. (Ölçüldü:
	// TestOOBLoginSurvivesShortHandshakeTimeout bu sırayla düşüyordu.)
	//
	// Bağlantı zamanında değil BURADA uzatmak yine de anlamlı:
	// handshake_timeout'u baştan oobTimeout kadar uzun yapmak, her
	// anonim tarayıcıya bedava iki dakikalık goroutine vermek olurdu.
	// Buraya gelen istemci taşıma katmanı handshake'ini tamamlamış ve
	// keyboard-interactive'i SEÇMİŞ durumda; ayrıca MaxAuthTries ve
	// MaxPendingLogins bu yolu ayrıca sınırlıyor.
	extendDeadline(nConn, s.oobTimeout+oobDeadlineSlack, s.logger)

	// Challenge'ın hatası "istemci gitti" demektir: linki hiç görmemiş
	// olabilir. Wait'e girip tarayıcı onayı beklemek, terk edilmiş bir
	// handshake goroutine'ini s.oobTimeout boyunca yaşatmak olurdu.
	if _, err := client("", "postern login\n\n  "+a.URL+"\n\n  security code: "+
		a.UserCode+"\n\nOpen the link, sign in, and type the code.",
		nil, nil); err != nil {
		return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: challenge: %w", conn.RemoteAddr(), err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.oobTimeout)
	defer cancel()

	id, err := a.Wait(ctx)
	if err != nil {
		// İki olay ayrışsın: süre doldu mu, onay mı reddedildi? İkisi de
		// istemciye "access denied" görünür ama log farkı bilmeli.
		event := "oob login denied"
		if errors.Is(err, context.DeadlineExceeded) {
			event = "oob login timed out"
		}
		return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: %s: %w", conn.RemoteAddr(), event, err)
	}

	// Wait'in ctx'i giriş beklemek için biçilmişti ve işi bitti; sorgu
	// için taze, kısa bir süre. Background kullanmak da olurdu ama asılı
	// bir veritabanı bu goroutine'i sonsuza dek tutardı.
	qctx, qcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer qcancel()

	// Kimlik çözümü web ile AYNI yoldan: JIT sağlama, sonra e-posta
	// eşleştirmesine düşüş. İki kapı, tek kural — ayrı yazsaydık
	// "grubu eşlenmemiş kullanıcı" SSH'tan girebilir, web'den giremez
	// gibi bir ayrışma doğardı.
	u, err := s.resolveIdentity(qctx, id)
	if err != nil {
		return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: %w", conn.RemoteAddr(), err)
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"postern-user": u.Name,
		},
	}, nil
}

// resolveIdentity, doğrulanmış OIDC kimliğini postern kullanıcısına
// çevirir — httpapi'deki aynı adlı yardımcının SSH tarafındaki eşi.
//
// Sıra: kullanıcı adı varsa JIT sağlama (gruplar → roller, gerekirse
// kullanıcıyı oluştur), yoksa doğrulanmış e-postayla eşleştirme.
func (s *Server) resolveIdentity(ctx context.Context, id auth.Identity) (model.User, error) {
	if id.Username != "" {
		groups, err := s.groups.Groups(ctx, id)
		if err != nil {
			// Dizin arızası yetki yokluğu değildir (httpapi'deki notun
			// aynısı): sessizce yetkisiz bırakmak yerine reddet.
			s.logger.Error("oob group lookup failed", "idp_user", id.Username, "error", err)
			return model.User{}, err
		}

		u, err := s.db.ProvisionUser(ctx, store.ProvisionRequest{
			Username: id.Username,
			Email:    id.Email,
			Groups:   groups,
		})
		if err == nil {
			return u, nil
		}
		if errors.Is(err, store.ErrAccessDenied) {
			s.logger.Warn("oob login denied: no mapped groups",
				"idp_user", id.Username, "groups", len(id.Groups))
			return model.User{}, fmt.Errorf("access denied")
		}
		s.logger.Error("oob provisioning failed", "idp_user", id.Username, "error", err)
		return model.User{}, err
	}

	if id.Email == "" {
		// Doğrulanmamış e-posta Identity'ye hiç binmiyor; bu dal "IdP ne
		// kullanıcı adı ne doğrulanmış e-posta verdi" demek.
		return model.User{}, fmt.Errorf("identity has neither username nor verified email")
	}

	u, err := s.db.UserByEmail(ctx, id.Email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// "IdP'de hesap var" ≠ "postern'de hesap var".
			return model.User{}, fmt.Errorf("no postern user for verified email: access denied")
		}
		return model.User{}, err
	}
	return u, nil
}
