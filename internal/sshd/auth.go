package sshd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/events"
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

	/*
	 * ⚠️ SSO'YA BAĞLI KULLANICI, YETKİSİ TAZELENEBİLİYORSA anahtarla
	 * girebilir.
	 *
	 * Eskiden koşulsuz reddediliyordu ve gerekçesi doğruydu: anahtar
	 * kapısı kimlik sağlayıcıya bakmıyor, roller yalnızca SSO girişinde
	 * senkronize ediliyordu, yani anahtar bayat bir yetkiyi süresiz
	 * taşıyabilirdi.
	 *
	 * Artık tazelik oturum AÇILIRKEN sağlanıyor (proxy.Open,
	 * FreshenRoles): kimlik doğrulanmış, kanal sayısı sınırlı, ve iki
	 * kapı da aynı fonksiyondan geçiyor. O yüzden reddetmeye gerek
	 * kalmadı — SSH'ın anahtara sabitlendiği bir üründe bu reddetme
	 * dizin kullanıcılarının SSH'ını tamamen kapatırdı.
	 *
	 * AMA KOŞULSUZ AÇMIYORUZ. Tazeleme ancak grup kaynağı kullanıcı
	 * ADIYLA sorgulanabiliyorsa mümkün; grupları token'dan okuyan bir
	 * kurulumda (ClaimGroups) anahtarla açılan oturumda sorulacak bir
	 * şey yok. Orada eski gerekçe hâlâ geçerli ve reddetme duruyor.
	 */
	if u.SSOOnly && !auth.CanResolveByUsername(s.groups) {
		s.logger.Warn("public key rejected: sso-only user and roles cannot be refreshed without a token",
			"user", u.Name, "remote", conn.RemoteAddr().String())
		return nil, fmt.Errorf(
			"auth.publicKeyCallback[%s]: user %s is governed by the identity provider "+
				"and their roles cannot be refreshed from a key session: access denied",
			conn.RemoteAddr(), u.Name)
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
	a, err := s.logins.Start(conn.RemoteAddr().String())
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

	// ⚠️ KOD TERMİNALDE GÖSTERİLMİYOR, TERMİNALDEN SORULUYOR.
	//
	// Yönün gerekçesi auth.Attempt.UserCode'un doküman yorumunda: eski
	// yönde saldırgan kodu kendi terminalinde görüp linkle birlikte
	// kurbana yolluyordu ve kurbanın tek tıkı saldırgana kurbanın
	// kimliğiyle oturum açıyordu. Bu yönde kod yalnızca kurbanın
	// tarayıcısında beliriyor.
	//
	// Challenge'ın hatası "istemci gitti" demektir: linki hiç görmemiş
	// olabilir. Beklemeye girip tarayıcı onayı beklemek, terk edilmiş
	// bir handshake goroutine'ini s.oobTimeout boyunca yaşatmak olurdu.
	// Metin SALT ASCII: OpenSSH keyboard-interactive yönergesini istemciye
	// vermeden önce strnvis'ten geçiriyor ve ASCII olmayan her baytı
	// kaçış dizisine çeviriyor. Buradaki tire "—" gerçek terminallerde
	// "\200\224" olarak çıkıyordu; kullanıcının okuduğu ilk ekran bu.
	instruction := "postern login\n\n  " + a.URL +
		"\n\nOpen the link and sign in. Your browser will then show a\n" +
		"verification code - type it here.\n"

	// Kullanıcıya birkaç deneme hakkı: tarayıcı tarafı bitmeden ENTER'a
	// basmak yaygın ve denemeyi yakmamalı.
	const maxCodeAttempts = 3

	for attempt := 0; ; attempt++ {
		answers, cerr := client("", instruction,
			[]string{"Verification code: "}, []bool{true})
		if cerr != nil {
			return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: challenge: %w", conn.RemoteAddr(), cerr)
		}
		if len(answers) != 1 {
			return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: no answer", conn.RemoteAddr())
		}

		err := s.logins.Confirm(a.State(), strings.TrimSpace(answers[0]))
		switch {
		case err == nil:
			// Kod doğru; kimlik teslim edildi, aşağıdaki Wait onu
			// hemen alacak.

		case errors.Is(err, auth.ErrNotReady):
			if attempt+1 >= maxCodeAttempts {
				s.logger.Warn("oob login abandoned: browser never completed",
					"remote", conn.RemoteAddr())
				return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: %w",
					conn.RemoteAddr(), err)
			}
			instruction = "Finish signing in in your browser first, then type the\n" +
				"verification code it shows.\n"
			continue

		default:
			// Yanlış kod denemeyi yaktı; tekrar sormanın anlamı yok.
			s.logger.Warn("oob login denied", "remote", conn.RemoteAddr(), "error", err)
			return nil, fmt.Errorf("auth.keyboardInteractiveCallback[%s]: %w",
				conn.RemoteAddr(), err)
		}
		break
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
		res, err := s.groups.Groups(ctx, id)
		if err != nil {
			// Dizin arızası yetki yokluğu değildir (httpapi'deki notun
			// aynısı): sessizce yetkisiz bırakmak yerine reddet.
			s.logger.Error("oob group lookup failed", "idp_user", id.Username, "error", err)
			return model.User{}, err
		}

		// ⚠️ "BULAMADIM" BİR YETKİ KARARI DEĞİL. Kaynak kullanıcıyı
		// tanımıyorsa roller olduğu gibi bırakılıyor; sessizce silmek,
		// dizindeki bir ad uyuşmazlığını toplu yetki kaybına
		// çeviriyordu. Operatörün bunu görmesi şart, yoksa yalnızca
		// "hiçbir hedefe erişimin yok" ekranı kalıyor.
		if res.Presence != auth.GroupsPresent {
			s.logger.Warn("directory did not resolve this user; roles left untouched",
				"idp_user", id.Username, "presence", res.Presence.String())
		}

		// Bkz. httpapi tarafındaki aynı not: yalnızca gruplar gerçekten
		// çözüldüyse sorulur, aksi hâlde kapı kapalı tarafta kalır.
		adminMember := false
		if res.Presence == auth.GroupsPresent {
			var aerr error
			adminMember, aerr = auth.InAdminGroup(ctx, s.db, res.Groups)
			if aerr != nil {
				s.logger.Error("admin group lookup failed", "error", aerr)
				return model.User{}, aerr
			}
		}

		u, err := s.db.ProvisionUser(ctx, store.ProvisionRequest{
			Username:         id.Username,
			Email:            id.Email,
			Groups:           res.Groups,
			GroupsResolved:   res.Presence == auth.GroupsPresent,
			Issuer:           id.Issuer,
			Subject:          id.Subject,
			AdminGroupMember: adminMember,
		})
		if err == nil {
			return u, nil
		}
		// Kimlik çatışması AYRI loglanıyor: bu bir yapılandırma eksiği
		// değil, var olan bir hesabın adını taşıyan BAŞKA bir IdP
		// kimliğinin giriş denemesi. Tek mesajla toplandığında olay
		// "no mapped groups" diye görünüyordu ve araştıran yönetici
		// hiçbir şeyi düzeltmeyecek olan grup eşlemesine yönlendiriliyordu.
		// İstemciye giden yanıt aynı — ayrım yalnızca logda.
		// ⚠️ Yönetici hesabını ad eşleşmesiyle devralma denemesi: AYRI
		// mesaj. "Kimlik çatışması" diye loglansaydı, meşru bir
		// yöneticinin ilk girişi de bir saldırı gibi görünürdü — ve
		// tersi: gerçek deneme, rutin bir çatışma gibi.
		if errors.Is(err, store.ErrAdminBindRefused) {
			s.logger.Warn("oob login denied: this username belongs to an administrator account "+
				"and cannot be claimed by a first sign-in",
				"idp_user", id.Username, "idp_issuer", id.Issuer)
			s.publish(events.AuthDenied, id.Username, "",
				"administrator account cannot be claimed by a matching username")
			return model.User{}, fmt.Errorf("access denied")
		}
		if errors.Is(err, store.ErrIdentityConflict) {
			s.logger.Warn("oob login denied: username belongs to an account bound to a different identity",
				"idp_user", id.Username, "idp_issuer", id.Issuer)
			// Canlı akışa da düşüyor: bu, incelenmesi gereken bir olay.
			s.publish(events.AuthDenied, id.Username, "",
				"username belongs to an account bound to a different identity")
			return model.User{}, fmt.Errorf("access denied")
		}
		if errors.Is(err, store.ErrAccessDenied) {
			// İki ayrı sebep, iki ayrı mesaj: "grubu role eşleşmiyor"
			// ile "dizin bu kullanıcıyı hiç tanımıyor" farklı şeyler ve
			// ikincisinde eşleme tablosuna bakan yönetici hiçbir şey
			// bulamaz.
			reason := "no mapped directory groups"
			if res.Presence != auth.GroupsPresent {
				reason = "directory could not resolve this user (" + res.Presence.String() + ")"
			}
			s.logger.Warn("oob login denied", "idp_user", id.Username,
				"reason", reason, "presence", res.Presence.String())
			s.publish(events.AuthDenied, id.Username, "", reason)
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
