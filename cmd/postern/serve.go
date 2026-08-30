package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/warewave/postern/internal/groupsync"
	"github.com/warewave/postern/internal/proxy"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/events"
	"github.com/warewave/postern/internal/httpapi"
	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/secret"
	"github.com/warewave/postern/internal/sshd"
	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/upstream"
)

/*
 * httpShutdownGrace, kapanışın SON ÇARE süresi.
 *
 * Beklenen yol bu değil: BeginShutdown uzun ömürlü işleyicilere
 * dönmelerini söylüyor ve kapanış milisaniyelerde bitiyor. Bu süre,
 * onu duymayan (ya da yazarken hedefte bloke olmuş) bir bağlantının
 * süreci rehin almasını engelliyor.
 *
 * 5 saniye: bir init sisteminin kendi SIGKILL süresinden (systemd
 * varsayılanı 90s) rahatça kısa, ama TCP'ye son baytları yazmaya
 * yetecek kadar uzun.
 */
const httpShutdownGrace = 5 * time.Second

func newServeCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the bastion (SSH listener)",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}

			// Sinyal bağlamı: ctx eskiden HİÇ iptal edilmiyordu, yani
			// arka plan döngülerinin tanımlı bir duruşu yoktu ve
			// aşağıdaki defer'daki api.Shutdown da hiç sırasını
			// bulamıyordu.
			ctx, stop := signal.NotifyContext(context.Background(),
				os.Interrupt, syscall.SIGTERM)
			defer stop()

			db, err := store.Open(ctx, cfg.Database.DSN)
			if err != nil {
				return err
			}
			defer db.Close()

			// Sır anahtarı varsa bağla: şifreli ayarlar (LDAP servis
			// hesabı parolası) onsuz okunamaz.
			if cfg.SecretKeyFile != "" {
				box, err := secret.Load(cfg.SecretKeyFile)
				if err != nil {
					return err
				}
				db.UseSecretBox(box)
			}

			pending, err := db.PendingMigrations(ctx)
			if err != nil {
				return err
			}
			if pending > 0 {
				return fmt.Errorf("schema is %d migration(s) behind; run `postern db migrate` first", pending)
			}

			// ÇÖZÜLMÜŞ değerler loglanıyor, ham config değil: "0 =
			// varsayılan" sözleşmesinde bloğu hiç yazmamış bir operatörün
			// yürürlükteki sınırı öğrenmesinin başka yolu yok.
			logger.Info("config loaded",
				"listen", cfg.Listen.Addr,
				// ⚠️ DSN parola taşır ve log satırları dosyaya, konsola,
				// hata ayıklama paketine gider. Ayıklanmış hâli
				// yazılıyor.
				"database", redactDSN(cfg.Database.DSN),
				"max_conns", cfg.Listen.MaxConnsOrDefault(),
				"max_conns_per_ip", cfg.Listen.MaxConnsPerIPOrDefault(),
				"max_auth_tries", cfg.Listen.MaxAuthTriesOrDefault(),
				"max_channels_per_conn", cfg.Listen.MaxChannelsOrDefault(),
				"max_pending_logins", cfg.Listen.MaxPendingLoginsOrDefault(),
				"handshake_timeout", cfg.Listen.HandshakeTimeoutOrDefault(),
				"session_idle_timeout", cfg.Session.IdleTimeout,
				"session_max_lifetime", cfg.Session.MaxLifetime,
			)

			s, err := sshd.New(cfg, db, logger)
			if err != nil {
				return err
			}

			// Canlı olay veriyolu. Panelde "Overview" ekranını besliyor;
			// abonesi yokken maliyeti yok (Publish boş haritada döner).
			//
			// ⚠️ SÜREÇ İÇİ: CLI'dan yapılan yönetim işlemleri başka bir
			// süreçte ve buradan geçmiyor. Panel bunu söylüyor —
			// "canlı akış her şeyi gösteriyor" sanmak, göstermediğini
			// fark etmemek olurdu.
			bus := events.New(0, 0)
			s.UseEventBus(bus)

			/*
			 * ⚠️ GRUP KAYNAĞI VE HTTP YÜZEYİ ARTIK OIDC'DEN BAĞIMSIZ.
			 *
			 * Eskiden buradaki her şey tek bir `if cfg.OOBEnabled()`
			 * bloğunun içindeydi ve o yüklem düpedüz "issuer_url dolu
			 * mu" demekti. Sonucu: dizini olan ama kimlik sağlayıcısı
			 * OLMAYAN bir kurum paneli hiç çalıştıramıyordu — postern'in
			 * yönetilebilir hâli bir Keycloak kurmaya bağlıydı, ki
			 * ürünün "mevcut yapıya uyum sağla" iddiasının tam tersi.
			 *
			 * Şimdi üç ayrı soru var: grup kaynağı kim (her zaman),
			 * kimlik sağlayıcı var mı (OIDCEnabled), panel servis
			 * ediliyor mu (WebEnabled).
			 */

			// Grup kaynağı: LDAP ayarlanmışsa dizin, değilse ID
			// token'ın claim'i. İKİ KAPI DA aynı kaynağı kullanır —
			// SSH'tan giren ile web'den giren aynı yetkiyi almalı.
			// PAYLAŞILAN sarmalayıcı: panelden ayar değişince tek
			// Set çağrısı iki kapıyı birden günceller.
			groupSwitch := auth.NewSwitchableGroupSource(auth.ClaimGroups{})
			s.UseGroupSource(groupSwitch)

			groupSource, gerr := ldap.SourceFromStore(ctx, db)
			switch {
			case gerr == nil:
				groupSwitch.Set(groupSource)
				logger.Info("group source: ldap directory")
			case errors.Is(gerr, ldap.ErrNotConfigured):
				if cfg.OIDCEnabled() {
					logger.Info("group source: oidc claim")
				} else {
					// ⚠️ Ne dizin ne kimlik sağlayıcı: kimsenin grubu
					// yok, dolayısıyla kimseye rol türetilemez. Sessiz
					// kalmak, "hedef listem neden boş" sorusunu
					// cevapsız bırakırdı.
					logger.Warn("no group source: configure ldap, or nobody will be granted a role")
				}
			default:
				// Yapılandırma VAR ama bozuk: sessizce claim'e
				// düşmek, yöneticinin kurduğunu sandığı LDAP'ın hiç
				// çalışmaması demek olurdu.
				return fmt.Errorf("ldap configuration is invalid: %w", gerr)
			}

			/*
			 * Oturum açılışında yetki tazeleme.
			 *
			 * ⚠️ İKİ KAPI, TEK KURAL: bu fonksiyon proxy.Deps üzerinden
			 * hem SSH kanalına hem web terminaline gidiyor.
			 *
			 * Üç cevap, üç ayrı karar:
			 *   present + açık  → roller tazelenir
			 *   present + KAPALI → oturum reddedilir (rol silinmez)
			 *   absent           → oturum reddedilir (rol silinmez)
			 *   unknown          → hiçbir şey; saklanan rollerle devam
			 *
			 * Kapalı hesabın reddedilmesi, eski "SSO kullanıcısı
			 * anahtarla giremez" kuralının koruduğu şeyin yerine geçen
			 * asıl mekanizma. Bir hesabı devre dışı bırakmak işten
			 * ayrılmanın İLK adımı ve AD'de bu ne girişi siler ne de
			 * grup üyeliklerini kaldırır — yalnızca gruplara bakan bir
			 * tazeleme o hesabı içeri alırdı.
			 *
			 * Unknown'da reddetmiyoruz: bir dizin kesintisi herkesi
			 * dışarıda bırakırdı. Bedeli açık ve kabul edilmiş —
			 * dizinden silinip dizini de düşüren biri saklanan
			 * rolleriyle girebilir.
			 */
			refreshTTL := 30 * time.Second
			var refreshMu sync.Mutex
			type refreshVerdict struct {
				at  time.Time
				err error
			}
			refreshCache := map[string]refreshVerdict{}

			freshen := func(c context.Context, username string) error {
				/*
				 * ⚠️ ÖNBELLEK BİR YÜK KORUMASI. Tazeleme
				 * policy.Authorize'dan ÖNCE çalışıyor, yani kimliği
				 * doğrulanmış HERHANGİ bir anahtar sahibi — hiç rolü
				 * olmayan biri bile — var olan bir hedefin adını
				 * yazarak dizine tam bir TCP+TLS+bind maliyeti
				 * çıkartabiliyor (ldap.connect'te havuz yok). Kanal
				 * sınırı bunu bağlantı başına 10'a indiriyor ama
				 * bağlantı sayısı 256; önbelleksiz bu bir yükseltici
				 * olurdu.
				 *
				 * KARAR önbellekleniyor, yalnızca "sorduk mu" değil:
				 * aksi hâlde TTL boyunca kapalı hesabın reddi de
				 * atlanırdı.
				 */
				refreshMu.Lock()
				v, ok := refreshCache[username]
				fresh := ok && time.Since(v.at) < refreshTTL
				refreshMu.Unlock()
				if fresh {
					return v.err
				}

				verdict := func(err error) error {
					refreshMu.Lock()
					refreshCache[username] = refreshVerdict{at: time.Now(), err: err}
					refreshMu.Unlock()
					return err
				}

				if !auth.CanResolveByUsername(groupSwitch) {
					// Kaynağa adla sorulamıyor (gruplar token'dan
					// okunuyor). Boş bir cevabı "grubu yok" sanmak
					// bütün SSO rollerini silerdi.
					return verdict(nil)
				}

				/*
				 * ⚠️ KİMLİĞİ BAĞLIYSA ADLA DEĞİL, KİMLİKLE SOR.
				 *
				 * Adla sormak, dizinde YENİDEN ADLANDIRILAN kişiyi
				 * SİLİNMİŞ kişiden ayırt edemiyor — ikisi de "yok"
				 * döner ve buradaki kod onu oturum reddine çevirir.
				 * Yani İK'nın soyadını güncellemesi, hiçbir şey
				 * yapmamış bir kullanıcının bütün oturumlarını
				 * kesiyordu.
				 */
				res, err := freshenLookup(c, db, groupSwitch, username)
				if err != nil {
					// Arıza önbelleklenmiyor: dizin geri geldiğinde
					// TTL beklenmesin.
					return err
				}

				switch res.Presence {
				case auth.GroupsPresent:
					if res.Disabled {
						logger.Warn("session refused: account is disabled in the directory",
							"user", username, "reason", res.DisabledReason)
						return verdict(fmt.Errorf("%w: %s", proxy.ErrDirectoryRefused, res.DisabledReason))
					}
				case auth.GroupsAbsent:
					logger.Warn("session refused: the directory has no such user",
						"user", username)
					return verdict(fmt.Errorf("%w: not in the directory", proxy.ErrDirectoryRefused))
				default:
					logger.Warn("session: directory could not answer; using stored roles",
						"user", username)
					return verdict(nil)
				}

				roles, _, rerr := db.RolesForGroups(c, model.ResolvedGroups(res.Groups))
				if rerr != nil {
					return rerr
				}
				if serr := db.SyncRoles(c, username, roles); serr != nil {
					return serr
				}
				return verdict(nil)
			}
			s.UseRoleRefresher(freshen)

			/*
			 * ⚠️ SENKRONİZASYON DÖNGÜSÜ PANELE BAĞLI DEĞİL.
			 *
			 * P0'da HTTP yüzeyi OIDC'den ayrılırken döngü web bloğunun
			 * içinde kalmıştı ve sonucu ölçüldü: LDAP'ı CLI'dan kuran,
			 * http bölümü olmayan bir kurulumda — yani tam olarak
			 * desteklediğimiz "SSH bastion + dizin" kurulumunda —
			 * HİÇBİR ŞEY iptal etmiyordu. Oturum açılışındaki kontrol
			 * bir oturumu reddeder ama rolleri temizlemez; temizleyen
			 * tek şey bu döngü.
			 */
			syncFallback := groupsync.Settings{
				Enabled: cfg.Sync.Enabled,
				Config: groupsync.Config{
					Interval: cfg.Sync.IntervalOrDefault(),
					Timeout:  cfg.Sync.TimeoutOrDefault(),
					DryRun:   cfg.Sync.DryRun,
					Limits: groupsync.Limits{
						Grace:              cfg.Sync.GraceOrDefault(),
						MaxZeroFraction:    cfg.Sync.MaxZeroFractionOrDefault(),
						MinZeroFloor:       cfg.Sync.MinZeroFloorOrDefault(),
						MaxUnknownFraction: cfg.Sync.MaxUnknownFractionOrDefault(),
						MaxRevokePerRun:    cfg.Sync.MaxRevokePerRunOrDefault(),
					},
				},
			}
			{
				runner := groupsync.NewRunner(db,
					func(c context.Context) (groupsync.Directory, error) {
						// HER koşuda yeniden açılıyor: LDAP ayarı
						// panelden değişebiliyor ve yakalanmış bir
						// kaynak, çoktan değiştirilmiş bir dizine
						// sorgu atmaya devam ederdi.
						return ldap.SourceFromStore(c, db)
					},
					syncFallback.Config, logger)

				runner.UseSettings(func(c context.Context) (groupsync.Settings, error) {
					return groupsync.LoadSettings(c, db, syncFallback)
				})

				go runner.Start(ctx)
			}

			// Kimlik sağlayıcı: yalnızca yapılandırıldıysa. Yoksa
			// tarayıcı giriş akışı ve SSH'taki OOB kapısı HİÇ
			// kurulmuyor — kapalı özellik, kapalı yüzey.
			var oidcClient *auth.OIDC
			var logins *auth.Logins
			if cfg.OIDCEnabled() {
				oidcClient, err = auth.NewOIDC(ctx, auth.OIDCConfig{
					IssuerURL:    cfg.OIDC.IssuerURL,
					ClientID:     cfg.OIDC.ClientID,
					ClientSecret: cfg.OIDC.ClientSecret,
					RedirectURL:  strings.TrimRight(cfg.HTTP.ExternalURL, "/") + "/auth/callback",
				})
				if err != nil {
					return err
				}

				logins = auth.NewLogins(oidcClient)
				// Bekleyen giriş kotası: her deneme handshake içinde
				// bekleyen bir goroutine demek ve kimlik doğrulaması
				// gerektirmiyor.
				logins.SetMaxPending(cfg.Listen.MaxPendingLoginsOrDefault())
				s.EnableOOB(logins, 0)
			}

			if cfg.WebEnabled() {

				// ⚠️ WARN, Info DEĞİL. Bu ayar postern'in hedefteki
				// davranışını değiştiriyor: kullanıcının bağlantısında,
				// kullanıcının adına, kullanıcının yazmadığı komutlar
				// çalışıyor. Açık olduğu HER açılışta operatörün
				// görmesi gereken bir şey; sessiz kalması "biz bunu
				// açmış mıydık" sorusuna yol açardı.
				if !cfg.Auth.PublicKeyLoginEnabled() {
					logger.Info("public key login is off: browser sign-in is the only way in")
				}

				if cfg.TargetProbe.Enabled {
					logger.Warn("target probe ENABLED: postern will run commands on targets",
						"commands", strings.Join(upstream.ProbeCommands, "; "),
						"refresh", cfg.TargetProbe.RefreshOrDefault(),
						"timeout", cfg.TargetProbe.TimeoutOrDefault())
				}

				webAPI := httpapi.New(oidcClient, logins, db, logger)
				webAPI.SetPublicKeyLogin(cfg.Auth.PublicKeyLoginEnabled())
				webAPI.UseGroupSource(groupSwitch)
				webAPI.UseEventBus(bus)
				// Terminal açık olmasa da gerekli: oturum çerezinin
				// Secure bayrağı bu adresin şemasından türüyor.
				webAPI.SetExternalURL(cfg.HTTP.ExternalURL)

				// Kayıt izleme: panelden oturum oynatma. sshd ile AYNI
				// depo — kayıtların yazıldığı yer ile okunduğu yer
				// ayrışamaz.
				webAPI.UseRecordings(s.Records())

				// Periyodik dizin senkronizasyonu — YALNIZCA serve'de.
				//
				// Runner'ı burada kurmak, "CLI komutlarıyla değil
				// sunucuyla başlar" kuralını bir gelenek olmaktan
				// çıkarıp yapısal hâle getiriyor: diğer alt komutlar
				// çıplak bir Store açıyor ve bu koda hiç ulaşamıyor.
				/*
				 * ⚠️ DÖNGÜ HER ZAMAN BAŞLIYOR, cfg.Sync.Enabled'a
				 * bakılmadan.
				 *
				 * Ayar artık panelden de değişebiliyor ve yalnızca
				 * YAML'a bakıp başlatmamak, "panelden açtım ama hiçbir
				 * şey olmuyor" demek olurdu — çalışacak bir döngü yok.
				 * Döngü uyuyor ve her tikte açık mı diye soruyor.
				 *
				 * YAML bloğu VARSAYILAN olarak duruyor: saklanan anahtar
				 * yoksa dosyadaki değer geçerli, yani mevcut kurulumlar
				 * yükseltmeden sonra ayar kaybetmiyor.
				 */
				// Panel de ETKİN değeri gösterebilsin.
				webAPI.SetSyncDefaults(syncFallback)

				// Web terminali yalnızca açıkça istendiğinde: rota bile
				// kurulmaz. Bağımlılıklar sshd'ninkilerle AYNI — iki kapı
				// tek oturum akışını paylaşıyor (proxy.Open).
				if cfg.HTTP.TerminalEnabled {
					webAPI.EnableTerminal(s.ProxyDeps(), cfg.HTTP.ExternalURL)
					logger.Info("web terminal enabled")
				}

				api := &http.Server{
					Addr:    cfg.HTTP.Addr,
					Handler: webAPI.Handler(),

					// Başlıkları okumak için üst sınır. Yoksa açık
					// bırakılan bir bağlantı başlık göndermeden sonsuza
					// kadar bir goroutine tutar (Slowloris).
					ReadHeaderTimeout: 10 * time.Second,

					// Boştaki keep-alive bağlantısının ömrü.
					IdleTimeout: 2 * time.Minute,

					// ⚠️ ReadTimeout ve WriteTimeout BİLEREK YOK: web
					// terminali bağlantıyı WebSocket'e devralıyor ve
					// oturum saatlerce açık kalabilir. Bütün isteği
					// kapsayan bir süre sınırı o oturumları ortasından
					// keserdi. Slowloris'e karşı koruyan zaten
					// ReadHeaderTimeout.
				}
				go func() {
					logger.Info("http listener started", "addr", cfg.HTTP.Addr)
					if err := api.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						logger.Error("http listener failed", "error", err)
					}
				}()
				/*
				 * ⚠️ KAPANIŞ İKİ ADIM: önce "bitir" de, sonra bekle.
				 *
				 * Eskiden burada yalnızca Shutdown(context.Background())
				 * vardı ve süreç SIGTERM ile ÖLMÜYORDU. Shutdown etkin
				 * bağlantıların bitmesini bekler ama istek bağlamlarını
				 * iptal etmez; canlı olay akışı ile web terminali de
				 * kendiliğinden bitmez. Sonuç ölçüldü: init sistemi
				 * süreci öldürene kadar eski süreç ayakta kalıyor,
				 * paneli açık operatör onun akışından ESKİ sayıları
				 * "Live" rozetiyle okumaya devam ediyordu.
				 *
				 * BeginShutdown o işleyicilere dönmelerini söylüyor;
				 * süre sınırı artık beklenen yol değil, SON ÇARE. Dolarsa
				 * sessiz geçilmiyor: bir bağlantının bırakmadığını
				 * bilmek, yeniden başlatmanın neden yavaşladığını
				 * arayan operatörün ilk ipucu.
				 */
				defer func() {
					webAPI.BeginShutdown()

					sctx, scancel := context.WithTimeout(context.Background(), httpShutdownGrace)
					defer scancel()
					if err := api.Shutdown(sctx); err != nil {
						logger.Warn("http shutdown did not finish cleanly",
							"error", err, "grace", httpShutdownGrace)
					}
				}()

				if cfg.OIDCEnabled() {
					logger.Info("oob login enabled", "issuer", cfg.OIDC.IssuerURL)
				} else {
					// Panel var ama kimlik sağlayıcı yok: giriş yolu
					// postern'in kendi yerel yöneticisi olacak.
					logger.Info("panel enabled without an identity provider")
				}
			}

			return s.ListenAndServe(ctx)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}

// redactDSN, bağlantı dizesindeki parolayı gizler.
//
// Log satırları dosyaya, konsola ve hata ayıklama paketlerine gider;
// veritabanı parolasının oralara sızmaması gerekiyor. Ayrıştırılamayan
// bir dize TAMAMEN gizleniyor: tanımadığımız bir biçimi "herhalde
// güvenlidir" diye olduğu gibi yazmak, gizlemenin amacını bozardı.
func redactDSN(dsn string) string {
	if dsn == "" {
		return ""
	}

	u, err := url.Parse(dsn)
	if err != nil || u.Host == "" {
		// URL değil (anahtar=değer biçimi olabilir) ya da bozuk.
		return "[redacted]"
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			u.User = url.UserPassword(u.User.Username(), "xxxxx")
		}
	}
	return u.Redacted()
}

/*
 * freshenLookup, kullanıcıyı dizinde çözer — kimliği bağlıysa KİMLİKLE.
 *
 * ⚠️ Ada düşmek yalnızca kimliği olmayan hesaplar için: eski kurulumlar
 * ve kararlı kimlik vermeyen dizinler. Orada davranış bugünküyle aynı
 * kalıyor, yani bu değişiklik hiçbir kurulumu geriletmiyor.
 *
 * ⚠️ Kimlikle arama başarısız olursa ada DÜŞMÜYORUZ. Düşseydi, dizinde
 * silinip aynı adla yeniden açılan (yani YENİ bir kimlik almış) kişi
 * eski hesabın rolleriyle çözülürdü — kimliğin bütün amacı o.
 */
func freshenLookup(ctx context.Context, db *store.Store, src *auth.SwitchableGroupSource,
	username string) (auth.GroupResult, error) {

	subject, err := db.DirSubjectOf(ctx, username)
	if err != nil {
		return auth.GroupResult{Presence: auth.GroupsUnknown}, err
	}
	if subject == "" {
		return src.Groups(ctx, auth.Identity{Username: username})
	}
	return src.GroupsBySubject(ctx, subject)
}
