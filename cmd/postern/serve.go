package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/httpapi"
	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/secret"
	"github.com/warewave/postern/internal/sshd"
	"github.com/warewave/postern/internal/store"
)

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

			ctx := context.Background()

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

			// OOB girişi yalnızca yapılandırıldıysa: OIDC discovery +
			// login kaydı + HTTP dinleyicisi. Yoksa bastion eskisi gibi
			// yalnızca public key kabul eder.
			if cfg.OOBEnabled() {
				oidcClient, err := auth.NewOIDC(ctx, auth.OIDCConfig{
					IssuerURL:    cfg.OIDC.IssuerURL,
					ClientID:     cfg.OIDC.ClientID,
					ClientSecret: cfg.OIDC.ClientSecret,
					RedirectURL:  strings.TrimRight(cfg.HTTP.ExternalURL, "/") + "/auth/callback",
				})
				if err != nil {
					return err
				}

				logins := auth.NewLogins(oidcClient)
				// Bekleyen giriş kotası: her deneme handshake içinde
				// bekleyen bir goroutine demek ve kimlik doğrulaması
				// gerektirmiyor.
				logins.SetMaxPending(cfg.Listen.MaxPendingLoginsOrDefault())
				s.EnableOOB(logins, 0)

				// Grup kaynağı: LDAP ayarlanmışsa dizin, değilse ID
				// token'ın claim'i. İKİ KAPI DA aynı kaynağı kullanır —
				// SSH'tan giren ile web'den giren aynı yetkiyi almalı.
				// PAYLAŞILAN sarmalayıcı: panelden ayar değişince tek
				// Set çağrısı iki kapıyı birden günceller.
				groupSwitch := auth.NewSwitchableGroupSource(auth.ClaimGroups{})
				s.UseGroupSource(groupSwitch)

				groupSource, err := ldap.SourceFromStore(ctx, db)
				switch {
				case err == nil:
					groupSwitch.Set(groupSource)
					logger.Info("group source: ldap directory")
				case errors.Is(err, ldap.ErrNotConfigured):
					logger.Info("group source: oidc claim")
				default:
					// Yapılandırma VAR ama bozuk: sessizce claim'e
					// düşmek, yöneticinin kurduğunu sandığı LDAP'ın hiç
					// çalışmaması demek olurdu.
					return fmt.Errorf("ldap configuration is invalid: %w", err)
				}

				webAPI := httpapi.New(oidcClient, logins, db, logger)
				webAPI.UseGroupSource(groupSwitch)
				// Terminal açık olmasa da gerekli: oturum çerezinin
				// Secure bayrağı bu adresin şemasından türüyor.
				webAPI.SetExternalURL(cfg.HTTP.ExternalURL)

				// Kayıt izleme: panelden oturum oynatma. sshd ile AYNI
				// depo — kayıtların yazıldığı yer ile okunduğu yer
				// ayrışamaz.
				webAPI.UseRecordings(s.Records())

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
				defer api.Shutdown(context.Background())

				logger.Info("oob login enabled", "issuer", cfg.OIDC.IssuerURL)
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
