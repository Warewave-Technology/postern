package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/ldap"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/secret"
	"github.com/Warewave-Technology/postern/internal/store"
)

// newSecretCmd, sır anahtarı yönetimi.
func newSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage the key that seals stored secrets",
	}
	cmd.AddCommand(newSecretInitCmd())
	return cmd
}

func newSecretInitCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create the master key for encrypted settings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			if cfg.SecretKeyFile == "" {
				return fmt.Errorf("secret_key_file is not set in %s", configPath)
			}

			// Init var olan anahtarın üstüne yazmaz: yazsaydı o anahtarla
			// mühürlenmiş her sır kalıcı olarak okunamaz hale gelirdi.
			if _, err := secret.Init(cfg.SecretKeyFile); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "secret key written to %s\n", cfg.SecretKeyFile)
			fmt.Fprintln(cmd.OutOrStdout(),
				"keep it out of the database's backup path — together they defeat the encryption")
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	return cmd
}

// newSettingsCmd, çalışma zamanı ayarları.
func newSettingsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "settings",
		Short: "Manage runtime settings stored in the database",
	}
	cmd.AddCommand(newSettingsSetCmd())
	cmd.AddCommand(newSettingsListCmd())
	cmd.AddCommand(newSettingsTestLDAPCmd())
	return cmd
}

// openStoreWithSecrets, sır anahtarı bağlanmış store döner.
func openStoreWithSecrets(configPath string) (*store.Store, context.Context, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	db, err := store.Open(ctx, cfg.Database.DSN)
	if err != nil {
		return nil, nil, err
	}
	if cfg.SecretKeyFile != "" {
		box, err := secret.Load(cfg.SecretKeyFile)
		if err != nil {
			db.Close()
			return nil, nil, err
		}
		db.UseSecretBox(box)
	}
	return db, ctx, nil
}

func newSettingsSetCmd() *cobra.Command {
	var configPath, key, value string
	var isSecret bool

	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set a runtime setting",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, ctx, err := openStoreWithSecrets(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			// Sır bilinen anahtarlarda otomatik: yönetici --secret
			// yazmayı unutup parolayı düz metin bırakmasın.
			if ldap.SecretKeys[key] || auth.OIDCSecretKeys[key] {
				isSecret = true
			}

			/*
			 * ⚠️ AKTİF GİRİŞ KAYNAĞI: ACİL ÇIKIŞ YOLU BURASI.
			 *
			 * Panel bu ayarı ancak geçilecek kaynağın gerçekten birini
			 * içeri alabildiğini kanıtladıktan sonra değiştiriyor.
			 * Burada o kontroller YOK ve olmamalı: bu komut tam da
			 * panelin açılmadığı durumda çalışacak. Host'a
			 * erişebilen kişi zaten en yüksek güven seviyesinde.
			 *
			 * Ama değerin kendisi doğrulanıyor: yazım hatası olan bir
			 * kaynak adı, hiçbir kapının açılmadığı bir kurulum
			 * üretirdi ve hata ancak bir sonraki giriş denemesinde
			 * görülürdü.
			 */
			// ⚠️ `unknown`, grubu olmayan HERKESİN düştüğü ad. Yönetici
			// grubu yapılırsa en az ayrıcalıklı küme en ayrıcalıklısına
			// dönüşür. Panel de reddediyor; burada da reddediliyor,
			// çünkü asıl tehlikeli yol "elle yazdım" olanı.
			if key == ldap.KeyAdminGroup && strings.EqualFold(strings.TrimSpace(value), model.UnknownGroup) {
				return fmt.Errorf("%q is the catch-all group for accounts whose source "+
					"named no group; making it the administrator group would hand "+
					"administrator to every one of them", model.UnknownGroup)
			}

			// ⚠️ Süre ayarı çözülemiyorsa REDDET: okuma anında sessizce
			// varsayılana düşmesi, operatörün yazdığının anlaşıldığını
			// sanmasına yol açıyordu ("45d" ölçüldü).
			/*
			 * ⚠️ PAROLA TABANI BURADA DA DOĞRULANIYOR.
			 *
			 * API tarafında bu kontrol "sessizce başka bir şey yapmayı"
			 * kapatmak için eklenmişti; CLI'da yoktu. Yani aynı ayarı
			 * host'tan yazan operatör "on iki" yazıp politikanın 12'de
			 * kaldığını fark etmeyebiliyordu — kapatıldığı iddia edilen
			 * arızanın ikinci kapısı açık kalmıştı. Alt sınır da burada
			 * geçerli: ayarı 4'e çekerek politikayı kapatmak, bir ayar
			 * değişikliği değil bir güvenlik kontrolünün sökülmesi.
			 */
			if key == auth.KeyPasswordMinLength {
				if _, perr := auth.ParsePasswordMinLength(value); perr != nil {
					return perr
				}
			}
			if key == auth.KeyConfirmTTL || key == auth.KeyDeleteTTL {
				if _, perr := auth.ParseAccountDuration(value); perr != nil {
					return perr
				}
			}

			if key == auth.KeyLoginSource {
				parsed, perr := auth.ParseLoginSource(value)
				if perr != nil {
					return perr
				}
				value = string(parsed)
			}

			// Sır değeri komut satırında GEÇMEZ: kabuk geçmişine ve
			// süreç listesine (ps) düşer. Terminalden yankısız okunur.
			if isSecret && value == "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "value for %s: ", key)
				raw, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(cmd.ErrOrStderr())
				if err != nil {
					return fmt.Errorf("reading value: %w", err)
				}
				value = strings.TrimSpace(string(raw))
			}

			if err := db.SetSetting(ctx, key, value, isSecret, cliActor()); err != nil {
				return err
			}

			/*
			 * ⚠️ DEFTERE YAZILIYOR — VE YAZILMIYORDU.
			 *
			 * audit.go'nun başındaki gerekçe ("CLI'dan yapılan hiçbir
			 * değişiklik admin_log'a düşmüyordu ... en ayrıcalıklı olanı
			 * denetlenmiyordu") user/role/target'a ulaşıp burada durmuş.
			 * Oysa bu komut, CLI'ın YÖNETİCİ VERME/ALMA kolu:
			 * ldap.admin_group değişince eski gruptan gelen bütün
			 * yetkiler düşüyor, yenisinin üyeleri bir sonraki girişte
			 * yönetici oluyor.
			 *
			 * ÖLÇÜLDÜ: meşru yöneticiyi düşürüp saldırganın grubunu
			 * yönetici yapan ve sonra ayarı geri alan zincir, hiçbir yerde
			 * tek satır iz bırakmıyordu — üstelik `postern log` ardından
			 * "the audit trail is empty" diyor. settings tablosundaki
			 * updated_by yalnızca ŞU ANKİ değeri taşıyor; geri alma onu
			 * da üzerine yazıyor.
			 *
			 * ⚠️ DEĞER YAZILMIYOR, ANAHTAR YAZILIYOR. Sırlar bu komuttan
			 * geçiyor ve defter panelde okunuyor: değeri deftere koymak,
			 * şifrelenmiş tutulan şeyi düz metne çevirmek olurdu.
			 */
			details := "value changed"
			if isSecret {
				details = "secret value changed (not recorded)"
			}
			if err := auditCLI(ctx, db, "setting.set", key, details); err != nil {
				return err
			}

			if isSecret {
				fmt.Fprintf(cmd.OutOrStdout(), "%s set (encrypted, not shown again)\n", key)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "%s = %s\n", key, value)
			}

			/*
			 * ⚠️ YÖNETİCİ GRUBU DEĞİŞTİYSE, ESKİ GRUPTAN GELEN YETKİLER
			 * BURADA DÜŞÜYOR.
			 *
			 * Düşmeseydi sessiz bir sızıntı kalırdı: yetki yalnızca kişi
			 * giriş yaptığında güncelleniyor, dolayısıyla eski gruptan
			 * gelen kişi bir daha hiç giriş yapmasa da yönetici KALIRDI.
			 * "Grubu değiştirdim" ile "yetki değişti" arasındaki fark,
			 * kimsenin bakmadığı bir yerde süresiz açık dururdu.
			 *
			 * Yeni grubun üyeleri yetkilerini bir sonraki girişlerinde
			 * alıyor: burada dizine sormuyoruz, çünkü bu komut dizin
			 * ulaşılamazken de çalışabilmeli — acil çıkış yolunun bir
			 * ağ bağlantısına bağlı olmaması onun bütün anlamı.
			 *
			 * Panelde durum farklı ve orada olması gerektiği gibi: orası
			 * gösterdiği listeyi onaylatıp yetkiyi ANINDA uyguluyor.
			 */
			if key == auth.KeyLoginSource {
				explainLoginSource(cmd, db, ctx, auth.LoginSource(value))
			}

			if key == ldap.KeyAdminGroup {
				_, revoked, err := db.ApplyAdminGroup(ctx, nil)
				if err != nil {
					return fmt.Errorf("clearing previous group-granted admins: %w", err)
				}
				if len(revoked) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(),
						"%d account(s) lost administrator granted by the previous group: %s\n",
						len(revoked), strings.Join(revoked, ", "))
				}

				/*
				 * ⚠️ KİMİN YETKİSİNİN DÜŞTÜĞÜ DEFTERE YAZILIYOR.
				 *
				 * Yukarıdaki setting.set satırı "ayar değişti" diyor;
				 * bu satır KİMİN yöneticiliğini kaybettiğini söylüyor ve
				 * ikisi ayrı sorular. Liste yalnızca stdout'a yazılıyordu
				 * — yani komutu koşan kişinin terminalinde kalıyor,
				 * altı ay sonra bakan kimse göremiyordu.
				 *
				 * Boş liste de yazılıyor: "grup değişti ve kimse
				 * etkilenmedi" ile "bakmadım" ayrı şeyler.
				 */
				lost := "no account held administrator from the previous group"
				if len(revoked) > 0 {
					lost = "administrator revoked from " + strings.Join(revoked, ", ")
				}
				if err := auditCLI(ctx, db, "admin_group.set", value, lost); err != nil {
					return err
				}
				if value != "" {
					fmt.Fprintln(cmd.OutOrStdout(),
						"members of the new group become administrators at their next sign-in")
				}

				// Yönetici kalmadıysa SÖYLE. Reddetmiyoruz — host'ta
				// olan kişi zaten `postern admin issue` ile çıkabilir ve
				// acil çıkış yolunu kilitlemek onu acil çıkış olmaktan
				// çıkarırdı. Ama sessiz kalmak, panelin kapandığını
				// kimsenin fark etmemesi demekti.
				if admins, aerr := db.Admins(ctx); aerr == nil && len(admins) == 0 {
					fmt.Fprintln(cmd.ErrOrStderr(),
						"warning: postern now has no administrator at all — "+
							"run `postern admin issue --name <name>` to create one")
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&key, "key", "", "setting name, e.g. ldap.url (required)")
	cmd.Flags().StringVar(&value, "value", "", "value; leave it empty for a secret and you will be prompted")
	cmd.Flags().BoolVar(&isSecret, "secret", false, "store the value encrypted (--secret=true)")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func newSettingsListCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List runtime settings (secrets masked)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, ctx, err := openStore(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			views, err := db.Settings(ctx)
			if err != nil {
				return err
			}
			if len(views) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no settings stored")
				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "KEY\tVALUE\tUPDATED\tBY")
			for _, v := range views {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", v.Key, v.Value,
					v.UpdatedAt.Local().Format("2006-01-02 15:04"), v.UpdatedBy)
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	return cmd
}

// newSettingsTestLDAPCmd, yapılandırmayı gerçekten deneyerek doğrular.
//
// Kullanıcının istediği "config test" bu: yanlış base DN ya da bind
// parolası ilk gerçek girişte değil, burada ortaya çıksın.
func newSettingsTestLDAPCmd() *cobra.Command {
	var configPath, username string

	cmd := &cobra.Command{
		Use:   "test-ldap",
		Short: "Test the stored LDAP configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, ctx, err := openStoreWithSecrets(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			src, err := ldap.SourceFromStore(ctx, db)
			if err != nil {
				if errors.Is(err, ldap.ErrNotConfigured) {
					return fmt.Errorf("ldap is not configured (set %s first)", ldap.KeyURL)
				}
				return err
			}

			out := cmd.OutOrStdout()
			if err := src.Test(ctx); err != nil {
				return err
			}
			fmt.Fprintln(out, "connection and bind: ok")

			// Kullanıcı verildiyse gerçek bir arama yap: filtrenin
			// çalıştığını görmenin tek yolu.
			if username != "" {
				res, err := src.Groups(ctx, authIdentity(username))
				if err != nil {
					return err
				}
				// ⚠️ ÜÇ AYRI CEVAP, ÜÇ AYRI MESAJ. Eskiden üçü de "found
				// no groups" diye çıkıyordu ve "dizin bu kullanıcıyı
				// tanımıyor" ile "tanıyor ama grubu yok" aynı satıra
				// düşüyordu; ilkinde operatör grup ayarlarını
				// kurcalayarak saatler harcıyordu.
				switch res.Presence {
				case auth.GroupsAbsent:
					fmt.Fprintf(out, "user %q: the directory answered, and it has no such user "+
						"(check user_base and user_filter; postern looks the name up as given)\n", username)
					return nil
				case auth.GroupsUnknown:
					fmt.Fprintf(out, "user %q: the directory could not answer for this name\n", username)
					return nil
				}
				groups := res.Groups
				if len(groups) == 0 {
					fmt.Fprintf(out, "user %q: found in the directory, but in no groups within scope\n", username)
					return nil
				}
				fmt.Fprintf(out, "user %q groups: %s\n", username, strings.Join(groups, ", "))

				// Hangileri role dönüşüyor: eşlemenin çalışıp
				// çalışmadığını burada gör.
				roles, unmapped, err := db.RolesForGroups(ctx, groups)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "  mapped to roles: %s\n", joinOrDash(roles))
				fmt.Fprintf(out, "  unmapped groups: %s\n", joinOrDash(unmapped))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&username, "user", "", "also query this user's groups")
	return cmd
}

// authIdentity, test komutunun ihtiyaç duyduğu asgari kimlik.
func authIdentity(username string) auth.Identity {
	return auth.Identity{Username: username}
}

func joinOrDash(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	return strings.Join(v, ", ")
}

/*
 * explainLoginSource, kaynağı değiştirmenin SONUCUNU söyler.
 *
 * Panel bu geçişleri reddedebiliyor; CLI reddetmiyor (acil çıkışı
 * kilitlemek onu acil çıkış olmaktan çıkarır). Geriye kalan tek doğru
 * davranış, kapıyı kapatan bir değişikliği SESSİZ yapmamak: operatör
 * "yerele döndüm" deyip panele giremediğinde sebebi burada yazıyor
 * olsun.
 */
func explainLoginSource(cmd *cobra.Command, db *store.Store, ctx context.Context, src auth.LoginSource) {
	out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()

	switch src {
	case auth.SourceLocal:
		fmt.Fprintln(out, "panel sign-in now uses postern's own credentials; "+
			"the identity provider and directory doors are closed")
		// ⚠️ Geri dönüş satırı bu dalda BASILMIYOR (aşağıdaki koşul):
		// geri dönülecek yer zaten burası. Aynı komutu "bunu geri almak
		// için" diye yazdırmak, okuyanın metne güvenini bir defada
		// bitirir.
		holders, err := db.LocalCredentialHolders(ctx)
		if err != nil {
			return
		}
		/*
		 * ⚠️ SAYMAK YETMEZ: HESAP GERÇEKTEN GİREBİLİYOR OLMALI.
		 *
		 * Panelde aynı kontrol bu yüzden düzeltildi (canSwitchTo) ve
		 * burada bayat kalmıştı: silinmiş bir yönetici de "yerel
		 * kimlik bilgisi olan bir yönetici" sayılıyordu, ama
		 * locallogin.go silinmiş hesabı reddediyor. Yani uyarı tam da
		 * uyarması gereken durumda susuyordu.
		 *
		 * must_change de saymıyor: o hesap giriyor ama parolasını
		 * koyana kadar hiçbir şey yapamıyor — yapamadığı şeylerden
		 * biri de kaynağı geri çevirmek.
		 */
		for _, h := range holders {
			if h.IsAdmin && h.State == store.StateActive && !h.MustChange {
				return
			}
		}
		// ⚠️ Yerele dönmek de kilitleyebilir ve sezgiye aykırı olduğu
		// için asıl tehlikeli olan bu: yerel kapı yalnızca yerel
		// kimlik bilgisi OLAN hesapları alıyor.
		fmt.Fprintln(errOut, "warning: no local administrator has a sign-in secret — "+
			"run `postern admin issue --name <name>` or nobody can sign in to the panel")

	case auth.SourceOIDC:
		fmt.Fprintln(out, "panel sign-in now goes through the identity provider; "+
			"local secrets no longer open the panel")
		fmt.Fprintln(out, "administrator comes from the group named in ldap.admin_group")

	case auth.SourceLDAP:
		fmt.Fprintln(out, "panel sign-in now uses directory usernames and passwords; "+
			"local secrets no longer open the panel")
		fmt.Fprintln(out, "the directory door does not create accounts: only directory "+
			"users who already have a postern account can sign in")
	default:
		return
	}

	if src != auth.SourceLocal {
		fmt.Fprintln(out, "to undo this from the host: "+
			"postern settings set --key auth.source --value local")
	}
}
