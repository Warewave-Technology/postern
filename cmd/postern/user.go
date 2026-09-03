package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/sshalg"
	"github.com/warewave/postern/internal/store"
)

// newUserCmd, kullanıcı yönetimi.
//
// YETKİ MODELİ (S3 sözleşmesi): bu komutlar bastion hostunda, veritabanı
// dosyasına erişebilen kişi tarafından çalıştırılır. Ayrı bir kimlik
// katmanı BİLEREK yok: dosyayı (0700) ve CA anahtarını zaten okuyabilen
// biri her şeyi yapabilir; CLI'a şifre koymak güvenlik değil tören olurdu.
// OIDC'li API/UI geldiğinde (S3.2+) yetki oradan sorulacak, CLI "cam
// kırılınca" aracı olarak kalacak.
func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage users",
	}
	cmd.AddCommand(newUserAddCmd())
	cmd.AddCommand(newUserListCmd())
	cmd.AddCommand(newUserModifyCmd())
	cmd.AddCommand(newUserAllowBindCmd())
	cmd.AddCommand(newUserStateCmd())
	cmd.AddCommand(newUserUnbindDirectoryCmd())
	cmd.AddCommand(newUserPurgeCmd())
	cmd.AddCommand(newUserGrantRoleCmd())
	cmd.AddCommand(newUserRevokeRoleCmd())
	return cmd
}

/*
 * newUserPurgeCmd, silinmiş bir hesabın ADINI serbest bırakır.
 *
 * ⚠️ SATIRI SİLMİYOR. Denetim kaydı ve oturum kayıtları kullanıcı adını
 * METİN olarak saklıyor; satır yok olursa geçmişteki o adın kime ait
 * olduğu cevapsız kalır ve aynı adı alan yeni kişiyle karışır. Kalan
 * satır, "o ad şu tarihte boşaltıldı" sorusunun cevabı — ve denetim
 * satırı da kimin boşalttığını yazıyor.
 *
 * ⚠️ YALNIZCA 'deleted' hesaplar: aktif birinin adını almak, o kişi
 * hâlâ kullanıyorken kimliğini elinden almak olurdu.
 */
/*
 * newUserStateCmd, hesabın durumunu HOST'TAN geri alır.
 *
 * ⚠️ NEDEN VAR: hesap yaşam döngüsü işi (internal/accountlife) kaynağın
 * bir süredir doğrulamadığı hesapları önce pasife, sonra 'deleted'
 * durumuna çeviriyor. Pasif hesap bir sonraki girişte kendiliğinden
 * canlanıyor; SİLİNMİŞ hesap canlanmıyor — giriş bilerek reddediliyor
 * (göç 023).
 *
 * Bu, panelden düzeltilebilen bir durum. Ama panelin açılamadığı gün
 * düzeltilemiyordu ve postern'in kendi kuralı şu: CLI cam kırılınca
 * kullanılan araçtır ve hiçbir duruma "buradan çıkış yok" dedirtmemeli.
 * Otomatik bir işlemin geri alınamaması, tam olarak o kuralın ihlali.
 *
 * Yönetici hesapları bu işten zaten etkilenmiyor (StaleAccounts yalnızca
 * sso_only ya da dizine bağlı hesapları tarıyor) — ama "etkilenmiyor"
 * ile "kurtarılabilir" ayrı şeyler.
 */
func newUserStateCmd() *cobra.Command {
	var configPath, name, state string

	cmd := &cobra.Command{
		Use:   "state",
		Short: "Set an account's state (active, inactive, deleted)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" || state == "" {
				return errors.New("--name and --set are both required")
			}
			db, ctx, err := openStore(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			before, _, err := db.AccountState(ctx, name)
			if err != nil {
				return err
			}
			if err := db.SetAccountState(ctx, name, state); err != nil {
				return err
			}
			// ⚠️ Denetim kaydı ŞART: bu komut, otomatik bir kararı elle
			// geri alıyor. "Neden bu hesap yine aktif" sorusunun cevabı
			// başka hiçbir yerde yok.
			if err := db.LogAdmin(ctx, store.AdminLogEntry{
				Actor: "cli", Via: "cli", Action: "user.state", Entity: name,
				Details: fmt.Sprintf("state %s -> %s (set on the host)", before, state),
			}); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%q: %s -> %s\n", name, before, state)
			if state == store.StateActive {
				fmt.Fprint(cmd.OutOrStdout(),
					"\nThe account can sign in again. If the source still does not "+
						"confirm it, the lifecycle job will deactivate it once more — "+
						"fix it at the source, or this is only a reprieve.\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&name, "name", "", "postern username")
	cmd.Flags().StringVar(&state, "set", "", "active, inactive or deleted")
	return cmd
}

func newUserPurgeCmd() *cobra.Command {
	var configPath, name string

	cmd := &cobra.Command{
		Use:   "purge",
		Short: "Free a deleted account's username, keeping the record that it existed",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, ctx, err := openStore(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			res, err := db.PurgeAccount(ctx, name, time.Now())
			if err != nil {
				return err
			}

			// ⚠️ İZ ŞART: kim, ne zaman, neyi serbest bıraktı.
			if lerr := db.LogAdmin(ctx, store.AdminLogEntry{
				Actor: cliActor(), Via: "cli", Action: "user.purge", Entity: name,
				Details: fmt.Sprintf("username released on %s; %d key(s) and %d role(s) "+
					"removed; the row is kept so audit entries naming %q stay readable",
					res.At.Format("2006-01-02"), res.Keys, res.Roles, name),
			}); lerr != nil {
				return lerr
			}

			fmt.Fprintf(cmd.OutOrStdout(),
				"%q is free again — %d key(s) and %d role(s) released\n",
				name, res.Keys, res.Roles)
			fmt.Fprintln(cmd.OutOrStdout(),
				"the account row is kept: audit entries naming it stay readable, "+
					"and `postern log --entity <name>` records when it was released")
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&name, "name", "", "hesap adı (zorunlu)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

/*
 * newUserAllowBindCmd, bir YÖNETİCİ hesabının sıradaki kimlik
 * bağlamasına izin verir.
 *
 * ⚠️ NEDEN VAR — ölçülen saldırı: "developers" grubundaki sıradan bir
 * çalışan, IdP'de kendi kullanıcı adını "ops" yapıp OOB girişini
 * çalıştırdı ve postern'in CLI yönetici hesabını devraldı. Rol
 * eşlemesi bunu durdurmuyor: saldırgan kendi rollerini alıyor, ama
 * hesabın is_admin bayrağı hiçbir eşlemeden gelmiyor.
 *
 * Bağlama ANINDA saldırganla meşru yöneticiyi ayırt eden bir kanıt
 * yok — elde tek şey kullanıcı adı ve o birçok sağlayıcıda kullanıcının
 * kendi değiştirebildiği bir alan. Ayrım ancak buradan, host'tan
 * gelebilir.
 *
 * ⚠️ TEK KULLANIMLIK ve bu bilinçli: kalıcı bir izin, bir kez açılan ve
 * kimsenin kapatmayı hatırlamadığı bir pencere olurdu.
 */
func newUserAllowBindCmd() *cobra.Command {
	var configPath, name string

	cmd := &cobra.Command{
		Use:   "allow-bind",
		Short: "Let the next sign-in bind an identity to an administrator account",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, ctx, err := openStore(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			u, err := db.User(ctx, name)
			if err != nil {
				return err
			}
			// Sıradan hesapların ilk bağlaması zaten serbest: izin
			// vermek anlamsız olurdu ve operatöre yanlış bir güvenlik
			// hissi verirdi ("izin verdim, artık kapalı").
			if !u.Admin {
				return fmt.Errorf("%q is not an administrator; ordinary accounts "+
					"already bind on first sign-in and need no permission", name)
			}

			if err := db.AllowIdentityBind(ctx, name, time.Now()); err != nil {
				return err
			}
			if err := db.LogAdmin(ctx, store.AdminLogEntry{
				Actor: cliActor(), Via: "cli", Action: "user.allow_bind", Entity: name,
				Details: "the next sign-in may bind an identity to this administrator account",
			}); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(),
				"the next sign-in as %q may claim this account\n", name)
			fmt.Fprintln(cmd.OutOrStdout(),
				"this is single use: have them sign in now, and check "+
					"`postern log --entity <name>` afterwards to see which identity took it")
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&name, "name", "", "hesap adı (zorunlu)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

// newUserAddCmd, kullanıcıyı TEK komutta erişilir kılar: oluştur + roller +
// anahtarlar.
//
//	postern user add --name yigit --os-user yigit \
//	    --role ops --key ~/.ssh/id_ed25519.pub
//
// KISMİ BAŞARI SORUNU ve buradaki cevabı: bileşik bir komut yarıda
// kalabilir (kullanıcı oluştu, rol yazım hatalı çıktı). İki önlem birlikte:
//
//  1. Yazmaya başlamadan önce doğrulanabilecek her şey doğrulanır —
//     anahtar dosyaları okunup parse edilir. Bozuk dosya, kullanıcı
//     yaratılmadan ÖNCE hata verir.
//  2. Komut yeniden çalıştırılabilir: kullanıcı zaten varsa bu bir hata
//     değil, "bu kullanıcı şu rollere ve anahtarlara sahip OLSUN" isteğinin
//     devamıdır. AssignRole ve AddPublicKey zaten idempotent; rol yazım
//     hatasını düzeltip aynı komutu tekrar çalıştırmak işi tamamlar.
//     Tek koşul: var olan kullanıcının os_user'ı bayrakla ÇELİŞMEMELİ —
//     çelişki sessizce eski değeri korumak yerine açık hata verir.
func newUserAddCmd() *cobra.Command {
	var configPath, name, osUser, email string
	var roles, keyFiles []string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Create a user with roles and public keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Önlem 1: önce doğrula, sonra dokun.
			type parsedKey struct {
				blob    []byte
				comment string
				path    string
			}
			keys := make([]parsedKey, 0, len(keyFiles))
			for _, path := range keyFiles {
				// #nosec G304 -- yol CLI bayrağından gelir; komutu çalıştıran zaten host'ta
				data, err := os.ReadFile(path)
				if err != nil {
					return fmt.Errorf("key file: %w", err)
				}
				pub, comment, _, _, err := ssh.ParseAuthorizedKey(data)
				if err != nil {
					return fmt.Errorf("key file %s: not a valid public key: %w", path, err)
				}
				// ⚠️ HİÇ ÇALIŞAMAYACAK ANAHTAR EKLENMİYOR — HTTP uçlarındaki
				// kapının aynısı (bkz. sshalg.UnusableKeyType). DSA kapıda
				// reddediliyor ve hedef anahtarı olarak da sunulmuyor;
				// CLI'da kabul etmek, "yazılmış ve hiç çalışmayan" bir kayıt
				// yaratmak olurdu — sahibi bastion'ı suçlar.
				if why := sshalg.UnusableKeyType(pub.Type()); why != "" {
					return fmt.Errorf("key file %s: %s", path, why)
				}
				keys = append(keys, parsedKey{blob: pub.Marshal(), comment: comment, path: path})
			}

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

			out := cmd.OutOrStdout()

			_, err = db.CreateUser(ctx, name, email, osUser)
			switch {
			case errors.Is(err, store.ErrConflict):
				// Önlem 2: yeniden çalıştırma. Ama kimlik alanı çelişiyorsa
				// sessizce eskiyi korumak, operatörü yanıltır.
				existing, uerr := db.User(ctx, name)
				if uerr != nil {
					return uerr
				}
				if existing.OSUser != osUser {
					return fmt.Errorf("user %q exists with os-user %q (asked for %q); refusing to change identity implicitly",
						name, existing.OSUser, osUser)
				}
				fmt.Fprintf(out, "user %q already exists, updating grants\n", name)
			case err != nil:
				return err
			default:
				if aerr := auditCLI(ctx, db, "user.create", name,
					fmt.Sprintf("os-user %s", osUser)); aerr != nil {
					return aerr
				}
				fmt.Fprintf(out, "user %q created\n", name)
			}

			for _, role := range roles {
				if err := db.AssignRole(ctx, name, role, time.Time{}); err != nil {
					if errors.Is(err, store.ErrNotFound) {
						return fmt.Errorf("role %q not found — create it with `postern role add`, then re-run this command (already-applied grants are kept)", role)
					}
					return err
				}
				if aerr := auditCLI(ctx, db, "user.grant_role", name,
					"assigned role "+role); aerr != nil {
					return aerr
				}
				fmt.Fprintf(out, "  role %q assigned\n", role)
			}

			for _, k := range keys {
				if err := db.AddPublicKey(ctx, name, k.blob, k.comment); err != nil {
					if errors.Is(err, store.ErrConflict) {
						return fmt.Errorf("key %s belongs to another user — a key can only identify one person", k.path)
					}
					return err
				}
				// Anahtarın KENDİSİ loglanmıyor — yorumu yeterli ve
				// blob denetim kaydını gereksiz büyütür.
				if aerr := auditCLI(ctx, db, "user.key_add", name, k.comment); aerr != nil {
					return aerr
				}
				fmt.Fprintf(out, "  key %s added\n", k.path)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&name, "name", "", "postern kullanıcı adı (zorunlu)")
	cmd.Flags().StringVar(&osUser, "os-user", "", "hedeflerdeki hesap (zorunlu)")
	cmd.Flags().StringVar(&email, "email", "", "OIDC eşleşmesi için e-posta")
	cmd.Flags().StringArrayVar(&roles, "role", nil, "verilecek rol (tekrarlanabilir)")
	cmd.Flags().StringArrayVar(&keyFiles, "key", nil, "public key dosyası (tekrarlanabilir)")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("os-user")
	return cmd
}

// newUserListCmd, kullanıcıları rolleriyle listeler.
func newUserListCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List users with their roles",
		RunE: func(cmd *cobra.Command, args []string) error {
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

			users, err := db.Users(ctx)
			if err != nil {
				return err
			}
			if len(users) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no users defined")
				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tOS USER\tADMIN\tROLES\tKEYS")

			for _, u := range users {
				roleNames := make([]string, 0, len(u.Roles))
				for _, r := range u.Roles {
					roleNames = append(roleNames, r.Name)
				}
				rolesCol := "-"
				if len(roleNames) > 0 {
					rolesCol = strings.Join(roleNames, ",")
				}

				// Kullanıcı başına bir sorgu: listeleme yolu için kabul
				// edilebilir; sıcak yol değil.
				keys, err := db.PublicKeys(ctx, u.Name)
				if err != nil {
					return err
				}

				adminCol := "-"
				if u.Admin {
					adminCol = "yes"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", u.Name, u.OSUser, adminCol, rolesCol, len(keys))
			}

			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}

// newUserModifyCmd, var olan kullanıcının kimlik alanlarını AÇIKÇA değiştirir.
//
//	postern user modify --name yigit --email yigit@warewave.io
//	postern user modify --name yigit --os-user deploy
//
// "user add" kimliği örtük değiştirmeyi reddediyor (yanlışlıkla farklı
// os-user yazan bir yönetici sessizce kimlik değiştirmemeli); bu komut o
// işin bilinçli kapısı. --email "" adresi siler.
func newUserModifyCmd() *cobra.Command {
	var configPath, name, osUser, email string
	var admin, ssoOnly bool

	cmd := &cobra.Command{
		Use:   "modify",
		Short: "Change a user's email, os-user, admin or sso-only flag",
		// ⚠️ NoArgs olmadan "--admin false" sessizce YANLIŞ çalışır:
		// pflag boolean bayrağı --admin'i true yapar, "false" kelimesi
		// pozisyonel argüman olarak yutulurdu. NoArgs bunu hataya çevirir
		// ve kullanıcı --admin=false yazmayı öğrenir.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			emailSet := cmd.Flags().Changed("email")
			osUserSet := cmd.Flags().Changed("os-user")
			adminSet := cmd.Flags().Changed("admin")
			ssoOnlySet := cmd.Flags().Changed("sso-only")
			if !emailSet && !osUserSet && !adminSet && !ssoOnlySet {
				return fmt.Errorf("nothing to change: pass --email, --os-user, --admin and/or --sso-only")
			}

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

			out := cmd.OutOrStdout()

			if emailSet {
				if err := db.SetUserEmail(ctx, name, email); err != nil {
					if errors.Is(err, store.ErrConflict) {
						return fmt.Errorf("email %q already belongs to another user", email)
					}
					return err
				}
				if email == "" {
					fmt.Fprintf(out, "user %q: email cleared\n", name)
				} else {
					fmt.Fprintf(out, "user %q: email set to %s\n", name, email)
				}
			}

			if adminSet {
				// Admin bayrağını YALNIZCA bu CLI değiştirir: web/API
				// tarafı okur ama yazamaz — kendini admin yapabilen bir
				// panel, ele geçirildiğinde kalıcı yetki olurdu.
				if err := db.SetUserAdmin(ctx, name, admin); err != nil {
					return err
				}
				// ⚠️ Bu, sistemdeki en ayrıcalıklı işlem ve tasarım onu
				// bilerek yalnızca CLI'ya emanet ediyor. İz bırakmaması
				// düşünülemez.
				if err := auditCLI(ctx, db, "user.admin", name,
					fmt.Sprintf("admin set to %v", admin)); err != nil {
					return err
				}
				fmt.Fprintf(out, "user %q: admin set to %v\n", name, admin)
			}

			if ssoOnlySet {
				// sso_only iki şeye birden karar veriyor: public key
				// kapısının kapalı olması VE kullanıcının periyodik
				// dizin senkronizasyonunun kapsamına girmesi. İkincisi
				// "yetkisi otomatik iptal edilebilir" demek, yani bu da
				// admin bayrağı gibi yalnızca host'tan verilmeli.
				if err := db.SetUserSSOOnly(ctx, name, ssoOnly); err != nil {
					return err
				}
				if err := auditCLI(ctx, db, "user.sso_only", name,
					fmt.Sprintf("sso-only set to %v", ssoOnly)); err != nil {
					return err
				}
				fmt.Fprintf(out, "user %q: sso-only set to %v", name, ssoOnly)
				if ssoOnly {
					fmt.Fprint(out, " (public key login disabled; directory sync may revoke roles)")
				}
				fmt.Fprintln(out)
			}

			if osUserSet {
				if err := db.SetUserOSUser(ctx, name, osUser); err != nil {
					return err
				}
				// Etki alanını açıkça söyle: geçmiş oturum kayıtları
				// değişmez, yalnızca bundan sonraki sertifikalar.
				fmt.Fprintf(out, "user %q: os-user set to %s (affects new sessions only)\n", name, osUser)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&name, "name", "", "postern kullanıcı adı (zorunlu)")
	cmd.Flags().StringVar(&email, "email", "", "yeni e-posta (boş = sil)")
	cmd.Flags().StringVar(&osUser, "os-user", "", "hedeflerdeki yeni hesap")
	cmd.Flags().BoolVar(&admin, "admin", false, "uygulama yönetim yetkisi — eşittirle yaz: --admin=true / --admin=false")
	cmd.Flags().BoolVar(&ssoOnly, "sso-only", false,
		"erişim yalnızca IdP üzerinden — eşittirle yaz: --sso-only=true / --sso-only=false")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}
