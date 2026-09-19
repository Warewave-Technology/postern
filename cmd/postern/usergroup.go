package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/v2/internal/config"
	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/store"
)

/*
 * Var olan bir kullanıcıya grup verme ve alma.
 *
 * ⚠️ NEDEN VAR: `user add --group` yalnızca hesabı AÇARKEN grup
 * verebiliyordu; `user modify` e-posta, os-user, admin ve sso-only ile
 * sınırlı. Var olan birine grup eklemenin ya da almanın CLI karşılığı
 * YOKTU — panelde vardı.
 *
 * Bu, eksik bir kolaylık değil: CLI tam olarak PANELİN ÇALIŞMADIĞI AN
 * için var. Kilitlendiğinde ya da IdP düştüğünde host'a giriyorsun ve
 * orada kimseye erişim veremiyordun. Demo kurulurken de aynı duvara
 * toslandı; çare, kullanıcının zaten sahip olduğu group hedef eklemek
 * oldu — doğru çözüm değil, dolambaç.
 *
 * ⚠️ AD ALANI "user", "group" DEĞİL. Atama kullanıcıya ait bir gerçek ve
 * depo bunu her yerde öyle adlandırıyor: `user add --group`, `user list`
 * ROLES sütunu, panel rotaları /api/admin/users/{name}/groups, ve
 * denetim satırının entity'si kullanıcı adı. group.go'da user_groups'a
 * dokunan hiçbir şey yok; ikinci bir sahip yaratmak, aynı ilişkiyi iki
 * yerden yönetmek olurdu.
 *
 * ⚠️ ADLARDA "add" YOK. Bu CLI'da `add` SATIR YARATAN komutların sözü
 * (user add, group add, target add, mapping add) ve hepsi "created" /
 * "registered" basıyor. Atama satır yaratmıyor; `grant-group` /
 * `revoke-group` hem işi doğru adlandırıyor hem `admin revoke` ile aynı
 * fiili aynı anlamda kullanıyor.
 */

func newUserGrantGroupCmd() *cobra.Command {
	var configPath, name string
	var groups []string

	cmd := &cobra.Command{
		Use:   "grant-group",
		Short: "Give an existing user a group",
		Long: "Grants one or more groups to an account that already exists.\n" +
			"The grant is manual: directory synchronisation replaces only the\n" +
			"groups it owns and leaves this one alone.",
		Args: cobra.NoArgs,
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

			/*
			 * ⚠️ SİLİNMİŞ HESABA ROL VERMEK REDDEDİLMİYOR — UYARILIYOR.
			 *
			 * İlk hâli reddediyordu ve gerekçesi makuldü: silinmiş hesap
			 * hiçbir kapıdan giremediği için grup ona hiçbir şey vermez,
			 * komut da boşuna başarılı görünür.
			 *
			 * Ama bu CLI ACİL ÇIKIŞ YOLU ve onun ilk kuralı kimseyi
			 * kilitlememek. "Önce grupları geri ver, sonra hesabı aç"
			 * meşru bir sıra; `postern user state` tam da hiçbir durumun
			 * çıkmaz sokak olmaması için var. Reddetmek, operatöre
			 * sırasını bize göre yapmayı dayatırdı.
			 *
			 * Doğru cevap: yaz, ve NE VERMEDİĞİNİ söyle. Sessizce
			 * başarılı görünmek ile reddetmek arasındaki üçüncü yol bu.
			 */
			state, _, serr := db.AccountState(ctx, name)
			if serr != nil {
				if errors.Is(serr, store.ErrNotFound) {
					return fmt.Errorf("no user %q — see `postern user list`", name)
				}
				return serr
			}

			out := cmd.OutOrStdout()
			for _, group := range groups {
				/*
				 * ⚠️ DİZİNDEN GELEN BİR ROLÜ ELLE VERMEK, ONU
				 * SENKRONİZASYONUN ERİŞEMEYECEĞİ YERE TAŞIR.
				 *
				 * AssignGroup'un ON CONFLICT dalı source'u koşulsuz
				 * 'manual' yapıyor; SyncGroups ise yalnızca source='sso'
				 * satırlarını siliyor. Yani zaten IdP grubundan gelen
				 * bir grubu "yeniden vermek", kişi gruptan çıkarıldığında
				 * grubun ÜZERİNDE KALMASI demek — ve hiçbir otomatik yol
				 * onu geri alamaz. Sessizce kalıcı yetki üretmek, bu
				 * komutun yapabileceği en kötü şey.
				 *
				 * Engellemiyoruz (acil çıkış yolu), ama olacağı
				 * SÖYLÜYORUZ. Okuma yazmadan ÖNCE: sonrasında kaynak
				 * zaten 'manual' olmuş olurdu.
				 */
				priorSource, hadGrant, perr := db.GroupGrantSource(ctx, name, group)
				if perr != nil {
					return roleErr(perr, group)
				}

				// ⚠️ SÜRESİZ. expires_at şemada var ve OKUNUYOR ama onu
				// yazan bir yüzey eklemiyoruz: AssignGroup'un ON CONFLICT
				// dalı expires_at'i koşulsuz yazıyor, yani bayraksız
				// ikinci bir grant süreyi SESSİZCE siler. Okuması da
				// yok — `user list` süreyi gösteremiyor. Yazması olup
				// okuması olmayan bir alan, erişimin kimsenin
				// bakamayacağı bir saatte kaybolması demek.
				if err := db.AssignGroup(ctx, name, group, time.Time{}); err != nil {
					return roleErr(err, group)
				}

				// ⚠️ Denetim hatası YUTULMUYOR (audit.go sözleşmesi):
				// izsiz bir yetki değişikliği, yapılmamış olandan kötü.
				if err := auditCLI(ctx, db, "user.grant_role", name, "group "+group); err != nil {
					return err
				}
				fmt.Fprintf(out, "user %q: group %q granted\n", name, group)

				if hadGrant && priorSource == "sso" {
					fmt.Fprintf(out, "  ⚠ %q already had this group from a directory group; "+
						"it is now a manual grant\n"+
						"    and directory synchronisation will no longer take it away. "+
						"Use `postern user revoke-group` to remove it.\n", name)
				}
			}

			// ⚠️ HESABIN GİREMEDİĞİNİ SÖYLE. Rol yazıldı ama silinmiş bir
			// hesap hiçbir kapıdan giremiyor; bunu yazmazsak komut
			// erişim verdiğini ima etmiş olur.
			if state == store.StateDeleted {
				fmt.Fprintf(out, "\nnote: %q is deleted and cannot sign in, so this grants "+
					"nothing yet;\nbring it back with `postern user state --name %s --set active`\n",
					name, name)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&name, "name", "", "postern username (required)")
	cmd.Flags().StringArrayVar(&groups, "group", nil, "verilecek grup (tekrarlanabilir, zorunlu)")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("group")
	return cmd
}

func newUserRevokeGroupCmd() *cobra.Command {
	var configPath, name string
	var groups []string

	cmd := &cobra.Command{
		Use:   "revoke-group",
		Short: "Take a group away from a user",
		Long: "Removes a group from an account. A group that came from a\n" +
			"directory group is restored at the user's next sign-in — remove\n" +
			"the group mapping to stop that.",
		Args: cobra.NoArgs,
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

			/*
			 * ⚠️ KULLANICIYI DÖNGÜDEN ÖNCE, BİR KEZ OKU.
			 *
			 * ÖLÇÜLEN ARIZA: okuma döngünün içindeydi ve olmayan bir
			 * KULLANICI adı `no group "developer"` diye raporlanıyordu —
			 * yani operatör, doğru yazdığı grup adını düzeltmeye
			 * gönderiliyordu. Panelin çalışmadığı gün en son isteyeceğin
			 * şey, seni yanlış ipucuna göndermesi.
			 *
			 * Buradan sonra düşen not-found yalnızca ROL adına dair
			 * olabilir; roleErr de tam olarak onu söylüyor.
			 */
			u, uerr := db.User(ctx, name)
			if uerr != nil {
				if errors.Is(uerr, store.ErrNotFound) {
					return fmt.Errorf("no user %q — see `postern user list`", name)
				}
				return uerr
			}

			out := cmd.OutOrStdout()
			var revokedAny bool

			for _, group := range groups {
				/*
				 * ⚠️ "ZATEN YOKTU" İLE "ALDIM" AYRI CÜMLELER.
				 *
				 * RevokeGroup bağ yoksa sessiz no-op ve bu doğru
				 * davranış — ama komutun "alındı" demesi yanlış olurdu:
				 * var olan ama hiç verilmemiş bir grup adını yazan
				 * operatör (ops yerine ops-admin) işini bitirdiğini
				 * sanırdı. Kullanıcının ya da grubun HİÇ OLMAMASI zaten
				 * ayrı bir hata; bu, ayırt ettiğimiz üçüncü durum.
				 *
				 * "aktif atama" diyoruz, "satır" değil: User()'ın JOIN'i
				 * süresi dolmuş atamaları süzüyor, yani silinen satır
				 * burada zaten yok sayılmış olabilir.
				 */
				had := holdsGroup(u, group)

				if err := db.RevokeGroup(ctx, name, group); err != nil {
					return roleErr(err, group)
				}
				if err := auditCLI(ctx, db, "user.revoke_role", name, "group "+group); err != nil {
					return err
				}

				if had {
					revokedAny = true
					fmt.Fprintf(out, "user %q: group %q revoked\n", name, group)
				} else {
					fmt.Fprintf(out, "user %q held no active grant for group %q; nothing changed\n",
						name, group)
				}
			}

			/*
			 * ⚠️ BU UYARI OLMADAN KOMUT YALAN SÖYLER.
			 *
			 * RevokeGroup kaynak süzmeden siliyor (store.go), SyncGroups
			 * ise HER SSO GİRİŞİNDE IdP'nin listesini yeniden yazıyor.
			 * Yani dizinden gelen bir grubu almak, kişinin bir sonraki
			 * girişine kadar süren geçici bir işlem — ve komut bunu
			 * söylemezse "erişimi kestim" diye okunur. Panelin çalışmadığı
			 * gün çalıştırılan komutun tam olarak yanlış anlaşılmaması
			 * gereken yeri burası.
			 */
			if revokedAny {
				fmt.Fprintf(out, "\nif that group comes from a directory group it returns at "+
					"the next sign-in;\nremove the mapping with `postern mapping remove "+
					"--group <group> --group <group>`\n")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&name, "name", "", "postern username (required)")
	cmd.Flags().StringArrayVar(&groups, "group", nil, "group to remove (repeatable, required)")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("group")
	return cmd
}

/*
 * holdsGroup, okunmuş kullanıcının o group AKTİF olarak sahip olup
 * olmadığını söyler.
 *
 * store.User süresi dolmuş atamaları süzüyor: süresi geçmiş bir grup
 * "yok" sayılır ve doğrusu bu — erişim vermiyordu. Çıktıda da "aktif
 * atama" diyoruz, "satır" değil.
 *
 * ⚠️ Bu, silmeden ÖNCE alınmış bir gözlem. İki operatör aynı anda
 * çalışırsa cümle yanlış olabilir; veri değil. Alternatifi
 * RevokeGroup'un RowsAffected döndürmesiydi — paneli de etkileyen bir
 * imza değişikliği, tek bir mesaj nüansı için.
 */
func holdsGroup(u model.User, group string) bool {
	for _, r := range u.Groups {
		if r.Name == group {
			return true
		}
	}
	return false
}

/*
 * roleErr, store hatalarını operatörün okuyabileceği cümlelere çevirir.
 *
 * ⚠️ HANGİ ADIN YANLIŞ OLDUĞUNU SÖYLÜYOR. store.ErrNotFound "kullanıcı
 * mı grup mü" ayrımını yapmıyor, ama ÇAĞIRAN yapabiliyor: iki komut da
 * kullanıcıyı önce doğruluyor (grant'ta RefuseIfDeleted, revoke'ta
 * User), dolayısıyla buraya düşen bir not-found ROL adına dair.
 * "ikisinden biri yanlış" demek, operatörü doğru adı iki kez kontrol
 * etmeye gönderirdi.
 *
 * ⚠️ İÇ ZİNCİR GÖVDEYE GİTMİYOR. "store.AssignGroup: store: not found:
 * sql: no rows in result set" operatöre hiçbir şey anlatmıyor; httpapi
 * tarafındaki storeErr de aynı sebeple zinciri log'a yazıp çağırana
 * olayın adını veriyor.
 */
func roleErr(err error, group string) error {
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return fmt.Errorf("no group %q — see `postern group list`", group)
}
