package main

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * Dizin bağını koparma — kurtarma yolu.
 *
 * ⚠️ NEDEN VAR, ÖLÇÜLDÜ. Dizinde silinip aynı adla yeniden açılan kişi
 * YENİ bir kararlı kimlik alıyor. postern'deki satırı hâlâ eskisine
 * bağlı olduğu için:
 *
 *   - web girişi 403 veriyor ("bu bastion'da hesabın yok"), çünkü
 *     BindDirIdentity dolu bir bağın üzerine yazmayı reddediyor;
 *   - SSH tarafı kimliği eskisiyle arıyor, bulamıyor ve oturumu
 *     "dizinde yok" diye reddediyor;
 *   - DeleteUser oturum kaydı olan hesabı reddediyor;
 *   - `user modify` yalnızca e-posta ve os_user kabul ediyor.
 *
 * Yani kişi kendi hesabından kilitleniyordu ve geriye tek çıkış
 * PurgeAccount kalıyordu — ki o, kimlik bilgisini, anahtarlarını ve
 * rollerini siliyor. store.UnbindDirIdentity bunu çözmek için yazılmıştı,
 * testi vardı ve HİÇBİR YERDEN çağrılmıyordu; yorumu bile "bunu çözecek
 * bir komut olmazsa tek çıkış veritabanına elle girmek olurdu" diyordu.
 * Tam olarak orası.
 *
 * ⚠️ NEDEN PANELDE DEĞİL, HOST'TA. Bağı koparmak, hesabı bir sonraki
 * girişte BAŞKA bir dizin kimliğine açık hâle getiriyor. Ele geçirilmiş
 * bir panel oturumunun elinde bu, hesap devralmanın ilk adımı olurdu —
 * panelden `is_admin` vermeme ve arşiv hedefini panelden değiştirmeme
 * kararlarıyla aynı raf. Break-glass yolu gibi host'ta duruyor.
 */
func newUserUnbindDirectoryCmd() *cobra.Command {
	var configPath, name string
	var assumeYes bool

	cmd := &cobra.Command{
		Use:   "unbind-directory",
		Short: "Detach an account from the directory identity it is bound to",
		Long: "Use this when someone was deleted and re-created in the directory,\n" +
			"so their stable identity changed and they can no longer sign in.\n" +
			"The next successful directory sign-in binds the account to the new\n" +
			"identity. Roles, keys and history are untouched.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, ctx, err := openStore(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			out := cmd.OutOrStdout()

			/*
			 * ⚠️ ÖNCE OKU, SONRA YAZ. Bağı olmayan bir hesapta komut
			 * "başardım" deyip hiçbir şey yapmasa, operatör asıl
			 * sorunu başka yerde aramaya devam ederdi.
			 */
			subject, err := db.DirSubjectOf(ctx, name)
			if err != nil {
				return err
			}
			if subject == "" {
				fmt.Fprintf(out, "%q is not bound to a directory identity; "+
					"nothing to detach\n", name)
				fmt.Fprintln(out, "if they still cannot sign in, the cause is "+
					"elsewhere — check `postern user list` and the directory itself")
				return nil
			}

			fmt.Fprintf(out, "%q is bound to directory identity %s\n", name, subject)
			fmt.Fprintln(out, "detaching means the NEXT directory sign-in claims this "+
				"account, whoever it comes from.")
			fmt.Fprintln(out, "do that only if you know the directory really did "+
				"re-create this person.")

			if !assumeYes && !confirmUnbind(cmd, name) {
				fmt.Fprintln(out, "left untouched")
				return nil
			}

			if err := db.UnbindDirIdentity(ctx, name); err != nil {
				return err
			}

			// ⚠️ İZ ŞART: bu, bir hesabı başka bir kimliğe açan tek
			// komut. Kim, ne zaman, hangi kimlikten kopardı.
			if lerr := db.LogAdmin(ctx, store.AdminLogEntry{
				Actor: cliActor(), Via: "cli",
				Action: "user.unbind_directory", Entity: name,
				Details: "detached from directory identity " + subject +
					"; the next directory sign-in will bind this account again",
			}); lerr != nil {
				return lerr
			}

			fmt.Fprintf(out, "\n%q is detached. Their next directory sign-in binds "+
				"the account to the identity it comes from.\n", name)
			fmt.Fprintln(out, "roles, keys and session history were not touched")
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&name, "name", "", "account name (required)")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "onay sorma")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

/*
 * confirmUnbind, hesabın ADINI yazdırarak onay ister.
 *
 * ⚠️ "y" YETMİYOR. Bu komut yanlış hesapta çalıştırıldığında sessizce
 * zarar veriyor: yanlış kişinin bağı kopar ve bir sonraki dizin girişi
 * onun hesabını devralır. Adı yazdırmak, refleksle onaylamayı
 * imkânsızlaştırıyor — `ActionButton`'ın paneldeki onay metniyle aynı
 * gerekçe.
 */
func confirmUnbind(cmd *cobra.Command, name string) bool {
	fmt.Fprintf(cmd.OutOrStdout(), "\ntype the account name to confirm: ")
	r := bufio.NewReader(cmd.InOrStdin())
	line, err := r.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return false
	}
	return strings.TrimSpace(line) == name
}
