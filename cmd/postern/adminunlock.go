package main

// Kod denemeleri yüzünden kilitlenmiş bir hesabı açmak.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * newAdminUnlockCmd, kilidi süresini beklemeden kaldırır.
 *
 * ⚠️ KİLİT ZATEN SÜRELİ. Bu komut kilidi mümkün kılmıyor, BEKLEMEYİ
 * kısaltıyor. Kalıcı bir kilit seçseydik bu komut tek kurtarma yolu
 * olurdu ve host'a erişimi olmayan bir kurulumda tek yönetici süresiz
 * dışarıda kalabilirdi.
 *
 * ⚠️ DOĞRULAYICIYI SIFIRLAMIYOR. `admin reset-totp` kaydı siler ve
 * kullanıcıyı yeniden kaydolmaya zorlar; bu komut yalnızca sayacı ve
 * kilidi temizler. İkisini birleştirmek, "çok yanlış kod girdim" ile
 * "telefonumu kaybettim"i aynı müdahaleye indirger ve ilkinde kullanıcıyı
 * gereksiz yere yeniden kaydolmaya zorlardı.
 */
func newAdminUnlockCmd() *cobra.Command {
	var configPath, user string

	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Clear the code-attempt lock on an account",
		Long: "Wrong authenticator codes lock an account for a while. This clears\n" +
			"that lock and the failure counter immediately.\n\n" +
			"It does not touch the authenticator itself: if the user has lost their\n" +
			"phone, `postern admin reset-totp` is the command, and it makes them\n" +
			"enrol again. Clearing the counter as well is deliberate — unlocking\n" +
			"without it would let the next wrong code lock the account instantly.",
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

			out := cmd.OutOrStdout()

			/*
			 * ⚠️ ÖNCE DURUMU OKUYORUZ. "Zaten kilitli değildi" ile
			 * "kilidi açtım" farklı cümleler; ikisini ayırmayan bir
			 * çıktı, yöneticiye yapmadığı bir şeyi yaptığını söylerdi.
			 */
			before, berr := db.TOTPLockState(ctx, user)
			if berr != nil {
				if errors.Is(berr, store.ErrNotFound) {
					return fmt.Errorf("account %q has no authenticator, so it cannot be locked", user)
				}
				return berr
			}

			if err := db.UnlockTOTP(ctx, user); err != nil {
				return err
			}
			if aerr := auditCLI(ctx, db, "admin.unlock", user,
				fmt.Sprintf("cleared %d failed code attempts", before.Failures)); aerr != nil {
				return aerr
			}

			switch {
			case before.Locked(time.Now()):
				fmt.Fprintf(out, "%q unlocked; it was locked until %s after %d failed codes\n",
					user, before.LockedUntil.Local().Format(time.RFC1123), before.Failures)
			case before.Failures > 0:
				fmt.Fprintf(out, "%q was not locked; cleared %d failed code attempts\n",
					user, before.Failures)
			default:
				fmt.Fprintf(out, "%q was not locked and had no failed attempts; nothing to clear\n", user)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&user, "user", "", "account to unlock (required)")
	_ = cmd.MarkFlagRequired("user")

	return cmd
}
