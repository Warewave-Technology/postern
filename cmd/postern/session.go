package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/store"
)

// newSessionCmd, oturum denetim kaydı komutları.
func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Inspect the session audit trail",
	}
	cmd.AddCommand(newSessionListCmd())
	cmd.AddCommand(newSessionShowCmd())
	return cmd
}

// newSessionListCmd, kaydedilmiş oturumları listeler.
func newSessionListCmd() *cobra.Command {
	var configPath string
	var user string
	var limit int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List recorded sessions, newest first",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}

			ctx := context.Background()

			db, err := store.Open(ctx, cfg.Database.Path)
			if err != nil {
				return err
			}
			defer db.Close()

			sessions, err := db.Sessions(ctx, user, limit)
			if err != nil {
				return err
			}

			// "Hiç oturum yok" geçerli bir cevap; boş bir tablo başlığı
			// basmak ise cevaba benzemiyor.
			if len(sessions) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no sessions recorded")
				return nil
			}

			return printSessionTable(cmd, sessions)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&user, "user", "", "yalnızca bu kullanıcının oturumları")
	cmd.Flags().IntVar(&limit, "limit", 50, "en fazla kaç oturum (0 = sınırsız)")
	return cmd
}

// printSessionTable, oturumları hizalı bir tablo olarak basar.
//
// tabwriter'ın çalışma şekli: satırları biriktirir, sütunları \t ile
// ayırırsın; Flush çağrıldığında her sütunun EN GENİŞ hücresini bulur ve
// hepsini ona göre boşlukla doldurur. Yani hizalama yazarken değil,
// Flush'ta hesaplanır — Flush'ı unutursan HİÇBİR ŞEY basılmaz.
func printSessionTable(cmd *cobra.Command, sessions []model.Session) error {
	// Parametreler: minwidth=0, tabwidth=0 (tab'ları biz veriyoruz, dosyaya
	// yazmıyoruz), padding=2 (sütunlar arası en az 2 boşluk), padchar=' '.
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "SESSION ID\tUSER\tTARGET\tOS USER\tSRC IP\tSTARTED\tDURATION")

	for _, s := range sessions {
		// Süre yalnızca KAPANMIŞ oturum için hesaplanabilir. Open()
		// dururken EndedAt-StartedAt yapmak, sıfır time.Time yüzünden
		// eksi iki bin yıllık bir süre üretirdi.
		duration := "running"
		if !s.Open() {
			duration = s.EndedAt.Sub(s.StartedAt).Truncate(time.Second).String()
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			s.ID,
			s.User,
			s.Target,
			s.OSUser,
			s.SrcIP,
			// Saklanan UTC; GÖSTERİM yerel. time.Time zaten mutlak bir an
			// taşıdığı için Local() veriyi değiştirmez, yalnızca insan
			// için biçimler.
			s.StartedAt.Local().Format("2006-01-02 15:04:05"),
			duration,
		)
	}

	return w.Flush()
}

// newSessionShowCmd, tek bir oturumun tüm ayrıntısını gösterir ve kaydı
// izleme komutunu hazır basar.
func newSessionShowCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "show <session-id>",
		Short: "Show one session in detail",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}

			ctx := context.Background()

			db, err := store.Open(ctx, cfg.Database.Path)
			if err != nil {
				return err
			}
			defer db.Close()

			s, err := db.Session(ctx, args[0])
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("session %q not found", args[0])
				}
				return err
			}

			// Tek kayıt için tablo değil alan/değer satırları: list'in
			// yatay düzeni sekiz alanla okunmaz olurdu. tabwriter yine iş
			// başında — değer sütunu hizalı kalsın diye.
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)

			ended, duration := "-", "running"
			if !s.Open() {
				ended = s.EndedAt.Local().Format("2006-01-02 15:04:05")
				duration = s.EndedAt.Sub(s.StartedAt).Truncate(time.Second).String()
			}

			fmt.Fprintf(w, "SESSION ID:\t%s\n", s.ID)
			fmt.Fprintf(w, "USER:\t%s\n", s.User)
			fmt.Fprintf(w, "TARGET:\t%s\n", s.Target)
			fmt.Fprintf(w, "OS USER:\t%s\n", s.OSUser)
			fmt.Fprintf(w, "SRC IP:\t%s\n", s.SrcIP)
			fmt.Fprintf(w, "STARTED:\t%s\n", s.StartedAt.Local().Format("2006-01-02 15:04:05"))
			fmt.Fprintf(w, "ENDED:\t%s\n", ended)
			fmt.Fprintf(w, "DURATION:\t%s\n", duration)

			// Denetim satırı kayıt dosyasından uzun yaşar: dosya bugün
			// taşınmış ya da silinmiş olabilir. Bunu açıkça söylemek,
			// kullanıcıyı bozuk bir asciinema komutuyla baş başa
			// bırakmaktan iyidir.
			recordingOK := false
			switch _, statErr := os.Stat(s.RecordingPath); {
			case s.RecordingPath == "":
				fmt.Fprintf(w, "RECORDING:\t(none)\n")
			case statErr != nil:
				fmt.Fprintf(w, "RECORDING:\t%s (file missing!)\n", s.RecordingPath)
			default:
				recordingOK = true
				fmt.Fprintf(w, "RECORDING:\t%s\n", s.RecordingPath)
			}

			if err := w.Flush(); err != nil {
				return err
			}

			if recordingOK {
				fmt.Fprintf(cmd.OutOrStdout(), "\nplay with:  asciinema play %s\n", s.RecordingPath)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}
