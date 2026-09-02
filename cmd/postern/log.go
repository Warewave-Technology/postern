package main

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/store"
)

/*
 * Denetim defterini okuma.
 *
 * ⚠️ NEDEN VAR: `admin_log`'a hem panel hem CLI yazıyordu ama CLI'dan
 * OKUNAMIYORDU. Yani panelin çalışmadığı gün yapılan değişikliklerin
 * izi, yine panelden okunuyordu — denetimin yazma yarısı vardı, okuma
 * yarısı yoktu.
 *
 * İki komut çıktısı da olmayan bir `postern log`'a yönlendiriyordu
 * ("`postern log` records when the name was released"). O metinler
 * panelin Admin log'unu gösterecek şekilde düzeltilmişti; şimdi komut
 * gerçekten var ve metinler buraya dönebilir.
 *
 * ⚠️ SIRALAMA EN YENİDEN ESKİYE. Bir olaydan sonra çalıştırılan komut,
 * en son ne olduğunu ilk satırda göstermeli.
 */
func newLogCmd() *cobra.Command {
	var configPath, actor, action, entity string
	var limit int

	cmd := &cobra.Command{
		Use:   "log",
		Short: "Read the administrative audit trail",
		Long: "Shows what was changed, by whom, and through which door.\n" +
			"Both the panel and this CLI write here; this is the only way to\n" +
			"read it from the host.",
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
			 * ⚠️ SÜZGEÇ VARSA DAHA GENİŞ OKUYORUZ.
			 *
			 * Süzme istemcide yapılıyor (store'da süzgeçli bir okuma
			 * yok). Limiti olduğu gibi kullansaydık, "--actor yigit
			 * --limit 20" son 20 SATIRDAN yigit'e ait olanları
			 * gösterirdi — yani çoğu zaman boş çıkardı ve kullanıcı
			 * "hiç yapmamış" diye okurdu. Yanlış cevabın en sinsi
			 * biçimi.
			 */
			read := limit
			if filtering(actor, action, entity) {
				read = limit * 50
				if read <= 0 || read > 5000 {
					read = 5000
				}
			}

			entries, err := db.AdminLog(ctx, read)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			matched := 0

			/*
			 * ⚠️ BAŞLIK, İLK SATIRLA BİRLİKTE YAZILIYOR.
			 *
			 * Önceden koşulsuz basılıyordu ve eşleşme yokken boşluğun
			 * üstünde tek başına duruyordu — bir tablo başlığı "burada
			 * veri var" demek. Denetim aracında bu, olmayan bir kaydı
			 * varmış gibi okutmanın en ucuz yolu.
			 */
			w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			for _, e := range entries {
				if !matches(e, actor, action, entity) {
					continue
				}
				if limit > 0 && matched >= limit {
					break
				}
				if matched == 0 {
					fmt.Fprintln(w, "WHEN\tACTOR\tVIA\tACTION\tENTITY\tDETAILS")
				}
				matched++
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					e.At.Local().Format("2006-01-02 15:04:05"),
					e.Actor, e.Via, e.Action, e.Entity, e.Details)
			}
			if err := w.Flush(); err != nil {
				return err
			}

			/*
			 * ⚠️ BOŞ SONUÇ SESSİZ GEÇMİYOR — ve süzgeçle boş çıkmak,
			 * defterin boş olmasından farklı bir cümle. İkisini aynı
			 * boşlukla göstermek, "hiç kayıt yok" ile "aradığın yok"u
			 * karıştırmak olurdu.
			 */
			if matched == 0 {
				if filtering(actor, action, entity) {
					fmt.Fprintf(out, "no entries matched (searched the newest %d)\n", read)
				} else {
					fmt.Fprintln(out, "the audit trail is empty")
				}
				return nil
			}

			/*
			 * ⚠️ KESİLDİYSE SÖYLE. Sessizce ilk N'i göstermek,
			 * operatörün "hepsi bu" sanması demek — bir denetim
			 * aracında en pahalı yanlış anlama.
			 */
			if limit > 0 && matched == limit && len(entries) >= read {
				fmt.Fprintf(out, "\n(showing %d; there are older entries — raise --limit)\n", limit)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().IntVar(&limit, "limit", 50, "en fazla kaç satır (0 = sınırsız)")
	cmd.Flags().StringVar(&actor, "actor", "", "yalnızca bu kişinin yaptıkları")
	cmd.Flags().StringVar(&action, "action", "", "eylem öneki, ör. user. ya da session.terminate")
	cmd.Flags().StringVar(&entity, "entity", "", "yalnızca bu varlık")
	return cmd
}

func filtering(actor, action, entity string) bool {
	return actor != "" || action != "" || entity != ""
}

/*
 * matches, satırın süzgeçlere uyup uymadığı.
 *
 * ⚠️ ACTION ÖNEK EŞLEŞMESİ: "--action user." bütün kullanıcı
 * işlemlerini getiriyor. Eylem adları noktayla bölümlenmiş
 * ("user.grant_role") ve operatörün aradığı çoğu zaman bir aile, tek
 * bir olay değil. Diğer alanlar tam eşleşme: yanlış kişiyi getirmemek,
 * fazla kişi getirmemekten önemli.
 */
func matches(e store.AdminLogEntry, actor, action, entity string) bool {
	if actor != "" && !strings.EqualFold(e.Actor, actor) {
		return false
	}
	if entity != "" && !strings.EqualFold(e.Entity, entity) {
		return false
	}
	if action != "" && !strings.HasPrefix(e.Action, action) {
		return false
	}
	return true
}
