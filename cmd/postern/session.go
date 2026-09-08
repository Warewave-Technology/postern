package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/objstore"
	"github.com/Warewave-Technology/postern/internal/record"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/verify"
)

// newSessionCmd, oturum denetim kaydı komutları.
func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Inspect the session audit trail",
	}
	cmd.AddCommand(newSessionListCmd())
	cmd.AddCommand(newSessionShowCmd())
	cmd.AddCommand(newSessionVerifyCmd())
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

			db, err := store.Open(ctx, cfg.Database.DSN)
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

			if err := printSessionTable(cmd, sessions); err != nil {
				return err
			}

			/*
			 * ⚠️ KESİLDİYSE SÖYLE. İki kardeşi de söylüyor: `postern
			 * log` "(showing N; there are older entries)" basıyor,
			 * panel de listenin sınıra dayandığını yazıyor. Bu komut
			 * yazmıyordu — tam --limit satır basıp susuyordu, ve
			 * susan bir denetim aracı "hepsi bu" diye okunuyor.
			 *
			 * ⚠️ "DAHA ESKİSİ VAR" DEMİYOR, "OLMAYABİLİR" DİYOR. Tam
			 * sınırda duran bir liste gerçekten sınıra dayanmış da
			 * olabilir, tesadüfen o kadar da. Var olmayan kaydı var
			 * diye bildirmek, olanı yok saymak kadar yanlış.
			 */
			if limit > 0 && len(sessions) == limit {
				fmt.Fprintf(cmd.OutOrStdout(),
					"\n(showing %d; there may be older sessions — raise --limit)\n",
					limit)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&user, "user", "", "only this user's sessions")
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum sessions to show (0 = no limit)")
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

			db, err := store.Open(ctx, cfg.Database.DSN)
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

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	return cmd
}

/*
 * newSessionVerifyCmd, bir kaydın yazıldığı gibi durup durmadığını
 * söyler.
 *
 * ⚠️ NE KANITLAR, NE KANITLAMAZ — ve komut bunu ÇIKTISINDA söylüyor,
 * yalnızca belgede değil. Zincir, dosyanın yazıldıktan sonra
 * değiştirilmediğini gösterir. Bastion'da root olan biri hem .cast'i
 * hem veritabanındaki başı yeniden yazabilir; o durumda ikisi yine
 * tutar. Zincirin taşıdığı değer, başın makinenin ULAŞAMADIĞI bir yere
 * de yazılmasıyla ortaya çıkıyor (arşiv kovası, dış uç). Bunu söylemeyen
 * bir "doğrulandı" satırı, olmadığı bir güvence veriyor demektir.
 *
 * ⚠️ ÜÇ AYRI SONUÇ, İKİ DEĞİL. "Geçti" ve "geçmedi" yetmiyor: başı
 * olmayan kayıtlar var (göç 034 öncesi kapananlar, çökme sonrası
 * süpürülenler) ve onlar DOĞRULANAMAZ — doğrulanmış değil. Üçünü ayırt
 * etmeyen bir çıktı, kanıtı olmayan bir kaydı kanıtlanmış gösterirdi.
 */
func newSessionVerifyCmd() *cobra.Command {
	var configPath string
	var requireArchive bool

	cmd := &cobra.Command{
		Use:   "verify <session-id>",
		Short: "Check that a recording is byte-for-byte what postern wrote",
		Args:  cobra.ExactArgs(1),
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

			s, err := db.Session(ctx, args[0])
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("session %q not found", args[0])
				}
				return err
			}

			out := cmd.OutOrStdout()

			/*
			 * ⚠️ DEFTER KONTROLÜ ZİNCİRDEN AYRI KOŞUYOR VE HER YOLDA
			 * BASILIYOR — iki ayrı eksen, panelin doğrulama cevabındaki
			 * ayrımın aynısı. Zincir "dosya değişmiş mi" sorusunu
			 * cevaplıyor; defter kontrolü "kaydın saydığı olayların
			 * satırları duruyor mu" sorusunu. Birini diğerinin başarısız
			 * olduğu dala gömmek, kaydı okunamayan bir oturumda
			 * defterden satır silindiğini görünmez yapardı.
			 */
			jr, jerr := journalOf(ctx, db, s)
			verr := verifyChainReport(ctx, cfg, db, out, s, requireArchive)
			printJournal(out, jr, jerr)

			switch {
			case verr != nil:
				// Kayıt bulgusu önce: dosyanın kendisi şüpheliyse
				// defterin durumu ikincil bir sorudur.
				return verr
			case jerr != nil:
				return fmt.Errorf("the journal of session %q could not be checked: %w", s.ID, jerr)
			case !jr.State.OK():
				return errJournalGap
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	/*
	 * ⚠️ BETİKTEN ÇAĞIRAN İÇİN. Varsayılan davranışta kutu dışı kopyaya
	 * ulaşılamaması komutu düşürmüyor — ulaşılamamak kurcalanmışlık
	 * değil. Ama bir olay müdahalesi betiği "kova onayladı" ile "kovaya
	 * bakamadım"ı ayırt etmek zorunda ve sessiz bir sıfır çıkış kodu o
	 * ayrımı kaybettirir.
	 */
	cmd.Flags().BoolVar(&requireArchive, "require-archive", false,
		"fail unless the archived copy confirms the chain")

	return cmd
}

/*
 * verifyChainReport, kaydın zincirini doğrular ve raporunu yazar.
 *
 * Komuttan ayrı bir fonksiyon çünkü artık iki eksen var: bu, kaydın
 * kendisini; çağıran ise ayrıca defteri raporluyor. İkisini tek gövdede
 * tutmak, erken dönen her zincir dalının defter satırını da yutması
 * demekti.
 */
func verifyChainReport(ctx context.Context, cfg *config.Config, db *store.Store,
	out io.Writer, s model.Session, requireArchive bool) error {
	if s.RecordingPath == "" {
		return fmt.Errorf("session %q has no recording", s.ID)
	}
	if s.RecordingChain == "" {
		// Çıkış kodu 0 DEĞİL: "doğrulayamadım" bir başarı değil.
		return fmt.Errorf(
			"session %q has no chain, so it cannot be verified — it "+
				"ended before chains existed, or postern crashed before "+
				"the chain was stored", s.ID)
	}

	rs, err := record.NewStore(cfg.Recording.Dir)
	if err != nil {
		return err
	}
	/*
	 * ⚠️ YEREL DOSYA YOKSA KUTU DIŞI KOPYA HÂLÂ CEVAP VEREBİLİR
	 * — ve tam da o durumda TEK cevap odur.
	 *
	 * ÖLÇÜLEN KUSUR: burası eskiden rs.Open'ın hatasını olduğu
	 * gibi döndürüyordu, yani budayıcı arşivlenmiş bir kaydı
	 * yerelden sildikten sonra `session verify` bir dosya
	 * hatasıyla düşüyor ve kovadaki başa HİÇ BAKMIYORDU.
	 * Arşivlemenin bütün amacı o kopyanın kalması; onu
	 * okumadan pes etmek, özelliğin kendisini boşa çıkarıyordu.
	 */
	f, openErr := rs.Open(s.ID, s.RecordingPath)
	if openErr != nil {
		if !errors.Is(openErr, fs.ErrNotExist) {
			// İzin hatası gibi başka bir arıza: gizlemiyoruz.
			return openErr
		}

		gone := checkOffBox(ctx, cfg, db, s.ID, s.RecordingChain)

		return reportNoLocalCopy(out, s.ID, s.RecordingChain, s.RecordingLinks, gone)
	}
	defer f.Close()

	ok, links, err := record.VerifyChain(f, s.RecordingChain)
	if err != nil {
		return err
	}

	/*
	 * ⚠️ KUTU DIŞI KOPYA HER İKİ SONUÇTA DA OKUNUYOR.
	 *
	 * Yerel doğrulama düşse bile kovadaki başı göstermek işe
	 * yarıyor: dosya değişmişse, kovadaki baş "olması gereken"i
	 * söylüyor. Yalnızca başarı yolunda bakmak, en çok
	 * ihtiyaç duyulan anda susmak olurdu.
	 */
	off := checkOffBox(ctx, cfg, db, s.ID, s.RecordingChain)

	if !ok {
		/*
		 * Halka sayısı burada asıl bilgi: "bozuk" demek yetmiyor,
		 * olay müdahalesinde soru kaydın NEREDE ayrıldığı.
		 */
		fmt.Fprintf(out, "FAILED  %s\n", s.ID)
		fmt.Fprintf(out, "  stored chain   %s over %d links\n",
			s.RecordingChain, s.RecordingLinks)
		fmt.Fprintf(out, "  file has       %d links and a different chain\n", links)
		if links < s.RecordingLinks {
			fmt.Fprintf(out, "  the file is short by %d lines\n",
				s.RecordingLinks-links)
		}
		printOffBox(out, off)

		return errRecordingChanged
	}

	/*
	 * ⚠️ YEREL DOĞRULAMA GEÇTİ AMA KOVA BAŞKA ŞEY SÖYLÜYORSA,
	 * BU EN GÜÇLÜ KURCALAMA İŞARETİ — ve komut BAŞARISIZ dönmeli.
	 *
	 * Dosya veritabanındaki başla tutuyor, ama kovadaki kopya
	 * başka bir baş taşıyor. İkisini birden üretebilmenin tek
	 * yolu bu makineyi elinde tutmak; kovadaki nesne ise
	 * saklama süresi boyunca oradan değiştirilemiyor. Yani bu,
	 * "dosya ve veritabanı birlikte yeniden yazıldı" demek.
	 */
	if off.State == offBoxMismatch {
		fmt.Fprintf(out, "FAILED  %s\n", s.ID)
		fmt.Fprintf(out, "  the file matches this host's database, but the\n")
		fmt.Fprintf(out, "  archived copy carries a different chain head.\n")
		printOffBox(out, off)
		fmt.Fprintf(out, "\n")
		fmt.Fprintf(out, "Both the recording and the stored chain on this host can be\n")
		fmt.Fprintf(out, "rewritten by whoever holds root here; the archived copy\n")
		fmt.Fprintf(out, "cannot, while its retention lasts. Treat the archived head\n")
		fmt.Fprintf(out, "as the one to trust, and this host as compromised.\n")

		return errArchiveDisagrees
	}

	if requireArchive && off.State != offBoxMatch {
		fmt.Fprintf(out, "FAILED  %s\n", s.ID)
		fmt.Fprintf(out, "  the local chain is intact, but the off-box copy could\n")
		fmt.Fprintf(out, "  not confirm it and --require-archive was given.\n")
		printOffBox(out, off)

		return errArchiveUnverified
	}

	fmt.Fprintf(out, "OK  %s\n", s.ID)
	fmt.Fprintf(out, "  %d links, chain %s\n", links, s.RecordingChain)
	printOffBox(out, off)
	fmt.Fprintf(out, "\n")

	if off.State == offBoxMatch {
		fmt.Fprintf(out, "The recording matches its chain, and the copy in the archive\n")
		fmt.Fprintf(out, "carries the same head. Rewriting the file and this host's\n")
		fmt.Fprintf(out, "database together would not have produced that agreement,\n")
		fmt.Fprintf(out, "as long as the bucket keeps versioning and Object Lock on —\n")
		fmt.Fprintf(out, "`postern archive check` reports whether it does.\n")
		fmt.Fprintf(out, "\n")
		fmt.Fprintf(out, "This check ran on the bastion. For a reading that does not\n")
		fmt.Fprintf(out, "trust this host at all, compare the same head from elsewhere;\n")
		fmt.Fprintf(out, "the bucket credential and the session id are all it takes.\n")

		return nil
	}

	fmt.Fprintf(out, "This proves the file was not changed after postern wrote it.\n")
	fmt.Fprintf(out, "It does not prove more than that: whoever holds root on this\n")
	fmt.Fprintf(out, "host could rewrite the file and this chain together. The chain\n")
	fmt.Fprintf(out, "is worth what its copy elsewhere is worth — and that copy was\n")
	fmt.Fprintf(out, "not consulted here (see above).\n")

	return nil
}

/*
 * journalOf, oturumun defterini kaydın mührüyle karşılaştırır.
 *
 * ⚠️ SATIRLARIN KENDİSİ ÇEKİLİYOR, YALNIZCA SAYISI DEĞİL — ve bu bir
 * genişletme. Sayı, silinmiş satırı gösteriyor; DEĞİŞTİRİLMİŞ satırı
 * göstermiyor. Mühürdeki özeti yeniden hesaplamanın tek yolu satırların
 * içeriğini okumak, ve bu komut zaten kaydın tamamını okuyor: bir
 * denetim komutunda, sorulmayan soru sorulanla aynı bedelde değil.
 */
func journalOf(ctx context.Context, db *store.Store, s model.Session) (verify.JournalResult, error) {
	rows, err := db.SessionFiles(ctx, s.ID)
	if err != nil {
		return verify.JournalResult{}, err
	}

	return verify.JournalOf(s, rows), nil
}

// journalLabel, defter durumunun tek kelimelik operatör karşılığı.
//
// ⚠️ "OK" DIŞINDAKİLERİN HİÇBİRİ ONAY DEĞİL, "NOT CHECKED" DAHİL.
// Ölçülmemiş bir oturumu "OK" yazmak, hiç yapılmamış bir kontrolü
// yapılmış saymak olurdu — zincirdeki "cannot be verified" ayrımının
// aynısı.
func journalLabel(st verify.JournalState) string {
	switch st {
	case verify.JournalIntact:
		return "OK"
	case verify.JournalIncomplete:
		return "INCOMPLETE"
	case verify.JournalMissing:
		return "ROWS MISSING"
	case verify.JournalAltered:
		return "ROWS ALTERED"
	case verify.JournalExtra:
		return "UNEXPECTED ROWS"
	default:
		return "NOT CHECKED"
	}
}

/*
 * printJournal, defter kontrolünün sonucunu yazar.
 *
 * ⚠️ HER DURUMDA YAZILIYOR, printOffBox'la aynı gerekçeyle: bakılmadığı
 * yazılmazsa okuyan kişi bakıldığını ve tuttuğunu varsayar. Bu kontrolün
 * kapattığı açık tam olarak böyle bir varsayımdı — ekran dosya listesini
 * eksiksizmiş gibi gösteriyordu ve onu yalanlayacak hiçbir satır yoktu.
 */
func printJournal(out io.Writer, r verify.JournalResult, err error) {
	fmt.Fprintf(out, "\n")

	if err != nil {
		// ⚠️ Sayamamak "defter tam" değil. Cümle hatayı taşıyor:
		// veritabanına ulaşamamakla satırların silinmiş olması ayrı
		// şeyler ve ikincisi buradan okunmamalı.
		fmt.Fprintf(out, "JOURNAL  NOT CHECKED\n")
		fmt.Fprintf(out, "  the journal rows could not be counted: %v\n", err)

		return
	}

	fmt.Fprintf(out, "JOURNAL  %s\n", journalLabel(r.State))
	if r.Summary != "" {
		fmt.Fprintf(out, "  %s\n", r.Summary)
	}
	fmt.Fprintf(out, "  %s\n", r.Detail)

	if r.State.OK() {
		return
	}

	/*
	 * ⚠️ İKİ EKSENİ BİRBİRİNE BAĞLAYAN CÜMLE ŞART. Yukarıdaki zincir
	 * raporu "OK" yazmış olabilir ve o satır ekranın EN ÜSTÜNDE duruyor;
	 * onu okuyup duran biri, dosyanın doğrulanmış olmasını defterin de
	 * tam olması sanır. İkisi ayrı iddia ve bu satır bunu söylüyor.
	 */
	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "A recording that verifies does not make the journal sound:\n")
	fmt.Fprintf(out, "the chain covers the file, not the rows in the database.\n")

	/*
	 * ⚠️ İKİ BULGU İKİ AYRI CÜMLE. "Eksik satır" ile "değişmiş satır"
	 * denetçiyi farklı yerlere gönderiyor: biri kayıtta olup defterde
	 * olmayanı aratıyor, öteki defterde duran satırın kayıttaki
	 * karşılığını. Tek bir kapanış cümlesi, ikincisini birincisi gibi
	 * okutur ve olmayan bir eksik aratırdı.
	 */
	if r.State == verify.JournalAltered {
		fmt.Fprintf(out, "The rows are all there; what they say is what changed.\n")
		fmt.Fprintf(out, "Play the recording back and compare it line by line —\n")
		fmt.Fprintf(out, "that copy is the one the chain covers.\n")

		return
	}

	fmt.Fprintf(out, "The events themselves are in the recording, one line each —\n")
	fmt.Fprintf(out, "play it back to read what the journal is missing.\n")
}

/*
 * errJournalGap, defter ile kaydın ayrıştığını çağırana sıfırdan farklı
 * bir çıkış koduyla bildiriyor.
 *
 * ⚠️ AYRI BİR HATA, errRecordingChanged DEĞİL. Dosya yerinde ve
 * değişmemiş olabilir; ayrışan şey defter. Aynı hataya bağlamak, bir
 * olay müdahalesi betiğine "kayıt kurcalanmış" dedirtirdi.
 */
var errJournalGap = errors.New(
	"the journal does not match the file events sealed in the recording")

/*
 * reportNoLocalCopy, yerelde olmayan bir kaydın sonucunu yazar.
 *
 * ⚠️ EN BÜYÜK RİSK BURADA YANLIŞ KELİMEYİ SEÇMEK. Kovadaki baş
 * veritabanındakiyle tutuyorsa söylenebilecek şey "veritabanı yeniden
 * yazılmamış"tır — "kayıt doğrulandı" DEĞİL. Baytlar burada değil, yani
 * dosyanın o başla tuttuğu hiç kontrol edilmedi. İkisini aynı cümleyle
 * söylemek, yapılmamış bir işi yapılmış göstermek olurdu.
 */
func reportNoLocalCopy(out io.Writer, id, chain string, links int64, off offBoxResult) error {
	fmt.Fprintf(out, "NO LOCAL COPY  %s\n", id)
	fmt.Fprintf(out, "  the recording is not on this host — it was archived and pruned\n")
	fmt.Fprintf(out, "  stored chain   %s over %d links\n", chain, links)
	printOffBox(out, off)
	fmt.Fprintf(out, "\n")

	switch off.State {
	case offBoxMatch:
		fmt.Fprintf(out, "The archived head agrees with this host's database, so the\n")
		fmt.Fprintf(out, "database was not rewritten. The bytes were not checked —\n")
		fmt.Fprintf(out, "they are not here. Fetch the object and run the same chain\n")
		fmt.Fprintf(out, "over it to finish the job.\n")

		return nil
	case offBoxMismatch:
		fmt.Fprintf(out, "The archived head does not match this host's database.\n")
		fmt.Fprintf(out, "Treat the archived head as the one to trust.\n")

		return errArchiveDisagrees
	default:
		return fmt.Errorf(
			"session %q has no local recording and the archived copy "+
				"could not confirm the chain", id)
	}
}

/*
 * printOffBox, kutu dışı kopyanın durumunu yazar.
 *
 * ⚠️ HER DURUMDA BİR SATIR YAZILIYOR, sessizlik yok. "Bakılmadı"
 * yazılmazsa okuyan kişi bakıldığını ve tuttuğunu varsayar — ve bu
 * varsayım tam olarak zincirin değerini abartan varsayım.
 */
func printOffBox(out io.Writer, r offBoxResult) {
	switch r.State {
	case offBoxMatch:
		fmt.Fprintf(out, "  off-box copy   CONFIRMS (%s)\n", r.Object)
	case offBoxMismatch:
		fmt.Fprintf(out, "  off-box copy   DISAGREES (%s)\n", r.Object)
		fmt.Fprintf(out, "    archived chain %s over %s links\n", r.Chain, r.Links)
	case offBoxNoChain:
		fmt.Fprintf(out, "  off-box copy   NO CHAIN — %s\n", r.Detail)
	default:
		fmt.Fprintf(out, "  off-box copy   NOT CHECKED — %s\n", r.Detail)
	}
}

// errRecordingChanged, doğrulamanın BAŞARISIZ olduğunu çağırana sıfırdan
// farklı bir çıkış koduyla bildiriyor: bu komut betikten çağrılacak ve
// "değişmiş" hâli 0 dönmemeli.
var errRecordingChanged = errors.New("recording does not match its chain")

/*
 * errArchiveDisagrees, yerel doğrulama geçtiği hâlde arşivdeki kopyanın
 * farklı bir baş taşıması. Ayrı bir hata, çünkü ayrı bir olay: dosyanın
 * bozulması değil, BU MAKİNENİN ele geçirilmiş olması.
 */
var errArchiveDisagrees = errors.New(
	"the archived copy carries a different chain head; treat this host as compromised")

// errArchiveUnverified, --require-archive verilmişken kutu dışı kopyanın
// onaylayamaması.
var errArchiveUnverified = errors.New(
	"the off-box copy did not confirm the chain")

/*
 * Kutu dışı doğrulamanın KARARLARI internal/verify'da.
 *
 * ⚠️ NİYE ORADA. Aynı soruyu panelin doğrulama ucu da soruyor ve iki ayrı
 * uygulama kaçınılmaz olarak ayrışırdı — ayrıştıkları gün ortaya çıkan
 * şey, aynı kayıt için farklı iki cevap veren bir denetim aracı olurdu.
 * Buradaki takma adlar yalnızca komutun okunurluğu için.
 */
type offBoxResult = verify.OffBox

const (
	offBoxMatch     = verify.OffBoxMatch
	offBoxMismatch  = verify.OffBoxMismatch
	offBoxNoChain   = verify.OffBoxNoChain
	offBoxUnchecked = verify.OffBoxUnchecked
)

/*
 * checkOffBox, arşiv istemcisini kurar ve kararı verify'a bırakır.
 *
 * Kimlik bilgisi çözümü BURADA kalıyor: CLI onu dosyadan/ortamdan/panel
 * ayarından çözüyor, httpapi'nin yolu farklı. Ortak pakete taşınacak olan
 * karar, kimlik değil.
 */
func checkOffBox(ctx context.Context, cfg *config.Config, db *store.Store,
	sessionID, wantChain string) offBoxResult {
	ac := cfg.Recording.Archive
	if !ac.Enabled() {
		return verify.OffBoxOf(ctx, nil, store.ArchiveState{}, false, wantChain)
	}

	st, found, err := db.ArchiveStateOf(ctx, sessionID)
	if err != nil {
		return offBoxResult{State: offBoxUnchecked,
			Detail: fmt.Sprintf("could not read the archive state: %v", err)}
	}
	if !found || !st.Archived {
		return verify.OffBoxOf(ctx, nil, st, false, wantChain)
	}

	creds, _, cerr := resolveArchiveCreds(ctx, cfg)
	if cerr != nil {
		return offBoxResult{State: offBoxUnchecked,
			Detail: fmt.Sprintf("no archive credential: %v", cerr)}
	}

	client, err := objstore.New(objstore.Config{
		Endpoint: ac.Endpoint, Region: ac.Region, Bucket: ac.Bucket,
		CAFile: ac.CAFile, Timeout: ac.Timeout,
		ServerSideEncryption: ac.ServerSideEncryption,
		Credentials:          creds,
	})
	if err != nil {
		return offBoxResult{State: offBoxUnchecked,
			Detail: fmt.Sprintf("could not build the archive client: %v", err)}
	}

	return verify.OffBoxOf(ctx, client, st, true, wantChain)
}
