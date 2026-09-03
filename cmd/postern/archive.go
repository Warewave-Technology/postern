package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/internal/archive"
	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/objstore"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * Arşiv hedefinin durumunu operatöre raporlayan komut.
 *
 * ⚠️ BU BİR GÜVENLİK KONTROLÜ DEĞİL, YANLIŞ YAPILANDIRMA DEDEKTÖRÜ —
 * ve rapor bunu kendi ağzıyla söylüyor.
 *
 * Sorgular bastion'da, yani saldırganın ele geçireceği makinede
 * çalışıyor ve onun kimliğini kullanıyor. "Sürümleme açık" cevabı,
 * saldırgan altında da aynı şekilde dönerdi. Faydası operatörün
 * kurulumu doğru yaptığını görmesi.
 *
 * ⚠️ SERVE YOLUNDA DEĞİL. Açılışta çalıştırılsaydı, kova
 * yapılandırmasını okuyamayan bir kurulum başlayamaz ya da her
 * açılışta ağ beklerdi. Operatör istediğinde çalıştırıyor.
 *
 * ⚠️ ÜÇ SÜTUN, ve üçüncüsü en önemlisi. "Öğrenemedim" ile "böyle bir
 * şey yok" ayrı; "postern asla öğrenemez" ise operatörün başka bir
 * yerde bakması gereken şeylerin listesi. Doğrulayamadığımız bir
 * korumayı doğrulanmış gibi göstermek, bu raporu zararlı yapardı.
 */
func newArchiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "archive",
		Short: "Inspect the recording archive",
	}
	cmd.AddCommand(newArchiveCheckCmd())
	return cmd
}

// finding, raporun tek satırı.
type finding struct {
	label  string
	value  string
	note   string
	weak   bool // yapılandırma zayıf: uyarı
	unsure bool // öğrenilemedi
}

func newArchiveCheckCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Report what the archive bucket says about itself",
		Long: "Reads the bucket's own configuration and reports it in three\n" +
			"parts: what it reported, what could not be determined, and what\n" +
			"postern can never determine. It is a misconfiguration detector,\n" +
			"not a security control — it runs on the bastion, with the\n" +
			"bastion's credential.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			ac := cfg.Recording.Archive
			out := cmd.OutOrStdout()

			if !ac.Enabled() {
				// ⚠️ Kapalı olmak bir hata değil: sessiz kalmak yerine
				// söylüyoruz, ama çıkış kodu sıfır.
				fmt.Fprintln(out, "recording archive is not configured "+
					"(recording.archive.endpoint is empty)")
				return nil
			}

			ctx := context.Background()
			creds, source, cerr := resolveArchiveCreds(ctx, cfg)
			if cerr != nil {
				return cerr
			}
			if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
				return fmt.Errorf("no archive credential: set one in the panel, "+
					"or in %s, or POSTERN_ARCHIVE_SECRET_KEY", ac.SecretKeyFile)
			}

			client, err := objstore.New(objstore.Config{
				Endpoint: ac.Endpoint, Region: ac.Region, Bucket: ac.Bucket,
				CAFile: ac.CAFile, Timeout: ac.Timeout,
				ServerSideEncryption: ac.ServerSideEncryption,
				Credentials:          creds,
			})
			if err != nil {
				return err
			}

			fmt.Fprintf(out, "archive: %s/%s", ac.Endpoint, ac.Bucket)
			if ac.Prefix != "" {
				fmt.Fprintf(out, " under %s", ac.Prefix)
			}
			fmt.Fprintf(out, "\ncredential: %s (%s)\n\n", creds.AccessKeyID, source)

			reported, unknown, reachErr := probeBucket(ctx, client)
			if reachErr != nil {
				/*
				 * ⚠️ ULAŞAMAMAK KESİN BİR ARIZA: sıfır olmayan çıkış.
				 * Sertleştirme eksikleri uyarı, ama "şu an yükleme
				 * yapılamıyor" bir hata ve komut bunu ayırmalı.
				 */
				fmt.Fprintf(out, "CANNOT REACH THE BUCKET: %v\n", reachErr)
				return fmt.Errorf("archive check failed: the bucket is not usable right now")
			}

			printSection(out, "What the bucket reported", reported)
			printSection(out, "Could not be determined", unknown)
			printNeverKnowable(out)

			// Zayıf yapılandırma uyarı, hata değil: operatörün bilerek
			// yaptığı bir tercih olabilir.
			var weak int
			for _, f := range reported {
				if f.weak {
					weak++
				}
			}
			if weak > 0 {
				fmt.Fprintf(out, "\n%d thing(s) above weaken the archive. "+
					"None of them stop uploading; they decide what survives "+
					"someone who owns this bastion.\n", weak)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}

// resolveArchiveCreds, yürürlükteki kimliği ve kaynağını bulur.
func resolveArchiveCreds(ctx context.Context, cfg *config.Config) (objstore.Credentials, archive.CredentialSource, error) {
	ac := cfg.Recording.Archive

	hostSecret := ""
	if ac.SecretKeyFile != "" || os.Getenv("POSTERN_ARCHIVE_SECRET_KEY") != "" {
		v, err := ac.SecretAccessKey()
		if err != nil {
			return objstore.Credentials{}, archive.FromNowhere, err
		}
		hostSecret = v
	}

	db, err := store.Open(ctx, cfg.Database.DSN)
	if err != nil {
		return objstore.Credentials{}, archive.FromNowhere, err
	}
	defer db.Close()

	return archive.Credentials(ctx, db, ac.AccessKeyID, hostSecret)
}

/*
 * probeBucket, kovanın söylediklerini toplar.
 *
 * ⚠️ "OKUYAMADIM" İLE "AYARLI DEĞİL" AYRI KOVALARA GİDİYOR. S3, hiç
 * yapılandırılmamış bir alt kaynağa 404 + kendi kodunu döndürüyor;
 * yetkisizlikte ise AccessDenied. İkisini birleştirmek, yetkisi
 * olmayan bir kimlikle çalışan kurulumu "her şey kapalı" diye
 * göstermek olurdu — yanlış ve yanlış yönde.
 */
func probeBucket(ctx context.Context, c *objstore.Client) (reported, unknown []finding, reachErr error) {
	// Sürümleme. 200 + boş belge = hiç açılmamış.
	v, err := c.Versioning(ctx)
	switch {
	case err == nil && v == "Enabled":
		reported = append(reported, finding{"versioning", "Enabled",
			"a PUT to an existing key adds a version instead of replacing it", false, false})
	case err == nil:
		val := v
		if val == "" {
			val = "never enabled"
		}
		reported = append(reported, finding{"versioning", val,
			"⚠ a PUT to an existing key OVERWRITES it — PutObject alone is not append-only", true, false})
	case isUnreachable(err):
		// ⚠️ ULAŞILAMAMA ÖNCE: olmayan bir kova, "yapılandırılmamış"
		// dalına düşerse rapor yeşil çıkar ve yükleme hiç çalışmaz.
		return nil, nil, err
	case isNotConfigured(err):
		reported = append(reported, finding{"versioning", "not configured",
			"⚠ a PUT to an existing key overwrites it", true, false})
	default:
		unknown = append(unknown, finding{"versioning", reason(err),
			"the credential may lack s3:GetBucketVersioning", false, true})
	}

	// Object Lock.
	lock, err := c.ObjectLockConfig(ctx)
	switch {
	case err == nil && lock.Enabled && lock.Mode == "COMPLIANCE" && (lock.Days > 0 || lock.Years > 0):
		reported = append(reported, finding{"object lock",
			fmt.Sprintf("COMPLIANCE, default retention %s", retentionOf(lock)),
			"objects cannot be deleted or shortened by anyone, including this bastion", false, false})
	case err == nil && lock.Enabled && lock.Mode == "GOVERNANCE":
		reported = append(reported, finding{"object lock",
			fmt.Sprintf("GOVERNANCE, default retention %s", retentionOf(lock)),
			"⚠ an identity with s3:BypassGovernanceRetention can still delete", true, false})
	case err == nil && lock.Enabled:
		reported = append(reported, finding{"object lock", "enabled, NO default retention",
			"⚠ the lock protects nothing: retention would have to come from each " +
				"request, and postern deliberately does not send it — a credential " +
				"holder could set it to zero", true, false})
	case isUnreachable(err):
		return nil, nil, err
	case err == nil || isNotConfigured(err):
		reported = append(reported, finding{"object lock", "not enabled",
			"⚠ nothing stops a credential holder from overwriting or deleting objects", true, false})
	default:
		unknown = append(unknown, finding{"object lock", reason(err),
			"the credential may lack s3:GetBucketObjectLockConfiguration", false, true})
	}

	// Varsayılan şifreleme.
	enc, err := c.Encryption(ctx)
	switch {
	case err == nil && enc != "":
		reported = append(reported, finding{"default encryption", enc,
			"applies to objects postern writes without asking for it", false, false})
	case isUnreachable(err):
		return nil, nil, err
	case err == nil || isNotConfigured(err):
		reported = append(reported, finding{"default encryption", "not configured",
			"objects are stored unencrypted unless the store does it invisibly", false, false})
	default:
		unknown = append(unknown, finding{"default encryption", reason(err),
			"the credential may lack s3:GetEncryptionConfiguration", false, true})
	}

	return reported, unknown, nil
}

func retentionOf(l objstore.ObjectLock) string {
	switch {
	case l.Years > 0:
		return fmt.Sprintf("%d year(s)", l.Years)
	case l.Days > 0:
		return fmt.Sprintf("%d day(s)", l.Days)
	default:
		return "none"
	}
}

/*
 * isNotConfigured, "böyle bir yapılandırma yok" cevaplarını tanır.
 *
 * ⚠️ KOVA SEVİYESİ KODLAR BURAYA GİRMİYOR — ve bunu bir ölçüm
 * yakaladı: ilk hâli "NoSuch" alt dizesine bakıyordu, dolayısıyla
 * OLMAYAN BİR KOVA ("NoSuchBucket") "sürümleme yapılandırılmamış" diye
 * raporlanıyordu. Rapor yeşil çıkıyor, yükleme ise hiç çalışmıyordu.
 *
 * Ayrım şu: alt kaynağın yokluğu bir OLGU, kovanın yokluğu bir ARIZA.
 */
func isNotConfigured(err error) bool {
	code, ok := objstore.CodeOf(err)
	if !ok {
		return false
	}
	switch code {
	case "NoSuchBucket", "NoSuchKey":
		return false
	}
	return strings.Contains(code, "NotFound") || strings.Contains(code, "NoSuch")
}

// isUnreachable, kovanın kendisine ulaşılamadığını söyler: bu, komutun
// sıfır olmayan çıkışla bitmesi gereken tek durum.
func isUnreachable(err error) bool {
	if errors.Is(err, objstore.ErrTransient) {
		return true
	}
	code, ok := objstore.CodeOf(err)
	if !ok {
		return false
	}
	switch code {
	case "NoSuchBucket", "InvalidAccessKeyId", "SignatureDoesNotMatch",
		"RequestTimeTooSkewed", "AccountProblem":
		return true
	}
	return false
}

func reason(err error) string {
	if code, ok := objstore.CodeOf(err); ok {
		return code
	}
	return err.Error()
}

func printSection(w io.Writer, title string, fs []finding) {
	fmt.Fprintf(w, "%s\n", title)
	if len(fs) == 0 {
		// ⚠️ BOŞ BÖLÜM SESSİZ GEÇMİYOR: "hiçbir şey öğrenilemedi" ile
		// "bölüm hiç yazılmadı" farklı şeyler.
		fmt.Fprintln(w, "  (nothing)")
		fmt.Fprintln(w)
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, f := range fs {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", f.label, f.value, f.note)
	}
	tw.Flush()
	fmt.Fprintln(w)
}

/*
 * printNeverKnowable, postern'in ASLA doğrulayamayacaklarını sayar.
 *
 * ⚠️ BU BÖLÜM RAPORUN EN ÖNEMLİ YARISI. Yukarıdaki iki bölüm neyi
 * bildiğimizi söylüyor; burası, "kontrol ettim, güvendeyim" diye
 * okunmasını engelliyor. Doğrulayamadığımız bir korumayı sessizce
 * atlamak, raporu güvenlik tiyatrosuna çevirirdi.
 */
func printNeverKnowable(w io.Writer) {
	fmt.Fprintln(w, "What postern can never determine")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	rows := [][2]string{
		{"delete permission",
			"testing it would need a delete capability this build deliberately does not have; " +
				"with COMPLIANCE lock it does not matter, without one it is your IAM policy to check"},
		{"who else can write",
			"other identities with access to this bucket are invisible from here"},
		{"whether this stays true",
			"a policy change tomorrow is not something a check today can see"},
		{"whether retention is enough",
			"only you know the obligation the retention period has to meet"},
		{"this bastion's own honesty",
			"every answer above came from a credential on this machine; " +
				"an attacker who owns it gets the same answers"},
	}
	for _, r := range rows {
		fmt.Fprintf(tw, "  %s\t%s\n", r[0], r[1])
	}
	tw.Flush()
}
