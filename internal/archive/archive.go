package archive

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/warewave/postern/internal/objstore"
	"github.com/warewave/postern/internal/store"
)

/*
 * Kayıtları nesne deposuna taşıyan işçi.
 *
 * ⚠️ AĞ, OTURUM YOLUNA HİÇ DOKUNMUYOR — ve bu, bu paketin var olma
 * biçimini belirleyen tek kural.
 *
 * Bugün "kayıt açılamazsa oturum reddedilir" kuralı YEREL bir dosya
 * açmaya bakıyor. Yüklemeyi o yola bağlasaydık, nesne deposunun bir
 * kesintisi bastion'ın kesintisine dönüşürdü: postern, bulut
 * sağlayıcısının çalışma süresine zincirlenirdi.
 *
 * Yapısal güvence şu: bu paket proxy.Deps'in ÜYESİ DEĞİL. proxy.Open
 * ona ulaşamıyor, dolayısıyla ondan zarar da göremiyor. Oturum
 * yolunun yükleme ile tek teması, kapanışta yazılan bir veritabanı
 * satırı — o da başarısız olsa oturumu etkilemiyor.
 *
 * ⚠️ İŞ SIRASI: yükle → deponun kendisine sor → damgala → budayıcıya
 * silme izni doğ. Damgayı yüklemeden önce atmak, gönderilmemiş bir
 * kaydı silinebilir yapardı; doğrulamadan atmak ise "gönderdim" ile
 * "orada" arasındaki farkı yok sayardı.
 */

// Config, arşivleyicinin çalışma parametreleri.
type Config struct {
	// RecordingsDir, .cast dosyalarının kökü.
	RecordingsDir string

	// Bucket ve Prefix, nesne anahtarını kuruyor. İkisi de CONFIG'ten
	// geliyor ve panelden değiştirilemiyor (bkz. settings.go).
	Bucket string
	Prefix string

	// Interval, iki tarama arası.
	Interval time.Duration

	// Batch, bir turda kaç kayıt üstlenilecek.
	Batch int

	// ClaimTimeout, üstlenilmiş ama bitmemiş bir işin serbest kalma
	// süresi. Öldürülen süreç temizlik yapamaz; bu süre onun yerine
	// geçiyor.
	ClaimTimeout time.Duration

	// RetryAfter, başarısız bir denemeden sonra en erken tekrar.
	RetryAfter time.Duration
}

func (c *Config) withDefaults() {
	if c.Interval <= 0 {
		c.Interval = time.Minute
	}
	if c.Batch <= 0 {
		c.Batch = 8
	}
	if c.ClaimTimeout <= 0 {
		c.ClaimTimeout = 15 * time.Minute
	}
	if c.RetryAfter <= 0 {
		c.RetryAfter = 2 * time.Minute
	}
}

// Archiver, bekleyen kayıtları nesne deposuna taşıyor.
type Archiver struct {
	db     *store.Store
	cfg    Config
	logger *slog.Logger

	/*
	 * ⚠️ KİMLİK HER TURDA ÇÖZÜLÜYOR, açılışta bir kez değil.
	 *
	 * Panelden girilen bir anahtarın yürürlüğe girmesi için postern'i
	 * yeniden başlatmak gerekseydi, ekran "kaydedildi" der ve hiçbir
	 * şey olmazdı — bu depodaki en tanıdık arıza. Çözücü her turda
	 * soruluyor; istemci yalnızca kimlik DEĞİŞTİĞİNDE yeniden
	 * kuruluyor.
	 */
	resolve func(context.Context) (objstore.Credentials, error)
	build   func(objstore.Credentials) (*objstore.Client, error)

	mu      sync.Mutex
	client  *objstore.Client
	forID   string
	noCreds bool
}

/*
 * New, arşivleyiciyi kurar.
 *
 * resolve nil ise ya da hedef yapılandırılmamışsa nil döner: arşivleme
 * kapalı ve budayıcının kapısı da kurulmuyor.
 *
 * ⚠️ KİMLİK OLMADAN DA KURULUYOR. Hedef config'de yazılıysa ama anahtar
 * henüz girilmemişse arşivleyici ÇALIŞIYOR, yükleme yapmıyor ve sebebini
 * söylüyor — böylece panelden anahtar girildiği anda iş başlıyor.
 */
func New(db *store.Store, cfg Config, resolve func(context.Context) (objstore.Credentials, error),
	build func(objstore.Credentials) (*objstore.Client, error), logger *slog.Logger) *Archiver {

	if resolve == nil || build == nil {
		return nil
	}
	cfg.withDefaults()
	return &Archiver{db: db, cfg: cfg, logger: logger, resolve: resolve, build: build}
}

/*
 * current, yürürlükteki istemciyi döner.
 *
 * Kimlik yoksa (nil, nil): çağıran turu atlıyor. Sebep BİR KEZ
 * loglanıyor — her turda tekrarlansaydı, gerçek arızalar bu gürültünün
 * içinde kaybolurdu.
 */
func (a *Archiver) current(ctx context.Context) (*objstore.Client, error) {
	creds, err := a.resolve(ctx)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		if !a.noCreds {
			a.noCreds = true
			a.logger.Warn("recording archive is configured but has no credential; " +
				"nothing is being uploaded and nothing can be pruned until one is set")
		}
		a.client = nil
		a.forID = ""
		return nil, nil
	}
	a.noCreds = false

	// ⚠️ Karşılaştırma yalnızca ERİŞİM KİMLİĞİ üzerinden: gizli anahtarı
	// bellekte kıyaslamak için tutmak gereksiz bir kopya olurdu ve
	// pratikte kimlik değişmeden sır değişmiyor.
	if a.client != nil && a.forID == creds.AccessKeyID {
		return a.client, nil
	}

	c, berr := a.build(creds)
	if berr != nil {
		return nil, berr
	}
	a.client = c
	a.forID = creds.AccessKeyID
	a.logger.Info("recording archive credential loaded", "access_key_id", creds.AccessKeyID)
	return c, nil
}

/*
 * ArchivedIDs, budayıcının sorduğu soruya cevap verir.
 *
 * record.Archived arayüzünü karşılıyor. Arşivleyici kapalıysa (nil)
 * budayıcıya hiç takılmıyor, yani kapı da yok.
 */
func (a *Archiver) ArchivedIDs(ctx context.Context, ids []string) (map[string]bool, error) {
	return a.db.ArchivedIDs(ctx, ids)
}

// Start, tarama döngüsünü çalıştırır. ctx bitene kadar dönmüyor.
func (a *Archiver) Start(ctx context.Context) {
	if a == nil {
		return
	}
	a.logger.Info("recording archive is on",
		"bucket", a.cfg.Bucket, "prefix", a.cfg.Prefix,
		"interval", a.cfg.Interval,
		"note", "recordings are uploaded after they are finished; "+
			"the session path never waits on the network")

	// Açılışta hemen bir tur: yeniden başlatmadan sonra bekleyen iş
	// varsa bir sonraki tick'i beklemesin.
	a.RunOnce(ctx)

	t := time.NewTicker(a.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.RunOnce(ctx)
		}
	}
}

/*
 * RunOnce, bir tur yükleme yapar.
 *
 * DIŞARI AÇIK, çünkü testin sunucu kurmadan çağırabilmesi gerekiyor:
 * "yeniden başlatmadan sonra bekleyen iş yükleniyor mu" sorusu ancak
 * böyle ölçülebilir.
 */
func (a *Archiver) RunOnce(ctx context.Context) {
	if a == nil {
		return
	}
	client, cerr := a.current(ctx)
	if cerr != nil {
		a.logger.Error("could not load the archive credential", "error", cerr)
		return
	}
	if client == nil {
		// Kimlik yok: iş üstlenmiyoruz. Satırlar bekliyor ve
		// budayıcı onlara dokunmuyor.
		return
	}

	now := time.Now()
	pending, err := a.db.ClaimArchives(ctx, a.cfg.Batch, now, a.cfg.ClaimTimeout, a.cfg.RetryAfter)
	if err != nil {
		a.logger.Error("could not claim recordings to archive", "error", err)
		return
	}
	for _, p := range pending {
		if ctx.Err() != nil {
			// ⚠️ KAPANIŞTA BEKLEMİYORUZ. Yarım kalan iş, claimed_at
			// zaman aşımıyla serbest kalıyor ve bir sonraki açılışta
			// yeniden alınıyor. Doğruluk temizlikten değil SIRADAN
			// geliyor: damga ancak doğrulamadan sonra atılıyor.
			return
		}
		a.archiveOne(ctx, client, p)
	}
	a.reportBacklog(ctx)
}

func (a *Archiver) archiveOne(ctx context.Context, client *objstore.Client, p store.ArchivePending) {
	log := a.logger.With("session_id", p.SessionID, "attempts", p.Attempts)

	path, err := a.safePath(p.RecordingPath)
	if err != nil {
		// Kalıcı: yolun kendisi kabul edilebilir değil — düzeltilecek
		// bir yapılandırma yok, kayıt bu satırla hiç eşleşmiyor.
		a.fail(ctx, p.SessionID, log, err, false, true)
		return
	}

	f, err := os.Open(path) // #nosec G304 -- safePath kökün altını doğruladı
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			/*
			 * ⚠️ DOSYA YOK: KALICI, ve bu sessizce geçilecek bir şey
			 * değil. Özellik açılmadan önce budanmış kayıtlar bu dala
			 * düşüyor. "Kayıp" ile "bekliyor" ayrı durumlar; ikisini
			 * birleştirmek, kuyruğun hiç bitmeyen bir kuyruğa
			 * dönüşmesi ve gerçek arızayı gizlemesi demekti.
			 */
			a.fail(ctx, p.SessionID, log,
				fmt.Errorf("recording file is gone: %s", path), false, true)
			return
		}
		a.fail(ctx, p.SessionID, log, err, true, false)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		a.fail(ctx, p.SessionID, log, err, true, false)
		return
	}

	key := a.keyFor(p, path)

	sum, err := client.Put(ctx, key, f, info.Size())
	if err != nil {
		// ⚠️ gone=false: 403/404 gibi yapılandırma hataları kuyruktan
		// ÇIKMIYOR — operatör düzeltince kuyruk boşalmalı.
		a.fail(ctx, p.SessionID, log, err, errors.Is(err, objstore.ErrTransient), false)
		return
	}

	/*
	 * ⚠️ PUT'UN 200 DÖNMESİ YETMİYOR. Damgayı atmak, budayıcıya silme
	 * izni vermek demek; bunu yapmadan önce nesnenin orada olduğunu
	 * DEPONUN KENDİSİNDEN duyuyoruz. Kendi istemcimizin "başarılı"
	 * demesiyle deponun "duruyor" demesi aynı şey değil.
	 */
	size, err := client.Head(ctx, key)
	if err != nil {
		a.fail(ctx, p.SessionID, log, fmt.Errorf("verify: %w", err),
			errors.Is(err, objstore.ErrTransient), false)
		return
	}
	if size >= 0 && size != info.Size() {
		a.fail(ctx, p.SessionID, log,
			fmt.Errorf("verify: stored %d bytes, sent %d", size, info.Size()), true, false)
		return
	}

	if err := a.db.MarkArchived(ctx, p.SessionID, client.Bucket(), key,
		sum, info.Size(), time.Now()); err != nil {
		// Yüklendi ama damgalanamadı: bir sonraki turda yeniden
		// yüklenecek. Aynı anahtara aynı içeriği yazmak zararsız.
		log.Error("recording uploaded but could not be marked", "error", err)
		return
	}
	log.Info("recording archived", "object_key", key, "bytes", info.Size())
}

/*
 * fail, denemeyi kaydeder ve sebebini söyler.
 *
 * ⚠️ İKİ AYRI KAVRAM, VE BİR SÜRE BİRLEŞTİRİLMİŞLERDİ.
 *
 * transient: log satırı Warn mı Error mı olacak — "yeniden denenecek"
 * ile "bir şeyi düzeltmen gerekiyor" farkı.
 *
 * gone: kayıt HİÇBİR koşulda yüklenemez (dosya yok, yol kabul edilemez).
 * Yalnızca bu satırı kuyruktan çıkarıyor.
 *
 * İkisini "permanent = !transient" diye birleştirmek ÖLÇÜLEBİLİR bir
 * regresyondu: objstore 4xx'i ErrPermanent sayıyor (403 yanlış kimlik,
 * 404 yanlış kova adı) ve kendi yorumu "operatörün müdahalesi gerekir"
 * diyor — yani operatör düzeltecek. O satırları kuyruktan çıkarmak,
 * kimlik düzeltildikten sonra kuyruğun BİR DAHA HİÇ boşalmaması
 * demekti; CHANGELOG'un "hiçbir şey kalıcı ölü işaretlenmiyor, kovayı
 * düzeltmek kuyruğu boşaltıyor" sözünün tam tersi.
 */
func (a *Archiver) fail(ctx context.Context, id string, log *slog.Logger, cause error, transient, gone bool) {
	// ⚠️ Hata metni ASLA Authorization taşımıyor: objstore yalnızca
	// durum kodunu ve S3'ün XML gövdesini döndürüyor (bkz. classify).
	if transient {
		log.Warn("recording archive failed, will retry", "error", cause)
	} else {
		log.Error("recording archive failed and will not succeed without a change",
			"error", cause)
	}
	// gone ise satır kuyruktan çıkıyor (bkz. store.MarkArchiveFailed).
	// Yapılandırma/yetki hataları çıkmıyor: onlar düzeltilebilir ve
	// düzeltildiğinde kuyruk kendiliğinden boşalmalı.
	if err := a.db.MarkArchiveFailed(context.WithoutCancel(ctx), id, cause.Error(), gone, time.Now()); err != nil {
		log.Error("could not record the archive failure", "error", err)
	}
}

/*
 * keyFor, nesne anahtarını kurar.
 *
 * ⚠️ ANAHTAR KİMLİK BİLGİSİ TAŞIMIYOR: kullanıcı adı, hedef adı ya da
 * os_user yok. Kovayı listeleyebilen biri bunlardan bir erişim haritası
 * çıkarabilirdi. Tarih öneki duruyor — nesne sayıları zaten aktivite
 * hacmini veriyor ve önek, saklama kurallarını tarihe göre yazmayı
 * mümkün kılıyor.
 */
func (a *Archiver) keyFor(p store.ArchivePending, path string) string {
	day := filepath.Base(filepath.Dir(path))
	name := filepath.Base(path)
	key := day + "/" + name
	if a.cfg.Prefix != "" {
		key = trimSlashes(a.cfg.Prefix) + "/" + key
	}
	return key
}

func trimSlashes(s string) string {
	for len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

/*
 * safePath, veritabanından gelen yolu kayıt kökünün altında doğrular.
 *
 * ⚠️ recording_path BİR VERİTABANI SÜTUNU. record.Store.Open aynı
 * gerekçeyle aynı kontrolü yapıyor: veritabanına yazabilen her yol,
 * aksi hâlde keyfi bir dosyayı nesne deposuna YÜKLEMEYE dönüşürdü —
 * bariz hedef ca.key_file. Okuma tarafında korunan şeyin yazma
 * tarafında korunmaması, kapıyı arkadan açmak olurdu.
 */
func (a *Archiver) safePath(stored string) (string, error) {
	if stored == "" {
		return "", errors.New("session has no recording path")
	}
	root, err := filepath.Abs(a.cfg.RecordingsDir)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(stored)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return "", fmt.Errorf("recording path is outside the recordings root: %s", stored)
	}
	return abs, nil
}

/*
 * reportBacklog, bekleyen işin BÜYÜKLÜĞÜNÜ ve YAŞINI loglar.
 *
 * ⚠️ YAŞ, SAYIDAN DAHA ÖNEMLİ. Ölmüş bir yükleyicinin belirtisi
 * "sayı artıyor" değil — sabit bir sayı da hiçbir şeyin ilerlemediği
 * anlamına gelebilir. En eskisinin yaşlanması, sıkışmayı disk
 * dolmadan günler önce gösteren tek işaret.
 */
func (a *Archiver) reportBacklog(ctx context.Context) {
	b, err := a.db.ArchiveBacklog(ctx)
	if err != nil {
		return
	}
	// ⚠️ KAYIP OLANLARI TEK BAŞINA DA SÖYLE. Bekleyen iş yokken bile
	// dosyası kaybolmuş kayıtlar varsa, o sessiz durum görünmeli:
	// erken dönüş yalnızca ikisi de sıfırken.
	if b.Pending == 0 {
		if b.Lost > 0 {
			a.logger.Warn("recordings can never be archived (file missing); "+
				"they are not waiting and not on disk to prune", "lost", b.Lost)
		}
		return
	}
	age := time.Since(b.Oldest).Round(time.Minute)
	fields := []any{"pending", b.Pending, "oldest_age", age}

	/*
	 * ⚠️ ÜST ÜSTE BAŞARISIZ OLANLAR AYRI SÖYLENİYOR. "Bekleyen 40" ile
	 * "bekleyen 40, hepsi üst üste başarısız" farklı iki durum:
	 * birincisi yükleyicinin geride kalması, ikincisi hiç
	 * ilerlemediği. Sınıflandırma zaten yapılıyordu ama yalnızca log
	 * cümlesini seçiyordu; sayısı hiçbir yerde görünmüyordu.
	 */
	if b.Failing > 0 {
		fields = append(fields, "failing", b.Failing)
	}
	// ⚠️ KAYIP olanlar AYRI: dosyası olmayan kayıtlar "bekliyor"
	// sayılmıyor (yoksa alarm sonsuza kadar yanardı), ama görülmeleri
	// gerekiyor — onlar için yapılacak bir şey yok, olan bir şey var.
	if b.Lost > 0 {
		fields = append(fields, "lost", b.Lost)
	}

	// Bir günü aşan bekleme, disk baskısına dönüşmeden önce
	// görülmesi gereken bir arıza.
	if age > 24*time.Hour {
		a.logger.Error("recordings have been waiting to archive for over a day; "+
			"they cannot be pruned while they wait, so the disk will fill", fields...)
		return
	}
	a.logger.Info("recordings waiting to archive", fields...)
}
