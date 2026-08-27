package record

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Store owns the on-disk layout of recordings.
type Store struct {
	dir string
	re  *regexp.Regexp
}

// NewStore prepares the recordings root.
func NewStore(dir string) (*Store, error) {
	err := os.MkdirAll(dir, 0o700)
	if err != nil {
		return nil, fmt.Errorf("record.store.NewStore: %w", err)
	}

	fileNamePattern := `^[a-zA-Z0-9_-]+$`
	re := regexp.MustCompile(fileNamePattern)

	return &Store{dir: dir, re: re}, nil
}

// Create opens a new .cast file for sessionID and returns it with its path.
func (s *Store) Create(sessionID string) (*os.File, string, error) {
	if !s.re.MatchString(sessionID) {
		return nil, "", fmt.Errorf("record.store.Create: invalid session id")
	}

	path := filepath.Join(s.dir, time.Now().Format("2006-01-02"))
	fullPath := filepath.Join(path, fmt.Sprintf("%s.cast", sessionID))
	err := os.MkdirAll(path, 0o700)
	if err != nil {
		return nil, "", fmt.Errorf("record.store.Create: %w", err)
	}

	// #nosec G304 -- sessionID yukarıda ^[a-zA-Z0-9_-]+$ ile doğrulandı: traversal yok
	f, err := os.OpenFile(fullPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("record.store.Create: %w", err)
	}

	return f, fullPath, nil
}

// NewSessionID returns a random, filesystem-safe session identifier.
func NewSessionID() (string, error) {
	sessionID := make([]byte, 16)
	_, err := rand.Read(sessionID)
	if err != nil {
		return "", fmt.Errorf("record.store.NewSessionID: %w", err)
	}

	return hex.EncodeToString(sessionID), nil
}

// Kayıt okuma yolundaki hatalar.
var (
	// ErrNotRecorded: oturumun kaydı hiç olmamış (recording_path boş).
	ErrNotRecorded = errors.New("record: session has no recording")

	// ErrOutsideRoot: saklanan yol kayıt kökünün DIŞINDA.
	//
	// Bu bir "bulunamadı" değil, bir REDDETME: kökün dışını gösteren bir
	// yol ya recording.dir değişmiş demektir ya da veritabanına oraya ait
	// olmayan bir değer girmiş demektir. İkisi de sessizce dosya
	// açılacak durumlar değil.
	ErrOutsideRoot = errors.New("record: stored path is outside the recordings root")
)

// Open, bir oturumun kayıt dosyasını okumak için açar.
//
// ⚠️ NEDEN storedPath'i DOĞRUDAN os.Open'a VERMİYORUZ: sessions.
// recording_path bir VERİTABANI SÜTUNU. Bir veritabanı değerini dosya
// yolu olarak kullanmak, veritabanına yazabilen her yolu (başka bir
// yerdeki enjeksiyon, operatörün elle UPDATE'i, geri yüklenen bir dump,
// ileride eklenecek bir içe aktarma özelliği) yetkili bir admin oturumu
// üzerinden KEYFİ DOSYA OKUMAYA çevirir. Bariz hedef ca.key_file.
//
// Bu yüzden iki bağımsız kontrol var: sessionID kimlik doğrulaması
// (Create ile aynı desen) ve yolun kayıt kökünün altında kaldığının
// ispatı. İkisi de geçmeden dosya açılmıyor.
func (s *Store) Open(sessionID, storedPath string) (*os.File, error) {
	if !s.re.MatchString(sessionID) {
		return nil, fmt.Errorf("record.store.Open: invalid session id")
	}
	if storedPath == "" {
		return nil, fmt.Errorf("record.store.Open: %w", ErrNotRecorded)
	}

	// İki tarafı da mutlaklaştır VE sembolik bağları çöz.
	//
	// Mutlaklaştırma şart çünkü NewStore kökü OLDUĞU GİBİ saklıyor ve
	// göreli bir kök yapılandırılabiliyor; filepath.Rel biri mutlak biri
	// göreli olduğunda hata verir.
	//
	// Bağ çözümü de şart ve sebebi operasyonel: kayıt dizini bir
	// sembolik bağın arkasındaysa (macOS'ta /var → /private/var, ya da
	// bağlanmış bir birim) metinsel karşılaştırma HER kaydı kök dışı
	// sayardı — yani panelde hiçbir kayıt açılmazdı. Aynı çözüm ayrıca
	// kökün içine konmuş, dışarıyı gösteren bir bağı da yakalıyor.
	root, err := resolve(s.dir)
	if err != nil {
		return nil, fmt.Errorf("record.store.Open: %w", err)
	}
	target, err := resolve(storedPath)
	if err != nil {
		return nil, fmt.Errorf("record.store.Open: %w", err)
	}

	rel, err := filepath.Rel(root, target)
	if err != nil {
		return nil, fmt.Errorf("record.store.Open: %w", ErrOutsideRoot)
	}
	// ".." ile başlayan, mutlak olan ya da kökün kendisi olan bir göreli
	// yol kökün altında DEĞİLDİR.
	if rel == "." || rel == ".." ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(rel) {
		return nil, fmt.Errorf("record.store.Open: %w", ErrOutsideRoot)
	}

	f, err := os.Open(target) // #nosec G304 -- yol yukarıda kayıt kökünün altında olduğu ispatlandı
	if err != nil {
		return nil, fmt.Errorf("record.store.Open: %w", err)
	}
	return f, nil
}

// Root, kayıt kökünü döner (teşhis ve log için).
func (s *Store) Root() string { return s.dir }

// resolve, yolu mutlaklaştırır ve sembolik bağları çözer.
//
// Dosya henüz yoksa (kaydı silinmiş bir oturum) EvalSymlinks hata verir;
// o durumda DİZİNİ çözüp dosya adını geri ekliyoruz. Böylece "dosya yok"
// ile "kök dışı" ayrı kalıyor: ikisini karıştırmak, silinmiş bir kaydı
// güvenlik reddi gibi göstermek olurdu.
func resolve(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}

	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real, nil
	}

	dir, file := filepath.Split(abs)
	realDir, err := filepath.EvalSymlinks(filepath.Clean(dir))
	if err != nil {
		// Dizin de yoksa çözecek bir şey kalmadı; sözlüksel hâliyle
		// devam ediyoruz. Kapsama kontrolü yine çalışır, yalnız bağ
		// çözümünden faydalanamaz.
		return abs, nil
	}
	return filepath.Join(realDir, file), nil
}
