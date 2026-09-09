package sftpaudit

// Dosya seviyesinde SFTP denetimi.
//
// NEDEN VAR: `subsystem sftp` bu paket yazılana kadar reddediliyordu,
// çünkü transfer terminal kaydına ham ikili protokol olarak düşüyor ve
// "kim hangi dosyayı aldı" sorusu cevapsız kalıyordu. Burada akış
// SONLANDIRILMIYOR — postern araya bir SFTP sunucusu koymuyor; baytlar
// hedefe olduğu gibi gidiyor, kopyası çözümlenip dosya olaylarına
// dönüştürülüyor. Protokolü yeniden uygulamak, kendi hatalarımızı
// hedefle kullanıcının arasına koymak olurdu.
//
// ⚠️ OLAYLAR İSTEĞE DEĞİL CEVABA GÖRE YAZILIYOR. "sil" isteği bir olay
// değildir; hedefin sildiği bir olaydır. İsteği kaydeden bir denetim,
// izinsizlikten dönen bir silmeyi gerçekleşmiş gibi gösterirdi.

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Op, denetim olayının cinsi.
type Op string

const (
	OpOpen     Op = "open"
	OpTransfer Op = "transfer"
	OpRemove   Op = "remove"
	OpRename   Op = "rename"
	OpMkdir    Op = "mkdir"
	OpRmdir    Op = "rmdir"
	OpSetstat  Op = "setstat"
	OpSymlink  Op = "symlink"
	OpOpendir  Op = "opendir"
	OpLink     Op = "hardlink"
	OpExtended Op = "extended"
	// OpUnknown, TANIMADIĞIMIZ bir istek türü.
	OpUnknown Op = "unknown"

	// Aşağıdakiler yalnızca REDDEDİLDİKLERİNDE satır üretiyor: izin verilen
	// üstveri istekleri sessiz kalıyor. Kararın verildiği tek yer
	// onRequest'in switch'i — orada listelenmeyen tip bekleyenler
	// tablosuna girmiyor, dolayısıyla satır da üretmiyor.
	OpStat     Op = "stat"
	OpReaddir  Op = "readdir"
	OpRealpath Op = "realpath"
	OpReadlink Op = "readlink"
)

// Event, denetim kaydına düşen tek satır.
type Event struct {
	At   time.Time `json:"at"`
	Op   Op        `json:"op"`
	Path string    `json:"path"`
	// NewPath yalnızca rename ve symlink'te dolu.
	NewPath string `json:"new_path,omitempty"`
	// Flags yalnızca open/transfer'da dolu ("read", "write,creat,trunc").
	Flags string `json:"flags,omitempty"`

	// Read/Wrote, transfer olayında GERÇEKTEN taşınan bayt.
	Read  int64 `json:"read,omitempty"`
	Wrote int64 `json:"wrote,omitempty"`

	// OK, hedefin işlemi kabul edip etmediği.
	OK     bool   `json:"ok"`
	Status uint32 `json:"status,omitempty"`
	Detail string `json:"detail,omitempty"`

	/*
	 * Folded, bu satırın kaç AYRI reddi temsil ettiği — yalnızca
	 * katlanmış retlerin özet satırında dolu (flushDenyRunLocked).
	 *
	 * ⚠️ SAYIYI PROZDAN OKUMAK ZORUNDA KALMAMAK İÇİN VAR. Sayı zaten
	 * Detail'de bir cümlenin içinde duruyordu ("… (%d further identical
	 * refusals)") ve oradan okumanın tek yolu İngilizce ayrıştırmak.
	 * ÖLÇÜLDÜ: sayıyı olayları sayarak bulan bir tüketici, 32 KiB'lık
	 * parçalar hâlinde on bin kez reddedilen bir oturumu "2 ret" diye
	 * raporluyordu — yani en ısrarlı oturum en küçük sayıyı taşıyordu.
	 *
	 * ⚠️ ÖZET SATIRININ KENDİSİ BİR RET DEĞİL. Bir dizinin ilk reddi
	 * kendi satırını yazıyor; Folded yalnızca ONDAN SONRAKİLERİ sayıyor.
	 * İkisini toplayan tüketici doğru sayıyı buluyor (bkz. sftpJournal).
	 */
	Folded int `json:"folded,omitempty"`
}

/*
 * Sınırlar.
 *
 * ⚠️ NEDEN VAR: bekleyen istek ve açık tanıtıcı tabloları karşı taraftan
 * besleniyor. Cevabı hiç okumayan bir istemci, sınırsız bir tabloda
 * bellek tüketerek bastion'ı düşürebilirdi. Meşru istemciler çok altında
 * kalıyor (OpenSSH aynı anda ~64 istek tutuyor); sınırın aşılması bir
 * kullanım değil, saldırı işaretidir ve oturumu bitiriyor.
 */
const (
	/*
	 * maxPath, SAKLANAN yolun üst sınırı — işaret dahil.
	 *
	 * ⚠️ SAYI SINIRI BAYT SINIRI DEĞİL. maxPending 4096 istekle sınırlıyor
	 * ama her isteğin yolu gövde kadar (maxHeader, 64 KiB) uzun olabiliyordu:
	 * 4096 × 64 KiB ≈ 256 MiB, oturum başına. İstemci kanaldan OKUMAYI
	 * bırakırsa hedefin cevapları geri birikiyor, bekleyenler boşalmıyor ve
	 * bu sınıra gerçekten ulaşılıyor.
	 *
	 * ⚠️ SINIRI PATH_MAX DEĞİL, VERİTABANI KOYUYOR — VE ÖLÇÜLDÜ.
	 * Değer 4096'ydı ve gerekçesi "Linux'ta PATH_MAX"tı; defterin o yolu
	 * KABUL ETTİĞİ ise hiç ölçülmemişti. session_files.path btree
	 * indeksli (göç 027 ve 031) ve PostgreSQL bir btree girdisini
	 * reddediyor:
	 *
	 *   index row size 2712 exceeds btree version 4 maximum 2704
	 *   for index "session_files_path_idx"  (SQLSTATE 54000)
	 *
	 * Ölçüm (postgres:17-alpine, sıkışmayan yol): 2692 bayt geçiyor,
	 * 2693 reddediliyor. Sayı türetilebilir: girdi başlığı
	 * (IndexTupleData 8 + varlena 4 = 12 bayt) 2704'ten düşünce 2692
	 * kalıyor. Sıkışabilen bir yol daha uzunken de geçiyor — yani sınır
	 * VERİYE BAĞLI ve güvenli olan en kötü hâl.
	 *
	 * 2692 ile 4096 arasında kalan bir yol INSERT'i düşürüyordu; bir
	 * SFTP istemcisi iç içe dizin açarak o yolu üretebiliyor. Sonuç tek
	 * bir satırın kaybı değildi: grup tek transaction yazıldığı için
	 * oturumun BÜTÜN dosya olayları düşüyor, oturum ölüyor ve zehirli
	 * satır tampona geri konduğu için sonraki her deneme aynı yere
	 * çarpıyordu (bkz. proxy/sftpjournal.go).
	 *
	 * ⚠️ İNDEKSİ HASH'E / md5(path) İFADESİNE ÇEVİRMEK SEÇENEK DEĞİLDİ:
	 * 031'in tek gerekçesi `LIKE 'önek%'` ile ağaç araması ("/etc altında
	 * ne oldu") ve bir hash indeksi önek aralığını ifade edemez —
	 * soruşturmanın en sık sorduğu soruyu ölçülmüş bir hızdan tam
	 * taramaya düşürürdü. Kesilen yol ise önekini KORUYOR: üst dizin
	 * üzerinden arama çalışmaya devam ediyor.
	 */
	maxPath = 2692

	/*
	 * maxDetail, saklanan gerekçe metninin üst sınırı.
	 *
	 * ⚠️ METNİ HEDEF YAZIYOR, SINIRI HEDEF KOYAMAZ. Bu alan STATUS
	 * paketinin mesajı: açılamayan her dosya için hedefin gönderdiği
	 * cümle deftere olduğu gibi giriyordu (kolon TEXT, indekssiz —
	 * ölçtük: 100 KiB'lık bir detail sorunsuz yazılıyor). Binlerce
	 * başarısız açılış tek bir transaction'da onlarca kilobaytlık
	 * satırlar demek; denetim tablosunu şişirmek karşı tarafın eline
	 * bırakılacak bir şey değil.
	 *
	 * 512, kayda giren metnin sınırıyla aynı (proxy/sftpcast.go
	 * maxCastField). Aynı olayın kayıtta ve defterde ayrı ayrı
	 * kırpılması, iki yüzeyin aynı olayı farklı göstermesi demekti.
	 */
	maxDetail = 512

	/*
	 * maxHandleLen, tanıtıcının üst sınırı.
	 *
	 * ⚠️ KESMİYORUZ, REDDEDİYORUZ. Tanıtıcı bir tablo ANAHTARI; kesmek iki
	 * ayrı dosyayı aynı anahtara düşürebilir ve denetim baytları yanlış
	 * dosyaya yazardı. draft-ietf-secsh-filexfer-02 §6.7 tanıtıcının 256
	 * baytı aşmamasını şart koşuyor, yani bunu aşan bir tanıtıcı protokole
	 * aykırı — hedef değil, araya giren biri üretmiş olabilir.
	 */
	maxHandleLen = 256

	maxPending = 4096
	maxHandles = 1024
)

// pendingOp, cevabı beklenen bir istek.
type pendingOp struct {
	typ     byte
	path    string
	newPath string
	flags   uint32
	handle  string
	// n, WRITE'ta yazılmak istenen bayt sayısı.
	n uint32
	// ext, EXTENDED isteğinin adı ("posix-rename@openssh.com").
	ext string
}

// openFile, açık bir tanıtıcının durumu.
type openFile struct {
	path  string
	flags uint32
	read  int64
	wrote int64
	at    time.Time
}

/*
 * Session, tek bir SFTP kanalının iki yönünü izler.
 *
 * İki yön ayrı goroutine'lerden besleniyor (istemci→hedef ve hedef→
 * istemci kopyaları paralel akıyor), bu yüzden durum kilit altında.
 */
type Session struct {
	/*
	 * lastDeny*, ardışık aynı retlerin katlanması (policy.go
	 * refuseWith). Reddedilen bir aktarımın her parçası ayrı satır
	 * yazsaydı journalCap aşılır ve oturum ölürdü.
	 */
	lastDenyKey    string
	lastDenyCount  int
	lastDenyEvent  Event
	lastDenyReason string

	mu      sync.Mutex
	emit    func(Event)
	now     func() time.Time
	pending map[uint32]pendingOp
	handles map[string]*openFile
	/*
	 * dirHandles, OPENDIR ile açılan tanıtıcılar → AÇILDIKLARI YOL.
	 * Transfer özeti üretmiyorlar, ama yolları tutuluyor.
	 *
	 * ⚠️ ESKİDEN map[string]bool İDİ ve yol saklanmıyordu; "açılışta
	 * karara bağlandı, gerisi gerekmez" varsayımıyla. Ölçülen sonuç:
	 * READDIR politikaya BOŞ yolla gidiyor, hiçbir önek boş yolu
	 * kapsamıyor ve izin listesi kullanan bir kurulumda HER dizin
	 * listeleme reddediliyordu — `ls` çalışmıyordu. Ret satırı da yolsuz
	 * yazılıyordu, yani defterden hangi dizinin reddedildiği okunamıyordu.
	 */
	dirHandles map[string]string

	// policy, isteklere karar veren geri çağrı (policy.go). nil olabilir.
	policy Decider
	// readOnly, oturumun hedefte hiçbir şeyi değiştiremeyeceği.
	readOnly bool
	// denials, reddedilen isteklere üretilen ve istemciye gönderilmeyi
	// bekleyen cevaplar (paket + insan satırı).
	denials []Denial

	fromClient *framer
	fromTarget *framer

	// closed, Finish çağrıldıktan sonra true; ikinci kez özet yazmayı
	// engelliyor.
	closed bool
}

// NewSession, izleyiciyi kurar. emit her olay için çağrılıyor.
func NewSession(emit func(Event)) *Session {
	s := &Session{
		emit:       emit,
		now:        time.Now,
		pending:    make(map[uint32]pendingOp),
		handles:    make(map[string]*openFile),
		dirHandles: make(map[string]string),
	}
	s.fromClient = newFramer(s.onRequest)
	s.fromTarget = newFramer(s.onReply)
	return s
}

// FromClient, istemci→hedef akışından gelen baytları verir.
func (s *Session) FromClient(p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fromClient.write(p)
}

/*
 * FromClientTo, FromClient ile aynı işi yapıyor ve AYRICA iletimi
 * üstleniyor: hedefe gitmesi gereken aralıklar forward'a gidiyor,
 * reddedilen isteğin baytları hiç gitmiyor.
 *
 * ⚠️ ÇAĞIRAN DÖNÜŞTEN SONRA TakeDenials'I BOŞALTMALI. Reddedilen istek
 * hedefe gitmediği için hiçbir zaman cevaplanmayacak; istemciye postern'in
 * kendi cevabı gitmezse o istek kimliği sonsuza kadar açık kalır ve
 * istemci askıda bekler.
 *
 * ⚠️ DENETİMİN GÖRDÜĞÜ, HEDEFİN YAPABİLECEĞİNDEN ÖNCE. Bir paketin ilk
 * parçası hedefe gidebiliyor ama hedef paketi TAMAMLANMADAN işleyemiyor;
 * tamamlayan parça ise denetim olayı yazıldıktan sonra iletiliyor. Yani
 * "hedef bir isteği yaptıysa denetim onu görmüştür" değişmezi duruyor.
 */
func (s *Session) FromClientTo(p []byte, forward func([]byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.fromClient.writeTo(p, forward)
}

/*
 * TargetAtBoundary, hedef→istemci akışının paket SINIRINDA olup olmadığı.
 *
 * ⚠️ NEDEN SORULUYOR: postern bazen istemciye KENDİ cevabını yazıyor
 * (reddedilen istekler). O baytları gerçek bir paketin ORTASINA sokmak
 * istemcinin çözümleyicisini bozar — paket yanlış yerden ayrışır ve
 * sonraki her bayt kayar.
 *
 * ⚠️ İKİ KOŞUL. lenHave == 0, çözümleyicinin paketler ARASINDA olduğunu
 * söylüyor: önek tamamlanmışsa (4) gövdenin ortasındayız, kısmen gelmişse
 * (1..3) önekin ortasındayız. got/need karşılaştırması bu bilgiyi tekrar
 * etmekten ibaret.
 *
 * ⚠️ AMA "HİÇ BAŞLAMADIK" SINIR DEĞİL, ve bu ayrım ölçülebilir bir arızayı
 * önlüyor: istemci INIT ile reddedilecek bir isteği boru hattıyla birlikte
 * gönderirse, hedef daha VERSION'ı yollamadan cevabımızı yazardık.
 * İstemcinin gördüğü ilk paket SSH_FXP_STATUS olurdu; OpenSSH'in sftp_init'i
 * yalnızca VERSION kabul ediyor ve fatal ile çıkıyor.
 *
 * ⚠️ ÇAĞIRAN, İSTEMCİYE YAZMAYI SERİ HÂLE GETİREN KİLİDİ TUTMALI. Aksi
 * hâlde cevap, yazılmış ama HENÜZ ÇÖZÜMLENMEMİŞ bir parçanın ardından
 * gelir ve bu fonksiyon bayat bir cevap verir.
 */
func (s *Session) TargetAtBoundary() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.fromTarget.sawPacket && s.fromTarget.lenHave == 0
}

// FromTarget, hedef→istemci akışından gelen baytları verir.
func (s *Session) FromTarget(p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fromTarget.write(p)
}

/*
 * onRequest, istemciden gelen bir paketi işler.
 *
 * Burada olay YAZILMIYOR (bkz. dosya başı) — istek, cevabı gelene kadar
 * bekleyenler tablosunda duruyor.
 */
func (s *Session) onRequest(typ byte, r *reader) error {
	req, err := parseRequest(typ, r)
	if err != nil {
		return err
	}

	if !req.known {
		/*
		 * ⚠️ TANIMADIĞIMIZ TÜR SESSİZCE GEÇMİYOR — EKLENTİLERDEKİYLE AYNI
		 * GEREKÇE. Burası eskiden her bilinmeyen türü "salt okuma
		 * üstverisi" sayıyordu, yani ÖNCEDEN ONAYLIYORDU. Sürüm anlaşmasını
		 * izlemiyoruz (fxpInit'e bakılmıyor), dolayısıyla hedefin v6
		 * konuşmadığını iddia edemeyiz.
		 *
		 * Gövdeyi çözemiyoruz ama kimliği okuyabiliyoruz: hedefin cevabını
		 * bu satıra bağlamaya yetiyor — "bilinmeyen tür 22 BAŞARILI oldu".
		 */
		return s.addPending(req.id, pendingOp{typ: typ})
	}

	switch typ {
	case fxpInit:
		// Sürüm anlaşması: ilgilenmiyoruz, ama akışın başı burası.
		return nil

	case fxpOpen:
		return s.addPending(req.id, pendingOp{typ: typ, path: req.path, flags: req.flags})

	case fxpOpendir, fxpRemove, fxpRmdir, fxpMkdir, fxpSetstat:
		return s.addPending(req.id, pendingOp{typ: typ, path: req.path})

	case fxpRename, fxpSymlink, fxpLink:
		/*
		 * ⚠️ v6 LINK sert ve sembolik bağı AYIRMIYORUZ. Ayrım gövdenin
		 * sonundaki bayrakta ve denetimin sorduğu soru için önemsiz:
		 * ikisi de dosyaya İKİNCİ BİR AD veriyor, yani silinen bir
		 * dosyanın içeriği başka bir yerde yaşamaya devam edebiliyor.
		 */
		return s.addPending(req.id, pendingOp{typ: typ, path: req.path, newPath: req.newPath})

	case fxpRead, fxpClose:
		return s.addPending(req.id, pendingOp{typ: typ, handle: req.handle})

	case fxpWrite:
		return s.addPending(req.id, pendingOp{typ: typ, handle: req.handle, n: req.n})

	case fxpFsetstat:
		// Açık tanıtıcı üzerinde izin/zaman değişikliği. Tanıtıcıyı yola
		// çevirebiliyoruz; çeviremiyorsak yine de yazıyoruz ki "burada bir
		// değişiklik oldu" görünsün.
		path := req.handle
		if f, ok := s.handles[req.handle]; ok {
			path = f.path
		}
		return s.addPending(req.id, pendingOp{typ: typ, path: path})

	case fxpExtended:
		return s.pendExtended(req)
	}

	/*
	 * Tanıdığımız salt-okuma üstverisi (stat, lstat, fstat, readdir,
	 * realpath, readlink): dosya içeriğine ya da ad uzayına dokunmuyorlar
	 * ve denetim satırı üretmiyorlar. Yolları yine de ÇÖZÜLÜYOR
	 * (parseRequest), çünkü politika onları kapsıyor.
	 */
	return nil
}

/*
 * pendExtended, EXTENDED isteğini bekleyenler tablosuna koyar.
 *
 * ⚠️ ÖLÇÜLEN ARIZA: bu dal hiç yoktu ve yeniden adlandırmalar denetim
 * defterine HİÇ DÜŞMÜYORDU. OpenSSH'in kendi sftp istemcisi, sunucu
 * eklentiyi ilan ettiğinde SSH_FXP_RENAME değil "posix-rename@openssh.com"
 * gönderiyor — yani gerçek dünyadaki neredeyse her yeniden adlandırma.
 * Demoda ölçüldü: `rename a b` hedefte başarıyla çalıştı, session_files'ta
 * karşılığı yoktu.
 *
 * ⚠️ TANIMADIĞIMIZ EKLENTİ SESSİZCE GEÇMİYOR. Bilinen ve zararsız olanlar
 * (fsync, statvfs...) stat/readdir gibi satır üretmiyor; geri kalan HER ŞEY
 * adıyla birlikte yazılıyor. Aksi hâli bu arızanın kendisiydi: adını
 * bilmediğimiz bir eklenti dosyayı taşısın ve defter boş kalsın. Yarın
 * eklenen bir eklenti önceden onaylanmış olmamalı.
 */
func (s *Session) pendExtended(req request) error {
	switch req.ext {
	case extPosixRename, extHardlink, extLsetstat:
		return s.addPending(req.id, pendingOp{typ: fxpExtended, ext: req.ext,
			path: req.path, newPath: req.newPath})
	}

	if quietExtensions[req.ext] {
		return nil
	}

	return s.addPending(req.id, pendingOp{typ: fxpExtended, ext: req.ext})
}

// OpenSSH eklenti adları. Ayrıntı: PROTOCOL dosyası, openssh-portable.
const (
	extPosixRename = "posix-rename@openssh.com"
	extHardlink    = "hardlink@openssh.com"
	extLsetstat    = "lsetstat@openssh.com"
)

// quietExtensions, satır ÜRETMEYEN eklentiler: hiçbiri dosya içeriğini
// ya da ad uzayını değiştirmiyor. stat/readdir ile aynı muamele.
var quietExtensions = map[string]bool{
	"fsync@openssh.com":              true,
	"statvfs@openssh.com":            true,
	"fstatvfs@openssh.com":           true,
	"limits@openssh.com":             true,
	"expand-path@openssh.com":        true,
	"home-directory":                 true,
	"users-groups-by-id@openssh.com": true,
}

// extendedOps, EXTENDED isteğini olay adına çevirir.
var extendedOps = map[string]Op{
	extPosixRename: OpRename,
	extHardlink:    OpLink,
	extLsetstat:    OpSetstat,
}

// onReply, hedeften gelen bir paketi işler ve olayı YAZAR.
func (s *Session) onReply(typ byte, r *reader) error {
	switch typ {
	case fxpVersion:
		return nil

	case fxpHandle:
		id, err := r.uint32()
		if err != nil {
			return err
		}
		handle, err := r.str()
		if err != nil {
			return err
		}
		/*
		 * ⚠️ SINIR HEDEF TARAFINDA DA GEREKLİ. addPending istemcinin
		 * gönderdiği tanıtıcıyı süzüyor, ama tanıtıcı buraya HEDEFTEN
		 * geliyor ve tablo anahtarı olarak saklanıyor. Yalnızca istemci
		 * tarafını süzmek, ele geçirilmiş bir hedefin maxHandles × 64 KiB
		 * tutturmasına açık bırakırdı — ve bir bastion'ın sınırlaması
		 * gereken şey tam olarak hedefin ele geçirilmiş olması.
		 */
		if len(handle) > maxHandleLen {
			return fmt.Errorf("sftpaudit: target handle length %d exceeds limit %d", len(handle), maxHandleLen)
		}
		p, ok := s.takePending(id)
		if !ok {
			return nil
		}
		if p.typ == fxpOpendir {
			if len(s.dirHandles)+len(s.handles) >= maxHandles {
				return fmt.Errorf("sftpaudit: too many open handles (limit %d)", maxHandles)
			}
			s.dirHandles[handle] = p.path
			s.write(Event{Op: OpOpendir, Path: p.path, OK: true})
			return nil
		}
		/*
		 * ⚠️ TANIMADIĞIMIZ TÜR TANITICI DÖNDÜRDÜYSE onu DOSYA olarak
		 * kaydetmiyoruz. p.path boş olurdu ve sonraki READ/WRITE baytları
		 * boş yola atfedilirdi — yani defter, olmayan bir dosyaya yapılmış
		 * gerçek bir transfer gösterirdi. Yanlış satır, eksik satırdan kötü.
		 */
		if p.typ != fxpOpen && p.typ != fxpExtended {
			s.write(Event{Op: OpUnknown, OK: true,
				Detail: unknownDetail(p.typ, "returned a handle")})
			return nil
		}
		if len(s.handles)+len(s.dirHandles) >= maxHandles {
			return fmt.Errorf("sftpaudit: too many open handles (limit %d)", maxHandles)
		}
		s.handles[handle] = &openFile{path: p.path, flags: p.flags, at: s.now()}
		s.write(Event{Op: OpOpen, Path: p.path, Flags: flagsString(p.flags), OK: true})
		return nil

	case fxpData:
		id, err := r.uint32()
		if err != nil {
			return err
		}
		n, err := r.strLen()
		if err != nil {
			return err
		}
		p, ok := s.takePending(id)
		if !ok || p.typ != fxpRead {
			return nil
		}
		// ⚠️ İSTENEN değil GELEN bayt sayılıyor: hedef istenenden az
		// verebilir (dosya sonu). İstenen sayılsaydı denetim, hiç
		// okunmamış baytları okunmuş gösterirdi.
		if f, ok := s.handles[p.handle]; ok {
			f.read += int64(n)
		}
		return nil

	/*
	 * ⚠️ STATUS OLMAYAN CEVAPLAR DA BEKLEYENİ ALIYOR.
	 *
	 * ÖLÇÜLEN AÇIK: bu dal hiç yoktu. onReply yalnızca
	 * VERSION/HANDLE/DATA/STATUS tanıyor, gerisi sessizce düşüyordu.
	 * Tanımadığımız bir eklenti EXTENDED_REPLY ile cevaplandığında
	 * bekleyen HİÇ alınmıyordu: satır yazılmıyordu — onExtended'in
	 * "tanımadığımız eklenti adıyla birlikte yazılır" sözüne rağmen — ve
	 * kayıt maxPending'e kadar birikiyordu. 4097'nci istekte addPending
	 * hata veriyor, denetim çöküyor, oturum "sftp audit failed" ile
	 * bitiyor: sıradan bir sunucu davranışı postern'in arızası gibi
	 * görünüyordu.
	 *
	 * Bu üç cevap BAŞARI bildiriyor: hedef isteği yaptı ve sonucunu
	 * gönderdi. STATUS beklerken sonuç gelmesi reddedilme değil.
	 */
	case fxpName, fxpAttrs, fxpExtendedReply:
		id, err := r.uint32()
		if err != nil {
			return err
		}
		p, ok := s.takePending(id)
		if !ok {
			return nil
		}
		/*
		 * ⚠️ OPEN/OPENDIR buraya düşmemeli — cevapları HANDLE. Düşerse
		 * onStatus onları "başarısız" yazardı, çünkü o dal STATUS'un
		 * HANDLE YERİNE geldiği durum için yazılmış. Yanlış satır
		 * yazmaktansa yazmamayı seçiyoruz; bekleyen yine de alındı.
		 */
		if p.typ == fxpOpen || p.typ == fxpOpendir {
			return nil
		}
		s.onStatus(p, fxOK, "")
		return nil

	case fxpStatus:
		id, err := r.uint32()
		if err != nil {
			return err
		}
		code, err := r.uint32()
		if err != nil {
			return err
		}
		// Mesaj alanı sürüm 3'te var, bazı sunucular boş bırakıyor.
		msg, _ := r.str()
		p, ok := s.takePending(id)
		if !ok {
			return nil
		}
		s.onStatus(p, code, msg)
		return nil
	}
	return nil
}

// onStatus, bekleyen isteği cevabıyla eşleştirip olayı yazar.
func (s *Session) onStatus(p pendingOp, code uint32, msg string) {
	ok := code == fxOK

	switch p.typ {
	case fxpWrite:
		// ⚠️ Yalnızca KABUL EDİLEN yazma sayılıyor: diski dolu bir
		// hedefe gönderilen baytlar taşınmış sayılmaz.
		if ok {
			if f, has := s.handles[p.handle]; has {
				f.wrote += int64(p.n)
			}
		}
		return

	case fxpRead:
		// Okuma STATUS ile bitiyorsa veri gelmemiş (EOF ya da hata).
		return

	case fxpClose:
		s.closeHandle(p.handle)
		return

	case fxpOpen:
		// HANDLE yerine STATUS geldi: açılamadı. Reddedilen erişim de
		// denetim kaydına girer — denemeyi görmek, engelin çalıştığını
		// görmektir.
		s.write(Event{Op: OpOpen, Path: p.path, Flags: flagsString(p.flags),
			OK: false, Status: code, Detail: msg})
		return

	case fxpOpendir:
		s.write(Event{Op: OpOpendir, Path: p.path, OK: false, Status: code, Detail: msg})
		return

	case fxpExtended:
		op, known := extendedOps[p.ext]
		if !known {
			// Tanımadığımız eklenti: adı olayın kendisi.
			op = OpExtended
			if msg == "" {
				msg = p.ext
			} else {
				msg = p.ext + ": " + msg
			}
		}
		s.write(Event{Op: op, Path: p.path, NewPath: p.newPath,
			OK: ok, Status: code, Detail: msg})
		return
	}

	op, ok2 := statusOps[p.typ]
	if !ok2 {
		/*
		 * Buraya yalnızca TANIMADIĞIMIZ bir tür düşebiliyor: tanıdığımız
		 * her istek ya yukarıdaki switch'te ya statusOps'ta karşılanıyor.
		 * Türün numarası olayın kendisi — adını bilmediğimiz bir işlemin
		 * hedefte ÇALIŞTIĞINI yazmak, hiç yazmamaktan iyi.
		 */
		s.write(Event{Op: OpUnknown, OK: ok, Status: code,
			Detail: unknownDetail(p.typ, msg)})
		return
	}
	s.write(Event{Op: op, Path: p.path, NewPath: p.newPath,
		OK: ok, Status: code, Detail: msg})
}

// unknownDetail, bilinmeyen tür olayının detail alanını kurar.
func unknownDetail(typ byte, msg string) string {
	d := fmt.Sprintf("request type %d", typ)
	if msg != "" {
		d += ": " + msg
	}
	return d
}

// statusOps, cevabı STATUS olan istek tiplerini olay adına çevirir.
var statusOps = map[byte]Op{
	fxpRemove:   OpRemove,
	fxpRmdir:    OpRmdir,
	fxpMkdir:    OpMkdir,
	fxpRename:   OpRename,
	fxpSymlink:  OpSymlink,
	fxpLink:     OpLink,
	fxpSetstat:  OpSetstat,
	fxpFsetstat: OpSetstat,
}

// closeHandle, dosya özetini yazar ve tanıtıcıyı bırakır.
func (s *Session) closeHandle(handle string) {
	if _, isDir := s.dirHandles[handle]; isDir {
		delete(s.dirHandles, handle)
		return
	}
	f, ok := s.handles[handle]
	if !ok {
		return
	}
	delete(s.handles, handle)
	s.write(Event{Op: OpTransfer, Path: f.path, Flags: flagsString(f.flags),
		Read: f.read, Wrote: f.wrote, OK: true})
}

/*
 * Finish, kanal kapanırken YARIM KALAN transferleri yazar.
 *
 * ⚠️ NEDEN ŞART: bağlantı transfer ortasında koparsa CLOSE hiç gelmez.
 * Bu olmadan, yarıda kesilen 1 GB'lık bir indirme denetim kaydında HİÇ
 * görünmezdi — yani veriyi çekip bağlantıyı koparmak, izi silmenin yolu
 * olurdu.
 */
func (s *Session) Finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	// Katlanmış retlerin özeti oturum biterken yazılıyor; yoksa son
	// dizinin sayısı kaybolurdu.
	s.flushDenyRunLocked()
	for h, f := range s.handles {
		delete(s.handles, h)
		s.write(Event{Op: OpTransfer, Path: f.path, Flags: flagsString(f.flags),
			Read: f.read, Wrote: f.wrote, OK: false,
			Detail: "channel closed before the file was closed"})
	}

	/*
	 * ⚠️ BEKLEYENLER VE FRAMER TAMPONLARI DA BIRAKILIYOR.
	 *
	 * Broker kapanışta b.sftp'yi TEMİZLEMİYOR (bilinçli, bkz. broker.go) —
	 * yani Session, kanal bittikten sonra da erişilebilir kalıyor. Finish
	 * yalnızca handles'ı boşaltsaydı, yarım kalmış bir paketin başlığı ve
	 * cevapsız bekleyenler oturumla birlikte asılı kalırdı. Bunlar
	 * kapandıktan sonra hiçbir işe yaramıyor.
	 */
	clear(s.pending)
	s.denials = nil
	s.fromClient.head = nil
	s.fromClient.keep = 0
	s.fromTarget.head = nil
	s.fromTarget.keep = 0
}

/*
 * Kesme işaretleri.
 *
 * ⚠️ SESSİZ KESME YAPMIYORUZ. Defterde kısaltılmış bir yol gören operatör,
 * onu gerçek yol sanıp yanlış bir şey üzerinde işlem yapabilirdi. İki ayrı
 * işaret var çünkü iki ayrı şey oldu: biri metnin UZUN olduğunu, diğeri
 * içinde SAKLANAMAYAN bayt bulunduğunu söylüyor.
 *
 * Metin operatöre bakıyor: İngilizce.
 */
const (
	markTruncated = " (truncated)"
	markStripped  = " (invalid bytes removed)"
)

/*
 * ⚠️ DERLEME ZAMANI KONTROLÜ: sınır, işaretleri TAŞIYABİLMELİ.
 *
 * clampText kesme payını max'tan işaret uzunluklarını düşerek buluyor.
 * Sınır işaretlerden küçük olsaydı pay negatife düşer ve fonksiyon yalnızca
 * işaretlerden oluşan, kendi sınırını AŞAN bir metin döndürürdü — yani
 * arızayı gidermek için yazılan kod arızayı üretirdi. Sabitler bir gün
 * daraltılırsa burası derlenmiyor; sessizce yanlış davranmıyor.
 */
const _ = uint(maxDetail - len(markStripped) - len(markTruncated) - 1)

// clampPath, saklanacak yolu deftere SIĞACAK hâle getirir.
func clampPath(p string) string { return clampText(p, maxPath) }

// clampDetail, saklanacak gerekçe metni için aynısı.
func clampDetail(d string) string { return clampText(d, maxDetail) }

/*
 * clampText, metni saklanabilir kılar: saklanamayan baytları atar,
 * sınırın üstünü keser ve İKİSİNİ DE İŞARETLER.
 *
 * ⚠️ ÖNCE AYIKLA SONRA KES. Tersi sırada, atılan baytlar yüzünden kısalan
 * metin sınırın altına düşse bile "kesildi" damgası yemiş olurdu; ayrıca
 * kesme sınırı gerçek uzunluğa göre değil ham uzunluğa göre işlerdi.
 *
 * ⚠️ İŞARET BÜTÇEYE DAHİL: dönen metnin TOPLAM uzunluğu max'ı aşmıyor.
 * Aşsaydı fonksiyon kendi sınırını ihlal ederdi ve — daha kötüsü —
 * iki kez uygulandığında (addPending bir kez, write bir kez) ikinci
 * çağrı birincinin işaretini kesip üstüne yenisini koyardı.
 */
func clampText(s string, max int) string {
	out, stripped := stripUnstorable(s)

	mark := ""
	if stripped {
		mark = markStripped
	}
	if len(out)+len(mark) > max {
		out = truncValid(out, max-len(mark)-len(markTruncated))
		mark += markTruncated
	}
	return out + mark
}

/*
 * stripUnstorable, PostgreSQL'in TEXT olarak KABUL ETMEDİĞİ baytları atar.
 *
 * ⚠️ BU KIRPMA DEĞİL, ARIZA GİDERME — VE ÖLÇÜLDÜ. SFTP'de dosya adı
 * uzunluk önekli bir bayt dizisi; geçerli UTF-8 olma zorunluluğu YOK.
 * Latin-1 adlandırılmış bir dosya (gerçek sunucularda olağan) ya da adına
 * NUL sıkıştıran bir istemci, satırı yazılamaz kılıyordu:
 *
 *   ERROR: invalid byte sequence for encoding "UTF8": 0xe7 0xf6 0xfc
 *   ERROR: invalid byte sequence for encoding "UTF8": 0x00   (SQLSTATE 22021)
 *
 * Uzun yol senaryosunun aksine bunun için iç içe dizin açmak bile
 * gerekmiyordu: tek bir "rapor-çöü.txt" oturumun bütün dosya olaylarını
 * düşürüyordu.
 *
 * ⚠️ NUL, GEÇERLİ UTF-8'DİR (U+0000) — utf8.ValidString onu yakalamıyor,
 * PostgreSQL ise kabul etmiyor. Ayrı elenmesinin sebebi bu.
 *
 * ⚠️ ATIYORUZ, DEĞİŞTİRMİYORUZ (castSafe ile aynı karar): yerine bir
 * işaret koymak baytın ne olduğunu söylemez, yalnızca yolu uzatır.
 * Atıldığını söyleyen şey, çağıranın koyduğu işaret.
 */
func stripUnstorable(s string) (string, bool) {
	if utf8.ValidString(s) && !strings.Contains(s, "\x00") {
		// Olağan yol: tek bir tarama, kopya yok.
		return s, false
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n <= 1:
			// Geçerli UTF-8 olmayan bayt.
			i++
		case r == 0:
			i += n
		default:
			b.WriteString(s[i : i+n])
			i += n
		}
	}
	return b.String(), true
}

// truncValid, metni n bayta indirir ve sondaki YARIM rune'u atar.
//
// Yarım bırakılan bir rune geçersiz UTF-8'dir: kesme, giderdiğimiz
// arızayı kendi elimizle geri getirirdi.
func truncValid(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func (s *Session) addPending(id uint32, p pendingOp) error {
	if len(p.handle) > maxHandleLen {
		return fmt.Errorf("sftpaudit: handle length %d exceeds limit %d", len(p.handle), maxHandleLen)
	}
	p.path = clampPath(p.path)
	p.newPath = clampPath(p.newPath)

	if len(s.pending) >= maxPending {
		return fmt.Errorf("sftpaudit: too many outstanding requests (limit %d)", maxPending)
	}
	s.pending[id] = p
	return nil
}

func (s *Session) takePending(id uint32) (pendingOp, bool) {
	p, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	return p, ok
}

/*
 * write, olayı zamanlayıp dinleyiciye verir.
 *
 * ⚠️ KIRPMA BURADA, HER OLAY BURADAN GEÇTİĞİ İÇİN. Yol kırpması
 * addPending'de de var (bekleyen tablosunun bellek sınırı) ama olayların
 * hepsi oradan gelmiyor: politika retleri isteğin yolunu doğrudan yazıyor
 * ve gerekçe metni hiç uğramıyor. Kırpmayı olay ÜRETEN yerlere dağıtmak,
 * eklenecek her yeni olayın sessizce dışarıda kalması demekti — nitekim
 * Detail için tam olarak bu olmuştu.
 *
 * clampText iki kez uygulanmaya dayanıklı: addPending'den geçmiş bir yol
 * burada olduğu gibi kalıyor.
 */
func (s *Session) write(e Event) {
	e.At = s.now()
	e.Path = clampPath(e.Path)
	e.NewPath = clampPath(e.NewPath)
	e.Detail = clampDetail(e.Detail)
	s.emit(e)
}
