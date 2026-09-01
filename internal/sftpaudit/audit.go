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
	"sync"
	"time"
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
	mu      sync.Mutex
	emit    func(Event)
	now     func() time.Time
	pending map[uint32]pendingOp
	handles map[string]*openFile
	// dirHandles, OPENDIR ile açılanlar — transfer özeti üretmiyorlar.
	dirHandles map[string]bool

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
		dirHandles: make(map[string]bool),
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
	switch typ {
	case fxpInit:
		// Sürüm anlaşması: ilgilenmiyoruz, ama akışın başı burası.
		return nil

	case fxpOpen:
		id, err := r.uint32()
		if err != nil {
			return err
		}
		path, err := r.str()
		if err != nil {
			return err
		}
		flags, err := r.uint32()
		if err != nil {
			return err
		}
		return s.addPending(id, pendingOp{typ: typ, path: path, flags: flags})

	case fxpOpendir:
		id, path, err := idAndPath(r)
		if err != nil {
			return err
		}
		return s.addPending(id, pendingOp{typ: typ, path: path})

	case fxpRemove, fxpRmdir, fxpMkdir, fxpSetstat:
		id, path, err := idAndPath(r)
		if err != nil {
			return err
		}
		return s.addPending(id, pendingOp{typ: typ, path: path})

	case fxpRename, fxpSymlink:
		id, path, err := idAndPath(r)
		if err != nil {
			return err
		}
		newPath, err := r.str()
		if err != nil {
			return err
		}
		return s.addPending(id, pendingOp{typ: typ, path: path, newPath: newPath})

	case fxpRead:
		id, handle, err := idAndPath(r)
		if err != nil {
			return err
		}
		return s.addPending(id, pendingOp{typ: typ, handle: handle})

	case fxpWrite:
		id, handle, err := idAndPath(r)
		if err != nil {
			return err
		}
		if _, err := r.uint64(); err != nil { // offset
			return err
		}
		n, err := r.strLen()
		if err != nil {
			return err
		}
		return s.addPending(id, pendingOp{typ: typ, handle: handle, n: n})

	case fxpClose:
		id, handle, err := idAndPath(r)
		if err != nil {
			return err
		}
		return s.addPending(id, pendingOp{typ: typ, handle: handle})

	case fxpExtended:
		return s.onExtended(r)

	case fxpFsetstat:
		// Açık tanıtıcı üzerinde izin/zaman değişikliği. Tanıtıcıyı
		// yola çevirebiliyoruz; çeviremiyorsak yine de yazıyoruz ki
		// "burada bir değişiklik oldu" görünsün.
		id, handle, err := idAndPath(r)
		if err != nil {
			return err
		}
		path := handle
		if f, ok := s.handles[handle]; ok {
			path = f.path
		}
		return s.addPending(id, pendingOp{typ: typ, path: path})
	}

	// Kalanlar (stat, lstat, readdir, realpath, readlink...) salt okuma
	// üstverisi; dosya içeriğine dokunmuyorlar ve denetim satırı
	// üretmiyorlar. Yine de akış çözümlenmeye devam ediyor.
	return nil
}

/*
 * onExtended, SSH_FXP_EXTENDED (200) isteklerini çözer.
 *
 * ⚠️ ÖLÇÜLEN ARIZA: BU DAL HİÇ YOKTU ve yeniden adlandırmalar denetim
 * defterine HİÇ DÜŞMÜYORDU. OpenSSH'in kendi sftp istemcisi, sunucu
 * eklentiyi ilan ettiğinde SSH_FXP_RENAME değil
 * "posix-rename@openssh.com" gönderiyor — yani gerçek dünyadaki
 * neredeyse her yeniden adlandırma. Demoda ölçüldü: `rename a b`
 * hedefte başarıyla çalıştı, session_files'ta karşılığı yoktu.
 *
 * ⚠️ TANIMADIĞIMIZ EKLENTİ SESSİZCE GEÇMİYOR. Bilinen ve zararsız
 * olanlar (fsync, statvfs...) stat/readdir gibi satır üretmiyor; geri
 * kalan HER ŞEY adıyla birlikte yazılıyor. Aksi hâli, bu arızanın
 * kendisiydi: adını bilmediğimiz bir eklenti dosyayı taşısın ve defter
 * boş kalsın. Yarın eklenen bir eklenti önceden onaylanmış olmamalı.
 */
func (s *Session) onExtended(r *reader) error {
	id, name, err := idAndPath(r) // id + string: eklenti adı
	if err != nil {
		return err
	}

	switch name {
	case extPosixRename, extHardlink:
		path, perr := r.str()
		if perr != nil {
			return perr
		}
		newPath, nerr := r.str()
		if nerr != nil {
			return nerr
		}
		return s.addPending(id, pendingOp{typ: fxpExtended, ext: name,
			path: path, newPath: newPath})

	case extLsetstat:
		path, perr := r.str()
		if perr != nil {
			return perr
		}
		return s.addPending(id, pendingOp{typ: fxpExtended, ext: name, path: path})
	}

	if quietExtensions[name] {
		return nil
	}

	// Tanımadığımız eklenti: yolunu çözemeyebiliriz ama OLDUĞUNU
	// yazarız. Adı detail'e gidiyor ki operatör neye baktığını bilsin.
	return s.addPending(id, pendingOp{typ: fxpExtended, ext: name})
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
		p, ok := s.takePending(id)
		if !ok {
			return nil
		}
		if p.typ == fxpOpendir {
			if len(s.dirHandles)+len(s.handles) >= maxHandles {
				return fmt.Errorf("sftpaudit: too many open handles (limit %d)", maxHandles)
			}
			s.dirHandles[handle] = true
			s.write(Event{Op: OpOpendir, Path: p.path, OK: true})
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
		return
	}
	s.write(Event{Op: op, Path: p.path, NewPath: p.newPath,
		OK: ok, Status: code, Detail: msg})
}

// statusOps, cevabı STATUS olan istek tiplerini olay adına çevirir.
var statusOps = map[byte]Op{
	fxpRemove:   OpRemove,
	fxpRmdir:    OpRmdir,
	fxpMkdir:    OpMkdir,
	fxpRename:   OpRename,
	fxpSymlink:  OpSymlink,
	fxpSetstat:  OpSetstat,
	fxpFsetstat: OpSetstat,
}

// closeHandle, dosya özetini yazar ve tanıtıcıyı bırakır.
func (s *Session) closeHandle(handle string) {
	if s.dirHandles[handle] {
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
	for h, f := range s.handles {
		delete(s.handles, h)
		s.write(Event{Op: OpTransfer, Path: f.path, Flags: flagsString(f.flags),
			Read: f.read, Wrote: f.wrote, OK: false,
			Detail: "channel closed before the file was closed"})
	}
}

func (s *Session) addPending(id uint32, p pendingOp) error {
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

func (s *Session) write(e Event) {
	e.At = s.now()
	s.emit(e)
}

// idAndPath, "uint32 id + string" başlığını okur (çok yerde aynı).
func idAndPath(r *reader) (uint32, string, error) {
	id, err := r.uint32()
	if err != nil {
		return 0, "", err
	}
	p, err := r.str()
	if err != nil {
		return 0, "", err
	}
	return id, p, nil
}
