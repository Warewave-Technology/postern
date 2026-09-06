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
	// üstveri istekleri sessiz kalmaya devam ediyor (bkz. readOnlyRequests).
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
	 * maxPath, BEKLEYEN kayıtta saklanan yolun üst sınırı.
	 *
	 * ⚠️ SAYI SINIRI BAYT SINIRI DEĞİL. maxPending 4096 istekle sınırlıyor
	 * ama her isteğin yolu gövde kadar (maxHeader, 64 KiB) uzun olabiliyordu:
	 * 4096 × 64 KiB ≈ 256 MiB, oturum başına. İstemci kanaldan OKUMAYI
	 * bırakırsa hedefin cevapları geri birikiyor, bekleyenler boşalmıyor ve
	 * bu sınıra gerçekten ulaşılıyor.
	 *
	 * 4096, Linux'ta PATH_MAX. Bunu aşan bir yol hedefte zaten
	 * ENAMETOOLONG ile dönüyor; sakladığımız şey reddedilecek bir isteğin
	 * kaydı.
	 */
	maxPath = 4096

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
	mu      sync.Mutex
	emit    func(Event)
	now     func() time.Time
	pending map[uint32]pendingOp
	handles map[string]*openFile
	// dirHandles, OPENDIR ile açılanlar — transfer özeti üretmiyorlar.
	dirHandles map[string]bool

	// policy, isteklere karar veren geri çağrı (policy.go). nil olabilir.
	policy Decider
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

// readOnlyRequests, satır ÜRETMEYEN istek türleri: hiçbiri içeriği ya da
// ad uzayını değiştirmiyor. quietExtensions'ın temel tür karşılığı.
var readOnlyRequests = map[byte]bool{
	fxpLstat:    true,
	fxpFstat:    true,
	fxpReaddir:  true,
	fxpRealpath: true,
	fxpStat:     true,
	fxpReadlink: true,
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
			s.dirHandles[handle] = true
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

// clampPath, saklanacak yolu maxPath'e indirir ve KESİLDİĞİNİ işaretler.
//
// ⚠️ SESSİZ KESME YAPMIYORUZ. Defterde kısaltılmış bir yol gören operatör,
// onu gerçek yol sanıp yanlış bir şey üzerinde işlem yapabilirdi.
func clampPath(p string) string {
	if len(p) <= maxPath {
		return p
	}
	p = p[:maxPath]
	for len(p) > 0 && !utf8.ValidString(p) {
		p = p[:len(p)-1]
	}
	return p + " (truncated)"
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
