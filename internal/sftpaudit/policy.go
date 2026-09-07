package sftpaudit

// İstek politikası: hangi isteğin hedefe geçeceğine karar vermek.

import (
	"fmt"
	"path"
	"strings"
)

/*
 * Request, politikaya sunulan istek.
 *
 * ⚠️ YOLLAR NORMALLEŞTİRİLMİŞ GELİYOR. İstemci `/veri/../etc/shadow`
 * yazabiliyor ve hedef bunu `/etc/shadow` olarak çözüyor; politikaya ham
 * dizgiyi vermek, korumayı kâğıt üzerinde bırakırdı.
 *
 * ⚠️ NEYİ ÇÖZEMEDİĞİMİZ DE AÇIK OLMALI: sembolik bağlar. Dosya sistemine
 * erişimimiz yok, dolayısıyla izinli bir dizindeki `link -> /etc` üzerinden
 * geçen bir yol bize izinli görünür. Bunu kapatmanın yolu her istekte
 * hedefe fazladan gidiş-dönüş olurdu; agentless duruşu ve gecikme hedefi
 * buna izin vermiyor. Sınır belgede aynı sertlikte yazılı.
 */
type Request struct {
	// Op, isteğin denetimdeki adı.
	Op Op
	// Path, normalleştirilmiş yol.
	Path string
	// NewPath, ikinci yol (rename, symlink, link); yoksa boş.
	NewPath string
	// Write, isteğin ad uzayını ya da içeriği DEĞİŞTİRME amacı taşıdığı.
	Write bool
}

/*
 * Decider, bir isteğe izin verilip verilmediğini söyler.
 *
 * ⚠️ BLOKLAMAMALI. Session'ın tek muteksi altında, veri yolunun üstünde
 * çalışıyor; burada geçen her milisaniye hedef→istemci akışını da
 * durduruyor (bkz. frame.go, decide).
 *
 * reason, hem istemciye giden STATUS mesajına hem de denetim satırına
 * giriyor: kullanıcı neden reddedildiğini görmeli, operatör de.
 */
type Decider func(Request) (allow bool, reason string)

/*
 * Denial, reddedilen bir isteğe verilecek iki cevap.
 *
 * ⚠️ İKİSİ AYRI KANALDAN GİDİYOR ve ikisi de gerekli. Status, SFTP veri
 * akışında istemcinin PROTOKOL cevabı: onsuz istek kimliği açık kalır ve
 * istemci sonsuza kadar bekler. Notice ise İNSANA giden satır, stderr'den.
 *
 * ⚠️ NEDEN İNSAN SATIRI DA ŞART: OpenSSH'in sftp istemcisi STATUS'un
 * mesaj alanını hiç okumuyor (get_status yalnızca tip, kimlik ve kodu
 * ayrıştırıp tamponu bırakıyor) ve `get`/`ls` öncesi yaptığı stat
 * başarısız olunca "not found" yazıyor — durum kodundan bağımsız olarak.
 * Yani reddi UYGULUYORUZ, defterine YAZIYORUZ, ama kullanıcı
 * "engellendim" ile "dosya yok"u ayırt edemiyor. Ölçüldü.
 */
type Denial struct {
	// Status, SFTP veri akışına yazılacak cevap paketi.
	Status []byte
	// Notice, stderr'e yazılacak insan satırı.
	Notice string
}

// SetPolicy, isteklere karar verecek geri çağrıyı kurar. nil ise yol
// kuralı uygulanmıyor (salt-okuma kısıtı ayrı, bkz. SetReadOnly).
func (s *Session) SetPolicy(d Decider) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.policy = d
	s.armLocked()
}

/*
 * SetReadOnly, oturumu hedefte HİÇBİR ŞEYİ DEĞİŞTİREMEZ hâle getirir.
 *
 * ⚠️ YOL POLİTİKASINDAN AYRI BİR KISIT. Roldeki kurallar "nereye"
 * sorusunu cevaplıyor; bu, "ne yapabilir" sorusunu. Bir kanalın
 * salt-okunur olması kullanıcının yetkisiyle değil, o KANALIN ne için
 * açıldığıyla ilgili.
 *
 * ⚠️ SARMALAYICI OLARAK YAZILAMAZDI ve sebebi ölçülebilir: FXP_WRITE
 * politikaya HİÇ sorulmuyor — tanıtıcı üzerinden yazma, açılışta karara
 * bağlandığı için politikaya götürülmüyor. Decider'ı saran bir kısıt o
 * isteği hiç görmezdi. Yazma bayraklı OPEN reddedilirse yazma tanıtıcısı
 * zaten oluşmaz; ama buna güvenmek, kısıtı HEDEFİN kendi kontrolüne
 * bırakmak demek — bir bastion'ın tam olarak yapmaması gereken şey.
 */
func (s *Session) SetReadOnly(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.readOnly = on
	s.armLocked()
}

/*
 * armLocked, karar kancasını gerektiğinde kurar. s.mu tutulmalı.
 *
 * ⚠️ İKİ KISITTAN BİRİ YETİYOR. Kancayı yalnızca policy'ye bağlasaydık,
 * politikasız ama salt-okunur bir oturum hiçbir şeyi kısıtlamazdı.
 */
func (s *Session) armLocked() {
	if s.policy == nil && !s.readOnly {
		s.fromClient.decide = nil
		return
	}
	s.fromClient.decide = s.decideRequest
}

/*
 * TakeDenials, reddedilen isteklere üretilen STATUS paketlerini alır.
 *
 * ⚠️ ÇAĞIRAN BUNLARI OTURUM KİLİDİ DIŞINDA YAZMALI. Karar, veri yolunun
 * üstünde ve s.mu altında veriliyor; istemciye o kilidi tutarken yazmak,
 * okumayı durduran bir istemcide hedef→istemci yönünü de kilitlerdi.
 */
func (s *Session) TakeDenials() []Denial {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.denials) == 0 {
		return nil
	}
	out := s.denials
	s.denials = nil

	return out
}

/*
 * decideRequest, framer'ın karar noktasında çağırdığı köprü: teli
 * çözüyor, politikayı soruyor, reddi hem deftere hem de istemciye
 * yazılacak cevaba dönüştürüyor.
 *
 * ⚠️ HER BELİRSİZLİK REDDE DÜŞÜYOR. Gövde eksikse, tür tanınmıyorsa,
 * eklentinin biçimini bilmiyorsak ya da yol mutlak değilse geçirmiyoruz.
 * Geçirmek, politikayı "postern'in çözemediği her şey" kadar delik
 * bırakırdı — ve o deliğin adını saldırgan koyardı.
 */
func (s *Session) decideRequest(typ byte, r *reader) (bool, error) {
	req, err := parseRequest(typ, r)

	// INIT'in kimliği yok ve yol taşımıyor; sürüm anlaşması geçiyor.
	if typ == fxpInit {
		return true, nil
	}

	if !req.haveID {
		/*
		 * ⚠️ KİMLİKSİZ İSTEĞE CEVAP YOK. Uydurma bir kimlikle STATUS
		 * yazmak, istemcinin HİÇ GÖNDERMEDİĞİ bir isteğe cevap vermek
		 * olur ve OpenSSH bunu fatal("ID mismatch") ile karşılıyor.
		 * Kimliği okunamayan bir akış zaten çözülemiyor demektir.
		 */
		return false, fmt.Errorf("sftpaudit: request id unreadable: %w", err)
	}

	if err != nil {
		// Karar bütçesine sığmayan ya da kesik gövde: kimlik var, cevap
		// verebiliyoruz.
		return s.refuse(req.id, Request{Op: OpUnknown}, "request could not be parsed"), nil
	}

	if !req.known {
		return s.refuseWith(req.id, Request{Op: OpUnknown}, StatusOpUnsupported,
			unknownDetail(typ, "not recognised")), nil
	}

	pr, checked := s.policyView(req)
	if !checked {
		return true, nil
	}
	if pr.deny != "" {
		/*
		 * ⚠️ TANIMADIĞIMIZ UZANTI "İZİN YOK" DEĞİL "DESTEKLENMİYOR".
		 * Sebebi doğru söylemek, istemcinin postern'in denetleyebildiği
		 * standart işlemlere geri düşmesini sağlıyor.
		 */
		code := StatusPermissionDenied
		if pr.unsupported {
			code = StatusOpUnsupported
		}
		return s.refuseWith(req.id, pr.req, code, pr.deny), nil
	}

	/*
	 * ⚠️ SALT-OKUMA, YOL KURALINDAN ÖNCE. Rol o yola yazma hakkı verse
	 * bile bu kanal yazamaz: kısıt kullanıcının yetkisinden değil,
	 * kanalın ne için açıldığından geliyor.
	 */
	if s.readOnly && pr.req.Write {
		return s.refuse(req.id, pr.req, "this session is read-only"), nil
	}

	if s.policy != nil {
		if allow, reason := s.policy(pr.req); !allow {
			if reason == "" {
				reason = "path is not permitted"
			}
			return s.refuse(req.id, pr.req, reason), nil
		}
	}

	return true, nil
}

// policyResult, politikaya sunulacak istek ya da onu sunmadan reddetme
// sebebi.
type policyResult struct {
	req  Request
	deny string
	// unsupported, reddin sebebinin YOL değil TANIMAMA olduğu.
	unsupported bool
}

/*
 * policyView, çözülmüş isteği politikanın göreceği hâle çevirir.
 *
 * İkinci dönüş değeri false ise istek politikaya HİÇ sorulmuyor: kapanışı
 * reddetmenin bir anlamı yok ve tanıtıcı üzerinden okuma/yazma zaten
 * açılışta karara bağlanmış durumda.
 */
func (s *Session) policyView(req request) (policyResult, bool) {
	switch req.typ {
	case fxpClose:
		/*
		 * ⚠️ CLOSE HİÇBİR ZAMAN REDDEDİLMİYOR. Reddetmek tanıtıcıyı
		 * hedefte açık bırakır ve transfer özetini yok ederdi — yani
		 * denetimin en çok işine yarayan satırı, politikayı uygulayarak
		 * kaybederdik.
		 */
		return policyResult{}, false

	case fxpRead, fxpWrite:
		/*
		 * ⚠️ SALT-OKUNUR OTURUMDA FXP_WRITE AÇIKTAN REDDEDİLİYOR.
		 *
		 * Yazma bayraklı OPEN zaten reddedildiği için buraya bir yazma
		 * tanıtıcısıyla gelinemez — ama o akıl yürütme, kısıtın HEDEFİN
		 * açma kipini uygulamasına bağlı olması demek. Bastion kendi
		 * kısıtını kendi uygulamalı.
		 */
		if s.readOnly && req.typ == fxpWrite {
			path, _ := s.pathForHandle(req.handle)
			return policyResult{
				deny: "this session is read-only",
				req:  Request{Op: OpTransfer, Path: path, Write: true},
			}, true
		}

		/*
		 * ⚠️ YAZMA, TANITICININ YOLU ÜZERİNDEN POLİTİKAYA SORULUYOR.
		 *
		 * Eskiden sorulmuyordu: tanıdık bir tanıtıcı görüldüğü an istek
		 * politikasız geçiyordu, gerekçesi de "yolu açan istek zaten
		 * karara bağlandı" idi. Açma isteği gerçekten karara bağlanıyor
		 * — ama YAZMA BAYRAKLI bir açma olarak. İstemci yolu OKUMA
		 * bayrağıyla açıp (politika izin verir) aynı tanıtıcı üzerine
		 * FXP_WRITE gönderdiğinde, kısıtı uygulayan tek şey HEDEFİN
		 * açma kipi oluyordu.
		 *
		 * Bu, hemen yukarıdaki salt-okuma dalının kendisi için yazdığı
		 * gerekçenin aynısı: "bastion kendi kısıtını kendi uygulamalı".
		 * Aynı cümle rol yol kuralları için de geçerli — can_write bir
		 * söz ve onu hedefin insafına bırakamayız.
		 *
		 * ⚠️ İZİN VERİLEN YAZMA SATIR ÜRETMİYOR: karar true dönerse
		 * defterde iz kalmıyor, aktarımın toplamı tanıtıcı kapanırken
		 * tek bir satır olarak yazılıyor. Yani parça başına bir denetim
		 * satırı yok. Reddedilen yazma satır üretiyor ve orası ayrı bir
		 * sınır (bkz. denyFlood).
		 */
		if req.typ == fxpWrite {
			p, ok := s.pathForHandle(req.handle)
			if !ok {
				return policyResult{deny: "handle was not opened through this session",
					req: Request{Op: OpTransfer, Write: true}}, true
			}

			return policyResult{req: Request{
				Op: OpTransfer, Path: p, Write: true,
			}}, true
		}

		/*
		 * Okuma: yolu açan istek karara bağlandı ve okuma yetkisi o
		 * kararın içinde. Tanıtığımız bir tanıtıcı değilse
		 * REDDEDİYORUZ — politika açıkken "nereden geldiğini
		 * bilmediğimiz tanıtıcı" kabul edilebilir bir şey değil.
		 */
		if _, ok := s.handles[req.handle]; ok {
			return policyResult{}, false
		}
		return policyResult{deny: "handle was not opened through this session",
			req: Request{Op: OpTransfer}}, true

	case fxpReaddir, fxpFstat, fxpFsetstat:
		p, ok := s.pathForHandle(req.handle)
		if !ok {
			return policyResult{deny: "handle was not opened through this session",
				req: Request{Op: opForType(req.typ)}}, true
		}
		return policyResult{req: Request{
			Op:    opForType(req.typ),
			Path:  p,
			Write: req.typ == fxpFsetstat,
		}}, true

	case fxpExtended:
		return s.extendedView(req)
	}

	/*
	 * ⚠️ GÖRELİ BİR AD ÜZERİNDEKİ REALPATH POLİTİKAYA HİÇ SORULMUYOR.
	 *
	 * ÖLÇÜLEN ARIZA: OpenSSH'in sftp istemcisi oturumun İLK isteği olarak
	 * `realpath "."` gönderiyor. Bunu politikaya sormak, hiçbir kurala
	 * uymayan bir yola sormak demek ve ret geliyor: istemci "Need cwd" ile
	 * daha başlarken kırılıyor. Demoda ölçüldü.
	 *
	 * REALPATH bir ADI çözüyor, içeriğe dokunmuyor; ardından gelen açma
	 * isteği mutlak yolla gelip karara bağlanıyor. Mutlak bir yol üzerinde
	 * REALPATH ise normal şekilde sorulabiliyor — o zaman eşleşecek bir
	 * şey var.
	 */
	if req.typ == fxpRealpath && !strings.HasPrefix(req.path, "/") {
		return policyResult{}, false
	}

	// Yol taşıyan sıradan istekler.
	pr := policyResult{req: Request{
		Op:      opForType(req.typ),
		Write:   writeIntent(req),
		Path:    req.path,
		NewPath: req.newPath,
	}}
	pr = normalise(pr, req.typ)

	return pr, true
}

// extendedView, EXTENDED isteğini politikanın göreceği hâle çevirir.
func (s *Session) extendedView(req request) (policyResult, bool) {
	switch req.ext {
	case extPosixRename, extHardlink:
		return normalise(policyResult{req: Request{
			Op: extendedOps[req.ext], Write: true,
			Path: req.path, NewPath: req.newPath,
		}}, req.typ), true

	case extLsetstat:
		return normalise(policyResult{req: Request{
			Op: extendedOps[req.ext], Write: true, Path: req.path,
		}}, req.typ), true
	}

	if quietExtensions[req.ext] {
		/*
		 * ⚠️ SESSİZ EKLENTİLER POLİTİKAYA HİÇ SORULMUYOR — yalnızca
		 * "izin ver" denmiyor, SORU SORULMUYOR.
		 *
		 * ÖLÇÜLEN ARIZA: bunlar için boş yollu bir istek üretip politikaya
		 * soruyorduk. Politika boş yolu hiçbir kurala uyduramayıp
		 * reddediyordu ve OpenSSH istemcisi daha oturumun başında
		 * "sftp_init: limits failed" ile kırılıyordu — limits@openssh.com
		 * bağlanır bağlanmaz gönderiliyor.
		 *
		 * Bu eklentiler yol taşımıyor ve içeriğe dokunmuyor (fsync,
		 * statvfs, limits, expand-path...). Sorulacak bir yol yok.
		 *
		 * copy-data@openssh.com bu listede DEĞİL ve olmamalı: iki tanıtıcı
		 * alıp içeriği sunucu tarafında kopyalıyor, yani yol taşımadan veri
		 * taşıyor. Aşağıdaki redde düşüyor.
		 */
		return policyResult{}, false
	}

	return policyResult{
		req:         Request{Op: OpExtended},
		deny:        "extension " + req.ext + " is not recognised",
		unsupported: true,
	}, true
}

// pathForHandle, tanıtıcıyı açılışta kaydedilen yola çevirir.
func (s *Session) pathForHandle(h string) (string, bool) {
	if f, ok := s.handles[h]; ok {
		return f.path, true
	}
	if p, ok := s.dirHandles[h]; ok {
		/*
		 * ⚠️ DİZİN TANITICISI DA YOLUNU TAŞIYOR. "OPENDIR'da karara
		 * bağlandı, READDIR'a bakmaya gerek yok" varsayımı, READDIR'ı
		 * politikaya BOŞ yolla sordurup her listelemeyi reddettiriyordu.
		 */
		return p, true
	}

	return "", false
}

/*
 * normalise, yolları politikanın eşleyebileceği hâle getirir.
 *
 * ⚠️ MUTLAK OLMAYAN YOL REDDEDİLİYOR — TEK İSTİSNASIYLA. Göreli bir yolu
 * politikaya sormak imkânsız: neye göre olduğunu bilmiyoruz (istemcinin
 * çalışma dizini hedefte, bizde değil). İstisna REALPATH: OpenSSH'in sftp
 * istemcisi oturumun İLK isteği olarak `realpath "."` gönderiyor ve bunu
 * reddetmek her oturumu daha başlarken kırardı. REALPATH bir ADI çözüyor,
 * içeriğe dokunmuyor; ardından gelen açma isteği mutlak yolla geliyor ve
 * o karara bağlanıyor.
 */
func normalise(pr policyResult, typ byte) policyResult {
	if pr.deny != "" {
		return pr
	}

	for _, f := range []*string{&pr.req.Path, &pr.req.NewPath} {
		if *f == "" {
			continue
		}
		if strings.ContainsRune(*f, 0) {
			pr.deny = "path contains a NUL byte"
			return pr
		}
		if !strings.HasPrefix(*f, "/") {
			pr.deny = "path is not absolute; postern cannot resolve it"
			return pr
		}
		*f = path.Clean(*f)
	}

	return pr
}

// writeIntent, isteğin değiştirme amacı taşıyıp taşımadığı.
func writeIntent(req request) bool {
	switch req.typ {
	case fxpOpen:
		return req.flags&(flagWrite|flagAppend|flagCreat|flagTrunc) != 0
	case fxpRemove, fxpRmdir, fxpMkdir, fxpSetstat, fxpRename, fxpSymlink, fxpLink:
		return true
	}

	return false
}

// opForType, istek türünü denetim adına çevirir.
func opForType(typ byte) Op {
	switch typ {
	case fxpOpen:
		return OpOpen
	case fxpOpendir:
		return OpOpendir
	case fxpRemove:
		return OpRemove
	case fxpRmdir:
		return OpRmdir
	case fxpMkdir:
		return OpMkdir
	case fxpSetstat, fxpFsetstat:
		return OpSetstat
	case fxpRename:
		return OpRename
	case fxpSymlink:
		return OpSymlink
	case fxpLink:
		return OpLink
	case fxpLstat, fxpStat, fxpFstat:
		return OpStat
	case fxpReaddir:
		return OpReaddir
	case fxpRealpath:
		return OpRealpath
	case fxpReadlink:
		return OpReadlink
	}

	return OpUnknown
}

/*
 * refuse, reddi kaydeder ve istemciye gidecek cevabı hazırlar.
 *
 * ⚠️ SATIR BURADA YAZILIYOR, deliver'DA DEĞİL. Reddedilen paket hedefe
 * gitmiyor, dolayısıyla hiçbir zaman bir cevabı olmayacak; bekleyenler
 * tablosuna koymak satırı hiç yazmamak ve kaydı sızdırmak demekti.
 *
 * Her zaman false dönüyor: çağrı yerinde "reddet" ifadesinin kendisi.
 */
// flagsText, reddedilen isteğin niyetini defterde okunur kılıyor: operatör
// "okumaya mı yazmaya mı kalkıştı" sorusunu satırdan cevaplayabilmeli.
func (r Request) flagsText() string {
	if r.Write {
		return "write"
	}

	return "read"
}

func (s *Session) refuse(id uint32, r Request, reason string) bool {
	return s.refuseWith(id, r, StatusPermissionDenied, reason)
}

// refuseWith, reddi belirli bir durum koduyla kaydeder.
func (s *Session) refuseWith(id uint32, r Request, code uint32, reason string) bool {
	/*
	 * ⚠️ OP'A "denied." ÖNEKİ. Hedefin kendi EACCES'i de OK=false ve
	 * Status=3 yazıyor; ayırt edilebilir olmalı ki panel "politika kaç
	 * isteği engelledi" sorusunu SERBEST METİNDE alt dizgi arayarak
	 * cevaplamak zorunda kalmasın.
	 *
	 * Önek, postern'in KENDİ retleri için zaten kurulmuş sözleşme
	 * (bkz. lifecycle.go, "denied."+reqType). Yeni bir sütun eklemek
	 * göç gerektirirdi; bu alan zaten serbest.
	 */
	s.write(Event{
		Op: "denied." + r.Op, Path: r.Path, NewPath: r.NewPath,
		Flags: r.flagsText(), OK: false, Status: code,
		Detail: "postern: " + reason,
	})
	notice := "postern: " + reason
	if r.Path != "" {
		notice = "postern: " + r.Path + ": " + reason
	}
	s.denials = append(s.denials, Denial{
		Status: StatusPacket(id, code, "postern: "+reason),
		Notice: notice,
	})

	return false
}
