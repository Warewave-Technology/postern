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

// SetPolicy, isteklere karar verecek geri çağrıyı kurar. nil ise her istek
// geçiyor.
func (s *Session) SetPolicy(d Decider) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.policy = d
	if d == nil {
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
func (s *Session) TakeDenials() [][]byte {
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

	if allow, reason := s.policy(pr.req); !allow {
		if reason == "" {
			reason = "path is not permitted"
		}
		return s.refuse(req.id, pr.req, reason), nil
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
		 * Tanıtıcı üzerinden okuma/yazma: yolu açan istek zaten karara
		 * bağlandı. Tanıtığımız bir tanıtıcı değilse REDDEDİYORUZ —
		 * politika açıkken "nereden geldiğini bilmediğimiz tanıtıcı"
		 * kabul edilebilir bir şey değil.
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
		return s.extendedView(req), true
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
func (s *Session) extendedView(req request) policyResult {
	switch req.ext {
	case extPosixRename, extHardlink:
		return normalise(policyResult{req: Request{
			Op: extendedOps[req.ext], Write: true,
			Path: req.path, NewPath: req.newPath,
		}}, req.typ)

	case extLsetstat:
		return normalise(policyResult{req: Request{
			Op: extendedOps[req.ext], Write: true, Path: req.path,
		}}, req.typ)
	}

	if quietExtensions[req.ext] {
		/*
		 * ⚠️ SESSİZ EKLENTİLER YOL TAŞIMIYOR ve içeriğe dokunmuyor
		 * (fsync, statvfs, limits...). Politikaya soracak bir yol yok;
		 * reddetmek sıradan istemcileri kırardı.
		 *
		 * copy-data@openssh.com bu listede DEĞİL ve olmamalı: iki
		 * tanıtıcı alıp içeriği sunucu tarafında kopyalıyor, yani yol
		 * taşımadan veri taşıyor. Aşağıdaki redde düşüyor.
		 */
		return policyResult{}
	}

	return policyResult{
		req:         Request{Op: OpExtended},
		deny:        "extension " + req.ext + " is not recognised",
		unsupported: true,
	}
}

// pathForHandle, tanıtıcıyı açılışta kaydedilen yola çevirir.
func (s *Session) pathForHandle(h string) (string, bool) {
	if f, ok := s.handles[h]; ok {
		return f.path, true
	}
	if s.dirHandles[h] {
		// Dizin tanıtıcıları yolu saklamıyor; açılışta karara bağlandı.
		return "", true
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
			if typ == fxpRealpath {
				continue
			}
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
	s.denials = append(s.denials, StatusPacket(id, code, "postern: "+reason))

	return false
}
