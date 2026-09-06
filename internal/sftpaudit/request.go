package sftpaudit

// Tel biçiminden çözülmüş istek: denetimin ve politikanın ORTAK görüşü.

/*
 * request, bir istemci isteğinin çözülmüş hâli.
 *
 * ⚠️ TEK ÇÖZÜMLEYİCİ, İKİ TÜKETİCİ. Politika kararını ve denetim satırını
 * ayrı ayrıştırmalardan üretmek, ikisinin zamanla farklı şeyler görmesi
 * demekti. "Defterde yazan yol ile politikanın baktığı yol aynı değil"
 * cümlesi bu üründe kabul edilemez.
 *
 * ⚠️ AYNI FONKSİYON EKSİK GÖVDEYLE DE ÇAĞRILIYOR. Politika kararı, paket
 * tamamlanmadan, karar bütçesi kadar gövdeyle veriliyor (frame.go). O
 * durumda okuyucu errShort veriyor ve çağıran ne yapacağını kendi biliyor:
 * politika REDDEDİYOR, denetim ise akışı bozuk sayıyor.
 */
type request struct {
	typ byte
	id  uint32

	// known, türü TANIDIĞIMIZI söylüyor. Tanımıyorsak id dışındaki hiçbir
	// alan doldurulmuyor — gövdenin biçimini bilmiyoruz.
	known bool

	path    string
	newPath string
	flags   uint32
	handle  string
	// n, WRITE'ta yazılmak istenen bayt sayısı.
	n   uint32
	ext string
}

/*
 * parseRequest, bir istek paketini çözer.
 *
 * ⚠️ HER YOL TAŞIYAN TÜR BURADA. Salt-okuma üstverisi (stat, lstat,
 * realpath, readlink, readdir, fstat) de çözülüyor: denetim onlar için
 * satır yazmıyor ama POLİTİKA onları da kapsıyor, ve kapsamanın koşulu
 * yolu görebilmek.
 *
 * ⚠️ İKİ YOLLU TÜRLERDE İKİSİ DE OKUNUYOR. SYMLINK'te alanların sırası
 * taslak ile OpenSSH arasında ters; hangisi hedef hangisi bağ olduğuna
 * bakmadan İKİSİNİ birden politikaya vermek bu ayrımı önemsiz kılıyor.
 */
func parseRequest(typ byte, r *reader) (request, error) {
	req := request{typ: typ, known: true}

	switch typ {
	case fxpInit:
		// Sürüm anlaşması: istek kimliği YOK, gövdesi sürüm numarası.
		return req, nil

	case fxpOpen:
		var err error
		if req.id, err = r.uint32(); err != nil {
			return req, err
		}
		if req.path, err = r.str(); err != nil {
			return req, err
		}
		if req.flags, err = r.uint32(); err != nil {
			return req, err
		}
		return req, nil

	case fxpOpendir, fxpRemove, fxpRmdir, fxpMkdir, fxpSetstat,
		fxpLstat, fxpStat, fxpRealpath, fxpReadlink:
		var err error
		req.id, req.path, err = idAndPath(r)
		return req, err

	case fxpRename, fxpSymlink, fxpLink:
		var err error
		if req.id, req.path, err = idAndPath(r); err != nil {
			return req, err
		}
		req.newPath, err = r.str()
		return req, err

	case fxpRead, fxpClose, fxpReaddir, fxpFstat, fxpFsetstat:
		var err error
		req.id, req.handle, err = idAndPath(r)
		return req, err

	case fxpWrite:
		var err error
		if req.id, req.handle, err = idAndPath(r); err != nil {
			return req, err
		}
		if _, err = r.uint64(); err != nil { // offset
			return req, err
		}
		req.n, err = r.strLen()
		return req, err

	case fxpExtended:
		var err error
		if req.id, req.ext, err = idAndPath(r); err != nil {
			return req, err
		}
		switch req.ext {
		case extPosixRename, extHardlink:
			if req.path, err = r.str(); err != nil {
				return req, err
			}
			req.newPath, err = r.str()
			return req, err
		case extLsetstat:
			req.path, err = r.str()
			return req, err
		}
		// Tanımadığımız eklenti: gövdesinin biçimini bilmiyoruz.
		return req, nil
	}

	/*
	 * Tanımadığımız tür. Gövdenin biçimini bilmiyoruz ama INIT dışında
	 * her istek kimlikle başlıyor; onu okuyabilmek, hedefin cevabını bu
	 * isteğe bağlamaya yetiyor.
	 */
	req.known = false
	var err error
	req.id, err = r.uint32()

	return req, err
}
