package sftpaudit

// SFTP tel biçiminin çözümlenmesi (draft-ietf-secsh-filexfer-02, sürüm 3 —
// OpenSSH'in konuştuğu sürüm).
//
// ⚠️ BURASI DÜŞMAN GİRDİSİ OKUYOR. Uzunluk alanlarının hepsi karşı
// taraftan geliyor; hiçbirine güvenilerek ayırma yapılmıyor. Bir alan
// pakete sığmıyorsa hata dönüyor — kısmi okunmuş bir alanla devam etmek,
// denetim kaydına uydurma bir dosya adı yazmak demektir.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Paket tipleri (RFC taslağı §3, §4).
const (
	fxpInit     = 1
	fxpVersion  = 2
	fxpOpen     = 3
	fxpClose    = 4
	fxpRead     = 5
	fxpWrite    = 6
	fxpSetstat  = 9
	fxpFsetstat = 10
	fxpOpendir  = 11
	fxpRemove   = 13
	fxpMkdir    = 14
	fxpRmdir    = 15
	fxpRename   = 18
	fxpSymlink  = 20

	fxpStatus = 101
	fxpHandle = 102
	fxpData   = 103
)

// Durum kodları (§7). Yalnızca "başardı mı" ayrımı için gerekli.
const (
	fxOK = 0
)

// open bayrakları (§6.3). Yönü buradan çıkarıyoruz: okuma mı yazma mı.
const (
	flagRead   = 0x00000001
	flagWrite  = 0x00000002
	flagAppend = 0x00000004
	flagCreat  = 0x00000008
	flagTrunc  = 0x00000010
	flagExcl   = 0x00000020
)

// errShort, alan pakete sığmadığında dönüyor.
var errShort = errors.New("sftpaudit: truncated packet")

/*
 * maxPacket, tek bir SFTP paketinin kabul edilen üst sınırı.
 *
 * ⚠️ NEDEN VAR: uzunluk alanı 32 bit ve karşı taraftan geliyor.
 * Sınırsız bırakılsa, "uzunluk = 4 GB" yazan tek bir paket başlığı
 * çözümleyiciyi 4 GB beklemeye sokardı; veri hiç gelmese bile durum
 * makinesi o pakete kilitlenir ve oturum boyunca bir daha hiçbir olay
 * üretmezdi. Yani denetim, tek bir sayı yazılarak susturulabilirdi.
 *
 * OpenSSH'in kendi sınırı 256 KB civarı; 1 MB rahat bir tavan.
 */
const maxPacket = 1 << 20

/*
 * maxHeader, bir paketten SAKLADIĞIMIZ en fazla bayt.
 *
 * Dosya adları ve tanıtıcılar paketin başında; gövde (DATA/WRITE içeriği)
 * bizi ilgilendirmiyor ve saklanmıyor. Bu sayede 1 GB'lık bir transfer
 * çözümleyicide 1 GB değil, paket başına en fazla bu kadar yer tutuyor —
 * kaydın kendisi de ham veriyi almadığı için transfer diske ikinci kez
 * yazılmıyor.
 *
 * SFTP yolları için 64 KB fazlasıyla yeterli (Linux PATH_MAX 4096).
 */
const maxHeader = 64 << 10

// reader, bir paket gövdesi üzerinde ilerleyen imleç.
type reader struct {
	buf []byte
	off int
}

func (r *reader) uint32() (uint32, error) {
	if r.off+4 > len(r.buf) {
		return 0, errShort
	}
	v := binary.BigEndian.Uint32(r.buf[r.off:])
	r.off += 4
	return v, nil
}

func (r *reader) uint64() (uint64, error) {
	if r.off+8 > len(r.buf) {
		return 0, errShort
	}
	v := binary.BigEndian.Uint64(r.buf[r.off:])
	r.off += 8
	return v, nil
}

func (r *reader) byteVal() (byte, error) {
	if r.off+1 > len(r.buf) {
		return 0, errShort
	}
	v := r.buf[r.off]
	r.off++
	return v, nil
}

/*
 * str, uzunluk önekli bir dizgi okur.
 *
 * ⚠️ Uzunluğu okuyup ona göre ayırmıyoruz: önce paketin İÇİNDE olup
 * olmadığına bakıyoruz. "uzunluk = 3 GB" yazan bir alan burada hata
 * veriyor, ayırma denemesi değil.
 */
func (r *reader) str() (string, error) {
	n, err := r.uint32()
	if err != nil {
		return "", err
	}
	if int64(n) > int64(len(r.buf)-r.off) {
		return "", errShort
	}
	s := string(r.buf[r.off : r.off+int(n)])
	r.off += int(n)
	return s, nil
}

// strLen, dizginin uzunluğunu okur ve gövdesini ATLAR.
//
// DATA ve WRITE için: kaç bayt taşındığını bilmek istiyoruz, içeriğini
// değil. İçeriği okumak, denetim kaydını dosyanın kopyasına çevirirdi.
func (r *reader) strLen() (uint32, error) {
	n, err := r.uint32()
	if err != nil {
		return 0, err
	}
	// Gövdeyi atlamıyoruz (arkasında okuyacağımız alan yok) ama
	// uzunluğun paket sınırını aşmadığını yine de doğruluyoruz:
	// aşıyorsa paket bozuk, sayı da güvenilmez.
	if int64(n) > int64(maxPacket) {
		return 0, fmt.Errorf("sftpaudit: data length %d exceeds max packet", n)
	}
	return n, nil
}

// flagsString, open bayraklarını okunur hâle getirir — denetim kaydında
// "0x1a" değil "write,creat,trunc" görünsün diye.
func flagsString(f uint32) string {
	var parts []string
	if f&flagRead != 0 {
		parts = append(parts, "read")
	}
	if f&flagWrite != 0 {
		parts = append(parts, "write")
	}
	if f&flagAppend != 0 {
		parts = append(parts, "append")
	}
	if f&flagCreat != 0 {
		parts = append(parts, "creat")
	}
	if f&flagTrunc != 0 {
		parts = append(parts, "trunc")
	}
	if f&flagExcl != 0 {
		parts = append(parts, "excl")
	}
	if len(parts) == 0 {
		return "none"
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "," + p
	}
	return out
}
