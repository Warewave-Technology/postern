// Package verify, bir oturumun kanıtının ne söylediğine karar verir:
// kaydın zinciri (verify.go) ve kaydın mührüyle defterin uyuşması
// (journal.go).
//
// ⚠️ İKİ EKSEN AYRI DURUYOR ve bu, paketin en önemli özelliği. Zincir
// "dosya yazıldığından beri değişti mi" sorusunu cevaplıyor; defter
// kontrolü "kaydın saydığı olayların satırları duruyor ve aynı şeyi
// söylüyor mu" sorusunu. Birini diğerinin sonucuna bağlamak — örneğin
// zinciri tutan bir kaydı "defteri de tamdır" diye okumak — hiç
// yapılmamış bir kontrolü yapılmış saymak olurdu.
//
// ⚠️ NİYE AYRI BİR PAKET. Bu kararı iki yer soruyor: `postern session
// verify` ve panelin doğrulama ucu. İkisi ayrı ayrı yazılsaydı ayrışmaları
// KAÇINILMAZ olurdu — ve ayrıştıkları gün ortaya çıkan şey, aynı kayıt
// için farklı iki cevap veren bir denetim aracı. Bir denetçinin en son
// isteyeceği şey bu.
//
// Paket I/O yapmıyor denecek kadar az yapıyor: kararlar saf, kovaya tek
// bir HEAD isteği var ve o da bir arayüzün arkasında. Böylece asıl
// iddialar bir kova ayağa kaldırmadan sınanabiliyor.
package verify

import (
	"context"
	"fmt"

	"github.com/Warewave-Technology/postern/internal/objstore"
	"github.com/Warewave-Technology/postern/internal/store"
)

// OffBoxState, arşivdeki kopyanın söylediği.
type OffBoxState int

const (
	// OffBoxMatch, kovadaki baş veritabanındakiyle AYNI.
	OffBoxMatch OffBoxState = iota

	/*
	 * OffBoxMismatch, kovadaki baş FARKLI — en güçlü kurcalama işareti.
	 *
	 * Dosya veritabanıyla tutuyorken kovadaki baş tutmuyorsa, ikisini
	 * birden üretebilmenin tek yolu bu makineyi elinde tutmaktır;
	 * kovadaki nesne ise saklama süresi boyunca oradan değiştirilemiyor.
	 */
	OffBoxMismatch

	/*
	 * OffBoxNoChain, nesne var ama zincir başı taşımıyor.
	 *
	 * ⚠️ "FARKLI" DEĞİL. Zincirlerden önce yüklenmiş bir nesne ya da
	 * üstveriyi düşüren bir depo, kurcalanmış bir kayıtla aynı şey
	 * değil — ikisini birleştirmek, kimsenin dokunmadığı eski kayıtları
	 * suçlamak olurdu.
	 */
	OffBoxNoChain

	/*
	 * OffBoxUnchecked, bakılamadı: arşiv kapalı, kayıt henüz yüklenmedi,
	 * ya da kovaya ulaşılamadı.
	 *
	 * ⚠️ "DOĞRULANDI" İLE KARIŞTIRILMAMASI GEREKEN DURUM. Bir kovaya
	 * ulaşamamak kurcalanmışlık kanıtı değil, ama onay da değil.
	 */
	OffBoxUnchecked
)

func (s OffBoxState) String() string {
	switch s {
	case OffBoxMatch:
		return "match"
	case OffBoxMismatch:
		return "mismatch"
	case OffBoxNoChain:
		return "no_chain"
	default:
		return "unchecked"
	}
}

// OffBox, arşivdeki kopyanın okunmasının sonucu.
type OffBox struct {
	State  OffBoxState
	Detail string
	// Chain/Links, kovadaki nesnenin taşıdığı değerler.
	Chain string
	Links string
	// Object, "kova/anahtar" — olay müdahalesinde nereye bakılacağı.
	Object string
}

/*
 * Verdict, arşivdeki başın ne söylediğine karar verir.
 *
 * I/O'dan AYRI, çünkü asıl iddia burada ve bir kovaya ihtiyaç duymadan
 * sınanabiliyor: hangi durum "farklı", hangisi "yok".
 */
func Verdict(archived, want string) (OffBoxState, string) {
	switch {
	case archived == "":
		return OffBoxNoChain, "the archived copy carries no chain head — it was " +
			"uploaded before chains existed, or the object store dropped the metadata"
	case archived != want:
		return OffBoxMismatch, ""
	default:
		return OffBoxMatch, ""
	}
}

/*
 * HeadReader, nesnenin üstverisini okuyan şey.
 *
 * Arayüz TÜKETİCİ tarafında: gerçek bir kova ayağa kaldırmadan "kova ne
 * derse desin karar doğru mu" sorusu sorulabilsin diye. Bu depoda tekrar
 * eden ders — somut tiple yazılan bir bağımlılık, pratikte hiç
 * sınanmayan bir dal bırakıyor.
 */
type HeadReader interface {
	Head(ctx context.Context, key string) (objstore.ObjectInfo, error)
}

/*
 * OffBoxOf, arşivdeki kopyanın taşıdığı zincir başını okur.
 *
 * client nil ise arşiv yapılandırılmamış demektir ve sonuç "bakılmadı"
 * olur — hata değil. Kayıt henüz yüklenmemişse de aynı: o kaydın kutu
 * dışı bir kopyası YOK, yani zincirin taşıdığı kanıt şu an yalnızca bu
 * makinede ve bunu söylemek gerekiyor.
 */
func OffBoxOf(ctx context.Context, client HeadReader, st store.ArchiveState,
	found bool, wantChain string) OffBox {
	switch {
	case client == nil:
		return OffBox{State: OffBoxUnchecked,
			Detail: "archiving is not configured (recording.archive.endpoint is empty)"}
	case !found || !st.Archived:
		return OffBox{State: OffBoxUnchecked,
			Detail: "this recording has not been archived yet"}
	}

	head, err := client.Head(ctx, st.ObjectKey)
	if err != nil {
		return OffBox{State: OffBoxUnchecked,
			Detail: fmt.Sprintf("could not read %s: %v", st.ObjectKey, err)}
	}

	out := OffBox{
		Chain:  head.Meta[objstore.MetaChain],
		Links:  head.Meta[objstore.MetaLinks],
		Object: st.Bucket + "/" + st.ObjectKey,
	}
	out.State, out.Detail = Verdict(out.Chain, wantChain)

	return out
}
