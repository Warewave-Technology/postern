package verify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/objstore"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * ⚠️ BU PAKETİN VAR OLMA SEBEBİ, İKİ CEVABIN AYRIŞMAMASI.
 *
 * Aynı soruyu `postern session verify` ve panelin doğrulama ucu soruyor.
 * İkisi ayrı yazılsaydı bir gün aynı kayıt için farklı iki cevap verirlerdi
 * — bir denetim aracının verebileceği en kötü çıktı.
 */

func TestVerdictSeparatesThreeCases(t *testing.T) {
	cases := []struct {
		name           string
		archived, want string
		state          OffBoxState
		mustExplain    bool
	}{
		{"aynı baş", "abc", "abc", OffBoxMatch, false},
		{"farklı baş", "zzz", "abc", OffBoxMismatch, false},
		/*
		 * ⚠️ "ZİNCİR YOK" İLE "FARKLI ZİNCİR" AYRI DURUMLAR.
		 * Birleştirmek, zincirlerden önce yüklenmiş ya da üstverisi
		 * düşürülmüş bir kaydı kurcalanmış diye suçlamak olurdu — ve o
		 * suçlama geri alınamaz bir olay müdahalesi başlatır.
		 */
		{"zincir yok", "", "abc", OffBoxNoChain, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, detail := Verdict(c.archived, c.want)
			if state != c.state {
				t.Errorf("durum = %v, %v bekleniyordu", state, c.state)
			}
			if c.mustExplain && detail == "" {
				t.Error("sebep yazılmamış: kullanıcı neden bakılamadığını bilmeli")
			}
		})
	}
}

// Durum adları BENZERSİZ olmalı: panel ve CLI bunları makine tarafında
// ayırt ediyor; iki durumun aynı adı taşıması ikisini birleştirir.
func TestStateNamesAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range []OffBoxState{OffBoxMatch, OffBoxMismatch, OffBoxNoChain, OffBoxUnchecked} {
		name := s.String()
		if name == "" {
			t.Fatalf("%d durumunun adı yok", s)
		}
		if seen[name] {
			t.Errorf("%q iki durumda kullanılıyor", name)
		}
		seen[name] = true
	}
}

// fakeHead, kova ayağa kaldırmadan HEAD cevabı verir.
type fakeHead struct {
	meta map[string]string
	err  error
}

func (f fakeHead) Head(context.Context, string) (objstore.ObjectInfo, error) {
	if f.err != nil {
		return objstore.ObjectInfo{}, f.err
	}

	return objstore.ObjectInfo{Meta: f.meta}, nil
}

/*
 * ⚠️ ARŞİV KAPALIYKEN SONUÇ "BAKILMADI" — HATA DEĞİL.
 *
 * Arşivi açmamış bir kurulumda her doğrulamayı başarısız saymak, çalışan
 * bir kurulumu bozuk gösterirdi. Ama "onaylandı" da değil ve ayrımı
 * söylemek zorunda.
 */
func TestArchivingOffIsUncheckedNotFailure(t *testing.T) {
	got := OffBoxOf(context.Background(), nil, store.ArchiveState{}, false, "abc")
	if got.State != OffBoxUnchecked {
		t.Fatalf("durum = %v", got.State)
	}
	if !strings.Contains(got.Detail, "not configured") {
		t.Errorf("sebep söylenmiyor: %q", got.Detail)
	}
}

// Henüz yüklenmemiş kayıt da "bakılmadı" — ve sebebi FARKLI yazılmalı:
// arşivin kapalı olmasıyla kaydın sırasını beklemesi ayrı durumlar.
func TestNotYetArchivedSaysSo(t *testing.T) {
	got := OffBoxOf(context.Background(), fakeHead{}, store.ArchiveState{}, true, "abc")
	if got.State != OffBoxUnchecked {
		t.Fatalf("durum = %v", got.State)
	}
	if !strings.Contains(got.Detail, "not been archived") {
		t.Errorf("sebep: %q", got.Detail)
	}
}

/*
 * ⚠️ KOVAYA ULAŞILAMAMASI KURCALANMIŞLIK DEĞİL.
 *
 * Ağ arızasını "farklı baş" diye raporlamak, düşmüş bir güvenlik duvarını
 * bir olay müdahalesine çevirirdi.
 */
func TestUnreachableBucketIsNotAMismatch(t *testing.T) {
	got := OffBoxOf(context.Background(),
		fakeHead{err: errors.New("dial tcp: timeout")},
		store.ArchiveState{Archived: true, ObjectKey: "gun/x.cast"}, true, "abc")

	if got.State == OffBoxMismatch {
		t.Fatal("ulaşılamayan kova 'farklı baş' diye raporlandı")
	}
	if got.State != OffBoxUnchecked {
		t.Fatalf("durum = %v", got.State)
	}
	if !strings.Contains(got.Detail, "timeout") {
		t.Errorf("asıl sebep kayboldu: %q", got.Detail)
	}
}

func TestMatchAndMismatchFromRealMetadata(t *testing.T) {
	st := store.ArchiveState{Archived: true, Bucket: "kova", ObjectKey: "gun/x.cast"}

	ok := OffBoxOf(context.Background(),
		fakeHead{meta: map[string]string{objstore.MetaChain: "abc", objstore.MetaLinks: "4"}},
		st, true, "abc")
	if ok.State != OffBoxMatch {
		t.Errorf("aynı baş 'match' değil: %v", ok.State)
	}
	if ok.Object != "kova/gun/x.cast" {
		t.Errorf("nesnenin yeri = %q — olay müdahalesinde ilk sorulan şey", ok.Object)
	}

	bad := OffBoxOf(context.Background(),
		fakeHead{meta: map[string]string{objstore.MetaChain: "zzz", objstore.MetaLinks: "4"}},
		st, true, "abc")
	if bad.State != OffBoxMismatch {
		t.Errorf("farklı baş 'mismatch' değil: %v", bad.State)
	}
	if bad.Chain != "zzz" {
		t.Errorf("arşivdeki baş taşınmıyor: %q — 'olması gereken' oydu", bad.Chain)
	}
}
