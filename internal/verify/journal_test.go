package verify

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/sftpaudit"
	"github.com/Warewave-Technology/postern/internal/sftpcast"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * rows, kayıtta karşılığı olan n satır üretir ve mühürlerini döner.
 *
 * ⚠️ MÜHÜR SATIRLARDAN HESAPLANIYOR, ELLE YAZILMIYOR. Uydurma bir özetle
 * yapılan test, kontrolün yazıcıyla aynı fikirde olduğunu ölçmez —
 * yalnızca kendi kendisiyle tutarlı olduğunu.
 */
func rows(n int) ([]store.SessionFile, string) {
	var (
		out  []store.SessionFile
		seal sftpcast.Seal
	)
	for i := range n {
		f := store.SessionFile{
			Op: "open", Path: fmt.Sprintf("/tmp/dosya-%d", i),
			OK: true, InRecording: true,
		}
		out = append(out, f)
		seal.Add(sftpcast.Line(sftpaudit.Event{
			Op: sftpaudit.Op(f.Op), Path: f.Path, OK: f.OK,
		}))
	}

	return out, seal.Head()
}

// closed, kapanmış bir oturum sarmalar: JournalOf oturumun SÜRÜP
// sürmediğini de soruyor (süren oturumda mühür henüz yazılmamıştır).
func closed(j model.SFTPJournal) model.Session {
	return model.Session{SFTPJournal: j, EndedAt: time.Now()}
}

/*
 * ⚠️ AYNI ARİTMETİK ÜÇ AYRI OLAY. "Satır sayısı mühürden eksik" cümlesi
 * postern'in kendi kaybından da çıkar, silinmiş satırlardan da. İkisini
 * ayırmayan bir kontrol ya her arızayı kurcalama diye bildirir ya da
 * gerçek bir müdahaleyi "bilinen kayıp" diye yutar.
 */
func TestJournalOfSeparatesLossFromTampering(t *testing.T) {
	for _, tc := range []struct {
		name string
		j    model.SFTPJournal
		rows int
		want JournalState
		ok   bool
	}{
		{
			name: "her olayın satırı var",
			j:    model.SFTPJournal{Measured: true, Events: 12},
			rows: 12, want: JournalIntact, ok: true,
		},
		{
			name: "hiç dosya olayı yok",
			j:    model.SFTPJournal{Measured: true},
			rows: 0, want: JournalIntact, ok: true,
		},
		{
			// postern kaybettiğini biliyor ve satır sayısı tam o kadar
			// eksik: kanıt eksik ama sebebi belli.
			name: "postern kendi kaybetti",
			j:    model.SFTPJournal{Measured: true, Events: 12, Lost: 3},
			rows: 9, want: JournalIncomplete, ok: false,
		},
		{
			// ⚠️ ASIL BULGU. Defterden satır silmek, kaydı yeniden yazıp
			// zinciri hesaplamaktan çok daha ucuz bir müdahale.
			name: "satırlar açıklanamayacak kadar az",
			j:    model.SFTPJournal{Measured: true, Events: 12},
			rows: 9, want: JournalMissing, ok: false,
		},
		{
			// Bilinen kaybın ÜSTÜNE silinmiş satırlar: bulgu, kaybın
			// arkasına saklanmamalı.
			name: "bilinen kaybın üstüne eksik satır",
			j:    model.SFTPJournal{Measured: true, Events: 12, Lost: 3},
			rows: 7, want: JournalMissing, ok: false,
		},
		{
			name: "mühürün saymadığı satırlar",
			j:    model.SFTPJournal{Measured: true, Events: 4},
			rows: 5, want: JournalExtra, ok: false,
		},
		{
			// ⚠️ ÖLÇÜLMEMİŞ OTURUM SUÇLANMIYOR. Göç öncesi kapanmış ve
			// kaydı hiç tutulmamış oturumlar burada; satırlarını
			// "fazlalık" diye raporlamak, ilk yükseltmede geçmişin
			// tamamını suçlamak olurdu.
			name: "ölçülmemiş oturum",
			j:    model.SFTPJournal{},
			rows: 40, want: JournalUnmeasured, ok: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, digest := rows(tc.rows)
			j := tc.j
			// ⚠️ ÖZET DOĞRU VERİLİYOR: bu testin ölçtüğü şey SAYIM.
			// Yanlış bir özetle beslemek, sayım bozulduğunda bile
			// "altered" alıp testi yeşil bırakabilirdi.
			if j.Measured && j.Events > 0 {
				j.Digest = digest
			}

			got := JournalOf(closed(j), files)

			if got.State != tc.want {
				t.Errorf("durum = %v, %v bekleniyordu (%s)", got.State, tc.want, got.Detail)
			}
			if got.State.OK() != tc.ok {
				t.Errorf("OK() = %v, %v bekleniyordu", got.State.OK(), tc.ok)
			}
			/*
			 * ⚠️ HER DURUMDA BİR CÜMLE. Boş bir gerekçe, paneldeki
			 * uyarıyı ve komutun çıktısını sessiz bırakırdı — ve sessiz
			 * bir denetim aracı "sorun yok" diye okunur.
			 */
			if strings.TrimSpace(got.Detail) == "" {
				t.Error("gerekçe boş")
			}
			if got.Rows != int64(tc.rows) || got.Events != tc.j.Events || got.Lost != tc.j.Lost {
				t.Errorf("sayılar taşınmadı: %+v", got)
			}
		})
	}
}

/*
 * ⚠️ "ÖLÇÜLMEDİ" CÜMLESİ ONAY GİBİ OKUNMAMALI.
 *
 * Bu, kontrolün en sık görülecek hâli: yükseltmeden önce kapanmış her
 * oturum burada. Cümle "tamam" derse, ilk günden itibaren yapılmamış
 * bir kontrol yapılmış sayılır.
 */
func TestUnmeasuredSaysWhyItCouldNotBeCompared(t *testing.T) {
	files, _ := rows(3)
	got := JournalOf(closed(model.SFTPJournal{}), files)

	if !strings.Contains(got.Detail, "no seal") {
		t.Errorf("gerekçe karşılaştırılamama sebebini söylemiyor: %q", got.Detail)
	}
	if got.State.String() != "unmeasured" {
		t.Errorf("durum dizgesi = %q", got.State.String())
	}
}

/*
 * ⚠️ SÜREN OTURUM "ESKİ" DEĞİL.
 *
 * Mühürdeki sayı kapanışta yazılıyor. Süren bir oturuma "kaydı yok ya
 * da bu sürümden önce kapandı" demek, panelde açık duran her oturum
 * için yanlış bir cümle olurdu — ve denetçiye olmayan bir eksiklik
 * gösterirdi.
 */
func TestOpenSessionIsNotReportedAsAnOldOne(t *testing.T) {
	files, _ := rows(2)
	got := JournalOf(model.Session{}, files)

	if got.State != JournalUnmeasured {
		t.Errorf("durum = %v", got.State)
	}
	if !strings.Contains(got.Detail, "still open") {
		t.Errorf("gerekçe süren oturumu anlatmıyor: %q", got.Detail)
	}
}

/*
 * ⚠️ ASIL YENİ İDDİA: SAYI TUTARKEN İÇERİK DEĞİŞTİRİLMİŞSE GÖRÜLÜR.
 *
 * Defterden satır silmek bir boşluk bırakıyor ve sayım onu görüyordu.
 * Bir satırı DEĞİŞTİRMEK — "/etc/shadow" yazan yolu "/tmp/notlar"
 * yapan bir UPDATE — hiçbir boşluk bırakmıyor: sayı tutuyor, liste tam
 * görünüyor, ve müdahale tam bir denetim kaydı gibi duruyor.
 */
func TestChangedRowIsSeenEvenWhenTheCountMatches(t *testing.T) {
	files, digest := rows(3)

	// Kayıt kapandıktan sonra bir yol değiştiriliyor; satır sayısı aynı.
	files[1].Path = "/tmp/masum"

	got := JournalOf(closed(model.SFTPJournal{
		Measured: true, Events: 3, Digest: digest,
	}), files)

	if got.State != JournalAltered {
		t.Fatalf("DEĞİŞTİRİLMİŞ SATIR GÖRÜLMEDİ: durum = %v (%s)", got.State, got.Detail)
	}
	if got.Rows != 3 {
		t.Errorf("sayım = %d — kurgu tutmadı, ölçülen şey özet değil", got.Rows)
	}
	if !got.DigestChecked {
		t.Error("özet karşılaştırıldı ama sonuç öyle demiyor")
	}
	if got.State.OK() {
		t.Error("değiştirilmiş defter OK sayıldı")
	}
}

/*
 * ⚠️ ÖZETİ HİÇ KARŞILAŞTIRILMAMIŞ BİR OTURUM, KARŞILAŞTIRILMIŞ GİBİ
 * GÖRÜNMEMELİ.
 *
 * Mühürde özet olmayan oturumlar var (sayı yazılmaya özetten önce
 * başlandı). Onlar için söylenebilecek şey "sayısı tuttu"; "içeriği de
 * tuttu" DEĞİL. İkisini aynı cümleye koymak, yapılmamış bir kontrolü
 * yapılmış saymak olurdu — bu depodaki tekrar eden hata.
 */
func TestIntactSaysWhetherTheDigestWasChecked(t *testing.T) {
	files, digest := rows(2)

	withDigest := JournalOf(closed(model.SFTPJournal{
		Measured: true, Events: 2, Digest: digest,
	}), files)
	if !withDigest.DigestChecked {
		t.Error("özet varken karşılaştırılmadı")
	}
	if !strings.Contains(withDigest.Detail, "digest matches") {
		t.Errorf("gerekçe özetin tuttuğunu söylemiyor: %q", withDigest.Detail)
	}

	noDigest := JournalOf(closed(model.SFTPJournal{
		Measured: true, Events: 2,
	}), files)
	if noDigest.State != JournalIntact {
		t.Errorf("özetsiz oturum suçlandı: %v", noDigest.State)
	}
	if noDigest.DigestChecked {
		t.Error("YAPILMAMIŞ KONTROL YAPILMIŞ SAYILDI: mühürde özet yokken tutmuş görünüyor")
	}
	if !strings.Contains(noDigest.Detail, "not checked") {
		t.Errorf("gerekçe, içeriğin kontrol edilmediğini söylemiyor: %q", noDigest.Detail)
	}
}

/*
 * ⚠️ SATIR EKSİKKEN ÖZET SORULMUYOR. Eksik satırın özeti zaten tutmaz;
 * onu "içerik de değiştirilmiş" diye raporlamak, tek bir arızayı iki
 * bulguya bölerdi ve ikincisi yanlış olurdu.
 */
func TestMissingRowsAreNotAlsoReportedAsAltered(t *testing.T) {
	files, digest := rows(5)

	got := JournalOf(closed(model.SFTPJournal{
		Measured: true, Events: 6, Digest: digest,
	}), files)

	if got.State != JournalMissing {
		t.Errorf("durum = %v, missing bekleniyordu", got.State)
	}
	if got.DigestChecked {
		t.Error("eksik defterde özet karşılaştırılmış gibi raporlandı")
	}
}

/*
 * ⚠️ KANAL DÜZEYİNDEKİ RET SATIRI NE SAYIMA NE ÖZETE GİRMELİ.
 *
 * Bu satırları ret defteri yazıyor (proxy/lifecycle.go) ve kayıtta
 * karşılıkları YOK. Özete katılsalardı, x11 isteği reddedilmiş dokunulmamış
 * bir oturum "içeriği değiştirilmiş" diye raporlanırdı — yani kontrol,
 * doğru çalışan bir bastion'ı suçlardı.
 */
func TestChannelDenialsStayOutOfBothSums(t *testing.T) {
	files, digest := rows(2)
	files = append(files, store.SessionFile{
		Op: "denied.x11-req", OK: false, Detail: "x11 forwarding is off",
	})

	got := JournalOf(closed(model.SFTPJournal{
		Measured: true, Events: 2, Digest: digest,
	}), files)

	if got.State != JournalIntact {
		t.Errorf("YANLIŞ ALARM: durum = %v (%s)", got.State, got.Detail)
	}
	if got.Rows != 2 {
		t.Errorf("sayım = %d, 2 bekleniyordu", got.Rows)
	}
}
