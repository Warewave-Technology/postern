package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/verify"
)

/*
 * ⚠️ HER DURUM BİR SATIR YAZMALI — SESSİZLİK EN KÖTÜ ÇIKTI.
 *
 * "Bakılmadı" yazılmazsa okuyan kişi bakıldığını ve tuttuğunu varsayar,
 * ve bu varsayım tam olarak zincirin değerini abartan varsayım. Bir
 * olay müdahalesinde "kova onayladı" ile "kovaya bakamadım" arasındaki
 * fark, kararın kendisi kadar önemli.
 */
func TestEveryOffBoxStatePrintsALine(t *testing.T) {
	states := []struct {
		res  offBoxResult
		want string
	}{
		{offBoxResult{State: offBoxMatch, Object: "kova/anahtar"}, "CONFIRMS"},
		{offBoxResult{State: offBoxMismatch, Object: "kova/anahtar", Chain: "zzz", Links: "3"}, "DISAGREES"},
		{offBoxResult{State: offBoxNoChain, Detail: "eski nesne"}, "NO CHAIN"},
		{offBoxResult{State: offBoxUnchecked, Detail: "arşiv kapalı"}, "NOT CHECKED"},
	}

	for _, c := range states {
		var buf bytes.Buffer
		printOffBox(&buf, c.res)

		got := buf.String()
		if got == "" {
			t.Fatalf("%v durumu hiçbir şey yazmadı", c.res.State)
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("çıktı %q içermiyor: %q", c.want, got)
		}
		if !strings.HasSuffix(got, "\n") {
			t.Errorf("satır sonu yok: %q", got)
		}
	}
}

/*
 * Uyuşmazlıkta ARŞİVDEKİ baş yazılmalı: olay müdahalesindeki ilk soru
 * "olması gereken neydi" ve cevabı yalnızca kovada duruyor.
 */
func TestMismatchPrintsTheArchivedHead(t *testing.T) {
	var buf bytes.Buffer
	printOffBox(&buf, offBoxResult{
		State: offBoxMismatch, Object: "kayitlar/gun/x.cast",
		Chain: "beklenen-bas", Links: "11",
	})

	got := buf.String()
	for _, want := range []string{"beklenen-bas", "11", "kayitlar/gun/x.cast"} {
		if !strings.Contains(got, want) {
			t.Errorf("çıktıda %q yok: %q", want, got)
		}
	}
}

/*
 * ⚠️ "BAKILMADI" ASLA "ONAYLADI" GİBİ OKUNMAMALI.
 *
 * Dört durumun çıktısı birbirinden ayırt edilebilir olmalı; iki durum
 * aynı kelimeyi kullanırsa betik de insan da onları karıştırır.
 */
func TestOffBoxStatesAreDistinguishable(t *testing.T) {
	seen := map[string]verify.OffBoxState{}
	for _, st := range []verify.OffBoxState{offBoxMatch, offBoxMismatch, offBoxNoChain, offBoxUnchecked} {
		var buf bytes.Buffer
		printOffBox(&buf, offBoxResult{State: st, Detail: "x"})

		// İlk satırdaki durum etiketi.
		line := strings.TrimSpace(buf.String())
		label := line
		if i := strings.Index(line, "—"); i > 0 {
			label = strings.TrimSpace(line[:i])
		}
		if prev, dup := seen[label]; dup {
			t.Errorf("%v ile %v aynı etiketi yazıyor: %q", st, prev, label)
		}
		seen[label] = st
	}
}

/*
 * ⚠️ ARŞİVLENİP YERELDEN BUDANMIŞ KAYIT — bir saat önce inen kodda
 * bulunan kusurun testi.
 *
 * O hâlde `rs.Open` hata veriyordu ve komut kovadaki başa HİÇ BAKMADAN
 * düşüyordu. Arşivlemenin bütün amacı o kopyanın kalması; onu okumadan
 * pes etmek, özelliğin kendisini boşa çıkarıyordu.
 */
func TestPrunedRecordingStillConsultsTheArchive(t *testing.T) {
	var buf bytes.Buffer
	err := reportNoLocalCopy(&buf, "abc123", "deadbeef", 7, offBoxResult{
		State: offBoxMatch, Object: "kova/gun/abc123.cast",
	})
	if err != nil {
		t.Fatalf("başların tuttuğu durumda hata döndü: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "NO LOCAL COPY") {
		t.Errorf("yerel kopyanın yokluğu söylenmiyor: %q", got)
	}
	if !strings.Contains(got, "CONFIRMS") {
		t.Errorf("kovadaki kopyaya bakılmamış: %q", got)
	}
}

/*
 * ⚠️ EN ÖNEMLİ İDDİA: BU DURUM "DOĞRULANDI" DEMEK DEĞİL.
 *
 * Kovadaki baş veritabanındakiyle tutuyor olabilir, ama BAYTLAR BURADA
 * DEĞİL — dosyanın o başla tuttuğu hiç kontrol edilmedi. Çıktı "OK" ya da
 * "verified" derse, yapılmamış bir işi yapılmış gösterir ve denetçi
 * elindeki tek kanıtı fazla değerli sanır.
 */
func TestPrunedRecordingIsNotCalledVerified(t *testing.T) {
	var buf bytes.Buffer
	_ = reportNoLocalCopy(&buf, "abc123", "deadbeef", 7, offBoxResult{
		State: offBoxMatch, Object: "kova/x",
	})

	got := buf.String()
	for _, forbidden := range []string{"OK  ", "verified", "VERIFIED"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("çıktı %q içeriyor — baytlar kontrol edilmedi: %q", forbidden, got)
		}
	}
	// Ve ne yapılmadığını AÇIKÇA söylemeli.
	if !strings.Contains(got, "bytes were not checked") {
		t.Errorf("neyin yapılmadığı yazılmıyor: %q", got)
	}
}

// Kovadaki baş çelişiyorsa budanmış kayıt da BAŞARISIZ dönmeli.
func TestPrunedRecordingWithADisagreeingArchiveFails(t *testing.T) {
	var buf bytes.Buffer
	err := reportNoLocalCopy(&buf, "abc123", "deadbeef", 7, offBoxResult{
		State: offBoxMismatch, Object: "kova/x", Chain: "baska", Links: "7",
	})
	if !errors.Is(err, errArchiveDisagrees) {
		t.Fatalf("hata = %v, errArchiveDisagrees bekleniyordu", err)
	}
	if !strings.Contains(buf.String(), "archived head as the one to trust") {
		t.Errorf("hangisine güvenileceği yazılmıyor: %q", buf.String())
	}
}

/*
 * Kovaya bakılamadıysa budanmış kayıt için söylenecek hiçbir olumlu şey
 * yok: dosya da yok, kopya da okunamadı. Bu, sıfır çıkış kodu HAK
 * ETMEYEN tek "bakamadım" durumu.
 */
func TestPrunedRecordingWithNoArchiveAnswerFails(t *testing.T) {
	for _, st := range []verify.OffBoxState{offBoxUnchecked, offBoxNoChain} {
		var buf bytes.Buffer
		if err := reportNoLocalCopy(&buf, "abc", "d", 1,
			offBoxResult{State: st, Detail: "sebep"}); err == nil {
			t.Errorf("%v durumunda hata dönmedi — elde hiçbir kanıt yokken başarı", st)
		}
	}
}
