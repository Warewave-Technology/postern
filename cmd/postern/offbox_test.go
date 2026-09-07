package main

import (
	"bytes"
	"strings"
	"testing"
)

/*
 * ⚠️ ZİNCİRİN ASIL DEĞERİ BU KARARDA.
 *
 * Yereldeki baş veritabanında, kayıt diskte; bastion'da root olan İKİSİNİ
 * DE yeniden yazabilir ve doğrulama yine "OK" der. Kovadaki kopya o
 * makinenin ulaşamadığı yer, ve bugüne kadar yazılıyor ama HİÇ
 * OKUNMUYORDU. Buradaki testler o okumanın ne söylediğini çiviliyor.
 */

func TestOffBoxVerdictSeparatesThreeCases(t *testing.T) {
	cases := []struct {
		name             string
		archived, want   string
		state            offBoxState
		detailMustSaySth bool
	}{
		{"aynı baş", "abc", "abc", offBoxMatch, false},
		{"farklı baş", "zzz", "abc", offBoxMismatch, false},
		/*
		 * ⚠️ "ZİNCİR YOK" İLE "FARKLI ZİNCİR" AYRI DURUMLAR. Birleştirmek,
		 * zincirlerden önce yüklenmiş ya da üstverisi düşürülmüş bir
		 * kaydı kurcalanmış diye suçlamak olurdu — ve o suçlama
		 * geri alınamaz bir olay müdahalesi başlatır.
		 */
		{"zincir yok", "", "abc", offBoxNoChain, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, detail := offBoxVerdict(c.archived, c.want)
			if state != c.state {
				t.Errorf("durum = %v, %v bekleniyordu", state, c.state)
			}
			if c.detailMustSaySth && detail == "" {
				t.Error("sebep yazılmamış: kullanıcı neden bakılamadığını bilmeli")
			}
		})
	}
}

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
		{offBoxResult{state: offBoxMatch, object: "kova/anahtar"}, "CONFIRMS"},
		{offBoxResult{state: offBoxMismatch, object: "kova/anahtar", chain: "zzz", links: "3"}, "DISAGREES"},
		{offBoxResult{state: offBoxNoChain, detail: "eski nesne"}, "NO CHAIN"},
		{offBoxResult{state: offBoxUnchecked, detail: "arşiv kapalı"}, "NOT CHECKED"},
	}

	for _, c := range states {
		var buf bytes.Buffer
		printOffBox(&buf, c.res)

		got := buf.String()
		if got == "" {
			t.Fatalf("%v durumu hiçbir şey yazmadı", c.res.state)
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
		state: offBoxMismatch, object: "kayitlar/gun/x.cast",
		chain: "beklenen-bas", links: "11",
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
	seen := map[string]offBoxState{}
	for _, st := range []offBoxState{offBoxMatch, offBoxMismatch, offBoxNoChain, offBoxUnchecked} {
		var buf bytes.Buffer
		printOffBox(&buf, offBoxResult{state: st, detail: "x"})

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
