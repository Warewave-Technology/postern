package record

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// jsonSafe, bir bayt dizisinin asciicast olay yükünde NASIL görüneceğini
// bağımsız olarak modeller: encoding/json geçersiz her UTF-8 baytını tek bir
// U+FFFD'ye çevirir, []rune dönüşümü de aynısını yapar. Referansı elle
// yazmıyoruz — dilin kendi çözücüsünü kullanıyoruz ki "kod ne yapıyorsa doğru
// odur" tuzağına düşmeyelim.
func jsonSafe(b []byte) string {
	return string(bytes.Runes(b))
}

// chunkBytes, splits baytlarını "TCP paketleri nereye düştü" senaryosuna
// çevirir. Hedeften gelen çıktının parça sınırları tamamen ağın insafındadır;
// fuzzer'ın görevi de o sınırları rastgele gezdirmek.
func chunkBytes(data, splits []byte) [][]byte {
	chunks := make([][]byte, 0, len(splits)+1)
	rest := data

	for _, s := range splits {
		if len(rest) == 0 {
			break
		}

		// +1: sıfır uzunluklu parça da meşru bir okuma sonucudur, onu da üret.
		n := int(s) % (len(rest) + 1)
		chunks = append(chunks, rest[:n])
		rest = rest[n:]
	}

	if len(rest) != 0 {
		chunks = append(chunks, rest)
	}

	return chunks
}

// collectOutput, parçaları tek bir Writer'a sırayla yazar, kapatır ve üretilen
// "o" olaylarının yüklerini döndürür.
func collectOutput(t *testing.T, chunks [][]byte) []string {
	t.Helper()

	sink := &nopCloser{}

	w, err := NewWriter(sink, 80, 24, nil)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	for i, c := range chunks {
		if err := w.Output(c); err != nil {
			t.Fatalf("Output parça %d (%x): %v", i, c, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, events := parseCast(t, sink.String())

	payloads := make([]string, 0, len(events))
	for _, ev := range events {
		kind, data := eventData(t, ev)
		if kind != "o" {
			t.Fatalf("olay tipi %q — yalnızca Output çağrıldı", kind)
		}
		payloads = append(payloads, data)
	}

	return payloads
}

// FuzzWriterChunking pins chunk invariance: the recording must not depend on
// where the network happened to cut the target's output.
//
// ⚠️ splitIncompleteUTF8'in VAROLUŞ SEBEBİ bu: aynı baytlar tek seferde de,
// bayt bayt da gelse kaydedilen akış aynı olmalı. Aksi halde bir oturumun
// kaydı, denetim kanıtı olarak, ağın o anki paketlemesine bağlı hale gelir.
func FuzzWriterChunking(f *testing.F) {
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("merhaba dünya"), []byte{3})
	f.Add([]byte("değişti"), []byte{3, 1})
	f.Add([]byte("değişti"), []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	f.Add([]byte("\x1b[?1034h\"tırnak\" ve \\ters\t\n"), []byte{5, 2, 9})
	f.Add([]byte{0xC4}, []byte{})                  // yarım "ğ", devamı hiç gelmiyor
	f.Add([]byte{0xE2, 0x82, 0xAC}, []byte{1, 1})  // "€" üç parçaya bölünmüş
	f.Add([]byte("😀ğ€"), []byte{1, 1, 1, 1, 1, 1}) // dört baytlı rune bayt bayt
	f.Add([]byte{0xCA, 0xFE, 0xBA, 0xBE}, []byte{2})
	f.Add([]byte{0xFF, 0xFE, 0x00, 0x80, 0x41}, []byte{1, 1, 1, 1})
	f.Add([]byte{0xF0, 0x80, 0x80, 0x80, 0x80}, []byte{2})

	f.Fuzz(func(t *testing.T, data, splits []byte) {
		whole := collectOutput(t, [][]byte{data})
		chunks := chunkBytes(data, splits)
		pieces := collectOutput(t, chunks)

		joinedWhole := strings.Join(whole, "")
		joinedPieces := strings.Join(pieces, "")

		// ASIL ÖZELLİK: parçalama olay SINIRLARINI değiştirebilir, ama
		// birleştirilmiş yükü ASLA değiştiremez.
		if joinedWhole != joinedPieces {
			t.Fatalf("parça sınırı kaydı değiştirdi:\n  tek çağrı = %q\n  %d parça  = %q\n  parçalar  = %x",
				joinedWhole, len(chunks), joinedPieces, chunks)
		}

		// Diferansiyel: kaydedilen akış, dilin kendi UTF-8 çözücüsünün aynı
		// baytlar için ürettiği string'e eşit olmalı. Bu, "sadakat" iddiasını
		// ölçülebilir hale getirir — ve nerede kaybettiğimizi de gösterir.
		if want := jsonSafe(data); joinedPieces != want {
			t.Fatalf("kaydedilen akış referans çözücüden ayrıştı:\n  kayıt    = %q\n  referans = %q\n  girdi    = %x",
				joinedPieces, want, data)
		}

		// Sadakat YALNIZCA geçerli UTF-8 için iddia edilebilir: geçersiz
		// baytlar JSON string'ine sığmaz, U+FFFD olur (aşağıdaki pin testine bak).
		if utf8.Valid(data) && joinedPieces != string(data) {
			t.Fatalf("geçerli UTF-8 bozuldu: kayıt = %q, girdi = %q", joinedPieces, string(data))
		}

		// Oynatıcılar olay yükünü JSON string'i olarak okur; her yük tek
		// başına geçerli UTF-8 olmalı, yoksa .cast dosyası ayrıştırılamaz.
		for i, p := range pieces {
			if !utf8.ValidString(p) {
				t.Fatalf("olay %d geçerli UTF-8 değil: %q", i, p)
			}
		}
	})
}

// FuzzSplitIncompleteUTF8 asserts the contract the buffering layer relies on:
// the split is lossless, order-preserving, and the trailing part is exactly a
// truncated rune — never more.
//
// ⚠️ len(trailing) sınırı gevşerse tampon oturum boyunca büyür ve bir bayt,
// devamı hiç gelmediğinde Close'a kadar kayıtta görünmez.
func FuzzSplitIncompleteUTF8(f *testing.F) {
	f.Add([]byte("merhaba"))
	f.Add([]byte("değişti"))
	f.Add([]byte{'d', 'e', 0xC4})
	f.Add([]byte{'a', 0xE2, 0x82})
	f.Add([]byte{0xC5})
	f.Add([]byte(nil))
	f.Add([]byte{0x80, 0x80, 0x80, 0x80, 0x80})
	f.Add([]byte{0xF0, 0x9F, 0x98})
	f.Add([]byte("😀"))
	f.Add([]byte{0xFF, 0xFE})

	f.Fuzz(func(t *testing.T, b []byte) {
		complete, trailing := splitIncompleteUTF8(b)

		// Kayıpsızlık: hiçbir bayt düşmez, sıra değişmez, bayt uydurulmaz.
		rejoined := make([]byte, 0, len(complete)+len(trailing))
		rejoined = append(rejoined, complete...)
		rejoined = append(rejoined, trailing...)

		if !bytes.Equal(rejoined, b) {
			t.Fatalf("bölme kayıplı: complete=%x trailing=%x, girdi=%x", complete, trailing, b)
		}

		// En uzun rune 4 bayt; tam rune zaten complete'e gider, dolayısıyla
		// kuyrukta en fazla 3 bayt kalabilir.
		if len(trailing) > 3 {
			t.Fatalf("kuyruk %d bayt (>3): %x, girdi=%x", len(trailing), trailing, b)
		}

		if len(trailing) == 0 {
			return
		}

		// Kuyruk yalnızca "başlamış ama bitmemiş rune" olabilir. Devam baytıyla
		// başlıyorsa sınır yanlış yerden geçmiştir; tam rune ise beklemeye
		// hiç gerek yoktu ve olay boş yere gecikir.
		if !utf8.RuneStart(trailing[0]) {
			t.Fatalf("kuyruk devam baytıyla başlıyor: %x, girdi=%x", trailing, b)
		}

		if utf8.FullRune(trailing) {
			t.Fatalf("kuyrukta TAM rune bekletiliyor: %x, girdi=%x", trailing, b)
		}
	})
}

// FuzzWriterStreamSeparation asserts that the "o" and "i" buffers never bleed
// into each other, whatever order the two brokers' goroutines write in.
//
// ⚠️ Bu bir güvenlik bağlantısı: girdi kaydı kullanıcının yazdığı her şeyi —
// sudo parolası dahil — taşır. Bir girdi baytının "o" olayına düşmesi,
// record_input:false ile kapatılmış bir kaydın parola sızdırması demektir.
func FuzzWriterStreamSeparation(f *testing.F) {
	f.Add([]byte("çıktı"), []byte("gizli parola\r"), []byte{2, 3, 1})
	f.Add([]byte{0xC4}, []byte{0xC5}, []byte{1, 1})
	f.Add([]byte("değişti"), []byte("ls -la\r"), []byte{1, 1, 1, 1, 1, 1, 1, 1})
	f.Add([]byte(""), []byte("sudo\r"), []byte{})
	f.Add([]byte{0xE2, 0x82, 0xAC}, []byte{0xF0, 0x9F, 0x98, 0x80}, []byte{3, 3, 3, 3})

	f.Fuzz(func(t *testing.T, out, in, interleave []byte) {
		sink := &nopCloser{}

		w, err := NewWriter(sink, 80, 24, nil)
		if err != nil {
			t.Fatalf("NewWriter: %v", err)
		}

		outRest, inRest := out, in
		for _, step := range interleave {
			// En düşük bit akışı, kalanı parça boyunu seçer.
			target := &outRest
			write := w.Output

			if step&1 == 1 {
				target = &inRest
				write = w.Input
			}

			n := int(step>>1) % (len(*target) + 1)
			if err := write((*target)[:n]); err != nil {
				t.Fatalf("yazma: %v", err)
			}
			*target = (*target)[n:]
		}

		if err := w.Output(outRest); err != nil {
			t.Fatalf("kalan çıktı: %v", err)
		}
		if err := w.Input(inRest); err != nil {
			t.Fatalf("kalan girdi: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		_, events := parseCast(t, sink.String())

		var gotOut, gotIn strings.Builder
		for _, ev := range events {
			kind, data := eventData(t, ev)
			switch kind {
			case "o":
				gotOut.WriteString(data)
			case "i":
				gotIn.WriteString(data)
			default:
				t.Fatalf("beklenmeyen olay tipi %q", kind)
			}
		}

		if want := jsonSafe(out); gotOut.String() != want {
			t.Fatalf("çıktı akışı bozuldu: got=%q want=%q (girdi akışı=%x)", gotOut.String(), want, in)
		}
		if want := jsonSafe(in); gotIn.String() != want {
			t.Fatalf("girdi akışı bozuldu: got=%q want=%q (çıktı akışı=%x)", gotIn.String(), want, out)
		}
	})
}

// Paket doküman yorumu "ham bayt akışını saklıyoruz" diyor. İkili çıktı için
// bu İDDİA YANLIŞ: olay yükü bir JSON string'i ve encoding/json geçersiz her
// UTF-8 baytını U+FFFD ile değiştirir. Bu test ölçülen davranışı sabitler —
// hedefte 'cat /bin/ls' çalıştıran bir oturumun kaydı sadık DEĞİLDİR ve o
// kayıttan orijinal baytlar geri elde edilemez.
func TestWriterReplacesInvalidUTF8Bytes(t *testing.T) {
	out := &nopCloser{}

	w, err := NewWriter(out, 80, 24, nil)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	raw := []byte{0xCA, 0xFE, 0xBA, 0xBE} // ikili dosya sihirli sayısı
	if err := w.Output(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	_, events := parseCast(t, out.String())
	if len(events) != 1 {
		t.Fatalf("olay sayısı = %d, beklenen 1", len(events))
	}

	_, data := eventData(t, events[0])

	const want = "\uFFFD\uFFFD\uFFFD\uFFFD"
	if data != want {
		t.Fatalf("yük = %q, ölçülen davranış %q idi", data, want)
	}

	if data == string(raw) {
		t.Fatal("baytlar sadık kaydedilmiş — doküman iddiası artık doğru, bu test güncellenmeli")
	}

	// Kayıp somut: 4 bayt girdi, geri okunduğunda 12 bayt U+FFFD.
	if len(data) != 12 {
		t.Fatalf("geri okunan yük %d bayt, beklenen 12 (4 × U+FFFD)", len(data))
	}
}
