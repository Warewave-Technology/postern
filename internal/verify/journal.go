package verify

// Defter ile kaydın karşılaştırılması: "bu oturumun dosya olayları
// eksiksiz mi".

import (
	"fmt"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/sftpaudit"
	"github.com/Warewave-Technology/postern/internal/sftpcast"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * JournalState, defterin kaydın mührüyle tutup tutmadığı.
 *
 * ⚠️ NEDEN BEŞ DURUM, "TAMAM/DEĞİL" DEĞİL. Aynı aritmetik (satır sayısı
 * mühürden eksik) üç bambaşka olaydan çıkabiliyor: postern'in kendi
 * kaybı, sonradan silinmiş satırlar, ve hiç ölçülmemiş bir oturum.
 * İkiye indirgeyen bir cevap ya eski oturumların tamamını suçlar ya da
 * gerçek bir kaybı "geçti" diye yutar.
 */
type JournalState int

const (
	/*
	 * JournalUnmeasured, karşılaştırılacak bir sayı YOK.
	 *
	 * ⚠️ "GEÇTİ" DEĞİL. Göç 037'den önce kapanmış oturumlarda ve kaydı
	 * hiç tutulmamış oturumlarda mühür satırı yok; onları tamam
	 * göstermek, hiç yapılmamış bir kontrolü yapılmış saymak olurdu.
	 * Zincirin "baş yok → doğrulanamaz" kararının aynısı.
	 */
	JournalUnmeasured JournalState = iota

	// JournalIntact, mühürdeki her olayın defterde bir satırı var.
	JournalIntact

	/*
	 * JournalIncomplete, postern olayları KENDİ kaybetti ve bunu
	 * biliyor: satır sayısı, kaybettiğini söylediği kadar eksik.
	 *
	 * Kanıt yine eksik — ama sebebi belli ve müdahale değil.
	 */
	JournalIncomplete

	/*
	 * JournalMissing, satırlar postern'in kaybıyla AÇIKLANAMAYACAK
	 * kadar eksik.
	 *
	 * ⚠️ BU, DEFTERDEN SATIR SİLİNDİĞİNİN İŞARETİ. Kaydı yeniden yazan
	 * biri zinciri de yeniden hesaplar (SECURITY.md); ama defterden bir
	 * satır silmek çok daha ucuz bir müdahale ve bugüne kadar hiçbir
	 * şey onu görmüyordu.
	 */
	JournalMissing

	/*
	 * JournalAltered, satır sayısı tutuyor ama satırların ÖZETİ
	 * tutmuyor: en az bir satırın içeriği, kayıttaki karşılığından
	 * farklı.
	 *
	 * ⚠️ SİLMEKTEN DAHA İNCE BİR MÜDAHALE. Silinen satır hiç değilse
	 * bir boşluk bırakıyor ve sayım onu görüyor; değiştirilen bir satır
	 * — "/etc/shadow" yerine "/tmp/notlar" yazan bir UPDATE — tam bir
	 * denetim kaydı gibi duruyor. Sayıya bakan bir kontrol bunu
	 * göremez, ve göremediği için de "defter tam" der.
	 */
	JournalAltered

	/*
	 * JournalExtra, defterde mühürün saymadığından FAZLA satır var.
	 *
	 * ⚠️ SESSİZ GEÇİLMİYOR. Bugün bunun bilinen bir yolu yok: kayda
	 * girmeyen satırlar (kanal düzeyindeki retler) zaten sayıma
	 * girmiyor. Yani bu ya uydurulmuş satır ya da postern'in kendi
	 * muhasebesindeki bir arıza — ikisi de duyurulmayı hak ediyor.
	 */
	JournalExtra
)

func (s JournalState) String() string {
	switch s {
	case JournalIntact:
		return "intact"
	case JournalIncomplete:
		return "incomplete"
	case JournalMissing:
		return "missing"
	case JournalAltered:
		return "altered"
	case JournalExtra:
		return "extra"
	default:
		return "unmeasured"
	}
}

/*
 * OK, denetçiye "bu oturumda arayacak bir şey yok" denebilir mi.
 *
 * ⚠️ Unmeasured OK SAYILIYOR ve sınırı çağıran SÖYLEMEK ZORUNDA: hiç
 * yapılmamış bir kontrol bir bulgu değildir, ama onay da değildir. Bu
 * yüzden Detail her durumda dolu.
 */
func (s JournalState) OK() bool {
	return s == JournalUnmeasured || s == JournalIntact
}

// JournalResult, karşılaştırmanın sonucu ve onu üreten sayılar.
//
// Sayılar dışarı çıkıyor çünkü olay müdahalesinin sorusu "kaç satır"
// değil "hangi satırlar": kaç tanesinin eksik olduğunu bilmeden, kaydı
// açıp hangi olayların defterde karşılığı olmadığını aramak mümkün değil.
type JournalResult struct {
	State JournalState
	// Events, kaydın mühür satırındaki olay sayısı.
	Events int64
	// Rows, defterde DURAN, kayıtta da karşılığı olan satır sayısı.
	Rows int64
	// Lost, postern'in kaybettiğini bildiği olay sayısı.
	Lost int64

	/*
	 * DigestChecked, satırların ÖZETİNİN karşılaştırıldığı.
	 *
	 * ⚠️ ÇIKTIDA SÖYLENMEK ZORUNDA. Sayı tutan ama özeti hiç
	 * karşılaştırılmamış bir oturum ile ikisi de tutan bir oturum aynı
	 * "OK"u alırsa, yapılmamış bir kontrol yapılmış sayılır. Özet
	 * yalnızca satır sayısı beklenenle aynıyken ve mühürde bir özet
	 * varken karşılaştırılabiliyor.
	 */
	DigestChecked bool
	// Detail, sonucun tek cümlelik ve iddiasını aşmayan gerekçesi.
	Detail string

	/*
	 * Summary, karşılaştırılan iki sayının cümlesi. Ölçülmemiş oturumda
	 * BOŞ: karşılaştırılan bir şey yok.
	 *
	 * ⚠️ CÜMLE BURADA KURULUYOR, ÇAĞIRANLARDA DEĞİL. İki yüzey de aynı
	 * sayıları yazıyor (`postern session verify` ve panel); metni iki
	 * yerde kurmak, tekil/çoğul gibi ufak farkların aynı oturum için
	 * iki farklı cümleye dönüşmesi demekti.
	 */
	Summary string
}

// plural, sayıyı adıyla birlikte yazar: "1 row", "3 rows".
//
// ⚠️ Denetim çıktısında "1 rows" ucuz görünür ama okuyan kişiye
// metnin elle kontrol edilmediğini söyler — ve bu, aynı çıktının
// söylediği her şeye duyulan güveni azaltır.
func plural(n int64, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}

	return fmt.Sprintf("%d %ss", n, noun)
}

/*
 * JournalOf, kaydın mührünü defterdeki satırlarla karşılaştırır: hem
 * SAYIYI hem satırların ÖZETİNİ.
 *
 * ⚠️ KARAR TEK YERDE, ÇÜNKÜ İKİ YÜZEY SORUYOR: `postern session verify`
 * ve panelin oturum ayrıntısı ucu. İki ayrı uygulama ayrışır ve
 * ayrıştıkları gün ortaya çıkan şey, aynı oturum için farklı iki cevap
 * veren bir denetim aracı olur — OffBox kararının burada durmasının
 * gerekçesinin aynısı.
 *
 * ⚠️ İKİ SORU, İKİ AYRI MÜDAHALE. Sayı "kaç satır" diyor ve SİLMEYİ
 * yakalıyor; özet "hangi satırlar" diyor ve DEĞİŞTİRMEYİ yakalıyor.
 * Yalnızca sayıya bakan bir kontrol, "/etc/shadow" yazan bir satırı
 * "/tmp/notlar" yapan bir UPDATE'i göremez — ve göremediği için de
 * "defter tam" der.
 *
 * ⚠️ XOR'UN BEDELİ BURADA KAPANIYOR. Özet sıradan bağımsız olsun diye
 * XOR'lanıyor (bkz. sftpcast.Seal) ve bunun bedeli, aynı satırdan çift
 * sayıda silmenin özeti değiştirmemesi. Sayı tam da onu görüyor: çift
 * silme sayıyı iki azaltır. İkisinden birini atmak, ötekinin
 * yakalayamadığını görünmez yapar.
 *
 * ⚠️ NE KANITLAR, NE KANITLAMAZ. Karşılaştırılan iki değer de bu
 * makinenin veritabanından geliyor; burada root olan biri satırları,
 * sayıyı ve özeti birlikte yeniden yazabilir. Kapatılan açık daha dar
 * ve gerçek: defterden satır silmek ya da bir yolu değiştirmek, kaydı
 * yeniden yazıp zinciri hesaplamaktan çok daha ucuz bir müdahale ve
 * bugüne kadar hiçbir şey onu görmüyordu. Mühür satırının kendisi
 * kaydın içinde duruyor ve zincir onu kapsıyor — yani karşılaştırılan
 * değerlerin kutu dışı bir kopyası da var.
 */
func JournalOf(sess model.Session, files []store.SessionFile) JournalResult {
	j := sess.SFTPJournal

	/*
	 * ⚠️ SAYIM VE ÖZET AYNI DÖNGÜDEN ÇIKIYOR, ve süzgeç ikisi için de
	 * aynı. Ayrı yerlerde süzülselerdi biri kanal düzeyindeki ret
	 * satırlarını sayıp öteki saymayabilirdi — ve o hâlde özet, hiç
	 * kurcalanmamış bir oturumda tutmazdı.
	 *
	 * in_recording ŞART: bu listeye ret defteri de yazıyor
	 * (proxy/lifecycle.go, `denied.<istek türü>`) ve o satırların
	 * kayıtta karşılığı yok.
	 */
	var (
		rows int64
		seal sftpcast.Seal
	)
	for _, f := range files {
		if !f.InRecording {
			continue
		}
		rows++
		seal.Add(sftpcast.Line(eventOf(f)))
	}

	out := JournalResult{Events: j.Events, Rows: rows, Lost: j.Lost}

	if !j.Measured {
		out.State = JournalUnmeasured
		/*
		 * ⚠️ SÜREN OTURUM AYRI BİR CÜMLE HAK EDİYOR. Sayı kapanışta
		 * yazılıyor; süren bir oturuma "kaydı yok ya da eski" demek,
		 * panelde açık duran her oturum için yanlış bir cümle olurdu —
		 * zincir cevabındaki "in_progress" ayrımının aynısı.
		 */
		if sess.Open() {
			out.Detail = "the session is still open; the sealed event count is " +
				"written when it closes"

			return out
		}
		out.Detail = "this session has no seal to compare the journal against — " +
			"it closed before postern counted them, or it was not recorded"

		return out
	}

	/*
	 * ⚠️ TABAN SIFIR. Measured iken Lost'un Events'i aşması mümkün
	 * değil (kaybedilen her olay kayda çoktan yazılmıştı), ama tutarsız
	 * bir satırda eksi bir "beklenen" üretip onu "fazla satır var" diye
	 * raporlamak, arızayı yanlış yöne çevirirdi.
	 */
	expected := j.Events - j.Lost
	if expected < 0 {
		expected = 0
	}

	out.Summary = fmt.Sprintf("%s in the recording's seal, %s in the journal",
		plural(j.Events, "event"), plural(rows, "row"))

	switch {
	case rows < expected:
		out.State = JournalMissing
		out.Detail = fmt.Sprintf(
			"the journal has no row for %s the recording's seal counts",
			plural(expected-rows, "event"))
		if j.Lost > 0 {
			/*
			 * ⚠️ BİLİNEN KAYIP AYRICA YAZILIYOR. İkisi aynı oturumda
			 * olabilir ve toplamı tek bir sayıya indirmek, postern'in
			 * kendi arızasını müdahalenin üstüne yıkardı.
			 */
			out.Detail += fmt.Sprintf(", on top of the %s postern says it lost",
				plural(j.Lost, "event"))
		}

	case rows > expected:
		out.State = JournalExtra
		out.Detail = "the journal holds rows the recording's seal does not count, " +
			"and postern has no path that writes a row without recording it"

	case j.Lost > 0:
		out.State = JournalIncomplete
		out.Detail = fmt.Sprintf(
			"postern could not write %s this session produced, so the journal is "+
				"short by that many; what is left could not be checked against "+
				"the seal's digest, and the events are in the recording",
			plural(j.Lost, "file event"))

	/*
	 * ⚠️ ÖZET YALNIZCA SAYI TUTARKEN SORULUYOR. Eksik ya da fazla
	 * satırın özeti zaten tutmaz; onu "içerik değiştirilmiş" diye
	 * raporlamak, tek bir arızayı iki bulguya bölerdi ve ikincisi
	 * yanlış olurdu.
	 *
	 * ⚠️ MÜHÜRDE ÖZET YOKSA KONTROL ÇALIŞMIYOR VE BUNU SÖYLÜYOR:
	 * DigestChecked false kalıyor. Özet sonradan eklendi; ondan önce
	 * kapanmış ama sayısı yazılmış bir oturum "sayısı tuttu" diyebilir,
	 * "içeriği de tuttu" diyemez.
	 */
	case j.Digest != "" && j.Digest != seal.Head():
		out.State = JournalAltered
		out.DigestChecked = true
		out.Detail = "the rows are all there but their digest does not match the " +
			"recording: at least one row's contents were changed after it was written"

	case j.Events == 0:
		/*
		 * ⚠️ "HİÇ OLAY YOK" AYRI BİR CÜMLE. Sıfırı diğerleriyle aynı
		 * kalıba sokmak ("all 0 file events have a row") kontrolün
		 * çalıştığını değil, saçmaladığını düşündürür — ve bu, SFTP
		 * hiç kullanılmamış her kabuk oturumunda görülecek cümle.
		 */
		out.State = JournalIntact
		out.Detail = "this session moved no files over SFTP, and the journal " +
			"holds no rows for it"

	case j.Digest == "":
		out.State = JournalIntact
		out.Detail = fmt.Sprintf(
			"every one of the %s the recording's seal counts has a row in the "+
				"journal; the seal carried no digest, so what those rows SAY was "+
				"not checked",
			plural(j.Events, "file event"))

	default:
		out.State = JournalIntact
		out.DigestChecked = true
		out.Detail = fmt.Sprintf(
			"every one of the %s the recording's seal counts has a row in the "+
				"journal, and their digest matches the recording",
			plural(j.Events, "file event"))
	}

	return out
}

/*
 * eventOf, bir defter satırını kayda yazılmış olayına geri çevirir.
 *
 * ⚠️ BU DÖNÜŞÜM KONTROLÜN KALBİ: satırın kayıttaki karşılığını YENİDEN
 * ÜRETİYOR. Satır zaten bir olayın kalıcılaşmış hâli — kolonlar
 * sftpaudit.Event'in alanlarından bire bir doldurulmuştu
 * (proxy/sftpjournal.go) — ve sftpcast.Line ikisinde de aynı baytları
 * üretiyor.
 *
 * ⚠️ At VE Flags TAŞINMIYOR ÇÜNKÜ SATIRA GİRMİYORLAR. Taşımak zararsız
 * görünür ama yanıltıcı olurdu: buradaki alanların hepsi mühüre giriyor
 * izlenimi verirdi ve biri bir gün Line'a zaman damgası eklemek
 * istediğinde, o eklemenin eski kayıtları doğrulanamaz kıldığını
 * kimse fark etmezdi.
 */
func eventOf(f store.SessionFile) sftpaudit.Event {
	return sftpaudit.Event{
		Op:      sftpaudit.Op(f.Op),
		Path:    f.Path,
		NewPath: f.NewPath,
		Read:    f.Read,
		Wrote:   f.Wrote,
		OK:      f.OK,
		Detail:  f.Detail,
	}
}
