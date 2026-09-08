package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

/*
 * wsPair, bir uçta wsChannel, diğer uçta ham bir websocket istemcisi olan
 * bağlı çift kurar.
 *
 * ⚠️ GERÇEK BİR WEBSOCKET KULLANILIYOR, SAHTE DEĞİL. Ölçmek istediğimiz
 * şey TEL ÜZERİNDEKİ biçim: çerçeve sınırları ve ilk bayt. Sahte bir
 * bağlantı, tam da sınanmak istenen kısmı kendi varsayımıyla değiştirirdi.
 */
func wsPair(t *testing.T) (*wsChannel, *websocket.Conn, func()) {
	t.Helper()

	ready := make(chan *wsChannel, 1)
	// hold, handler'ı test bitene kadar ayakta tutuyor.
	//
	// ⚠️ r.Context().Done() DEĞİL: httptest.Server.Close() süren isteği
	// bekliyor ve istemci kapanışının bağlama ulaşması gecikiyordu —
	// her test 5 saniye sürüyordu. Açık bir kanal, bekleyişi testin
	// kendi temizliğine bağlıyor.
	hold := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		ch, _ := newWSChannel(context.Background(), c, nil)
		ready <- ch
		<-hold
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cli, _, err := websocket.Dial(ctx, "ws"+srv.URL[4:], nil)
	if err != nil {
		cancel()
		srv.Close()
		t.Fatalf("dial: %v", err)
	}

	var ch *wsChannel
	select {
	case ch = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("sunucu tarafı kurulmadı")
	}

	return ch, cli, func() {
		/*
		 * ⚠️ CloseNow, Close DEĞİL — ve fark beş saniye.
		 *
		 * Close kapanış EL SIKIŞMASI yapıyor: karşı tarafın close
		 * çerçevesini beklemek için beş saniye duruyor. Bu testlerde
		 * sunucu tarafı hiç okumuyor (wsChannel.Read çağrılmıyor), yani
		 * o cevap hiçbir zaman gelmiyor ve her test tam olarak o süreyi
		 * harcıyordu. Ölçüldü; tahmin edilerek üç kez yanlış yer
		 * düzeltildi.
		 */
		close(hold)
		_ = cli.CloseNow()
		cancel()
		srv.Close()
	}
}

func readFrame(t *testing.T, c *websocket.Conn) (websocket.MessageType, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	typ, b, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("okuma: %v", err)
	}
	return typ, b
}

/*
 * ⚠️ VERİ İLE stderr TEL ÜZERİNDE AYRILMALI.
 *
 * ÖLÇÜLEN TEHLİKE: ikisi de aynı binary akışa yazılıyordu. Terminal için
 * doğruydu (pty zaten birleştiriyor), ama kanal SFTP taşıdığında
 * postern'in uyarı satırları istemcinin PROTOKOL baytları sanacağı yere
 * düşüyor ve çerçeveleme o noktadan sonra kayıyor — yol politikasının
 * gerekçe yazan yarısı, koruduğu istemciyi bozuyor.
 */
func TestDataAndStderrAreSeparableOnTheWire(t *testing.T) {
	ch, cli, done := wsPair(t)
	defer done()

	if _, err := ch.Write([]byte("cikti")); err != nil {
		t.Fatal(err)
	}
	if _, err := ch.Stderr().Write([]byte("uyari")); err != nil {
		t.Fatal(err)
	}

	typ, f1 := readFrame(t, cli)
	if typ != websocket.MessageBinary {
		t.Fatalf("veri çerçevesi %v", typ)
	}
	if f1[0] != wsStreamData || !bytes.Equal(f1[1:], []byte("cikti")) {
		t.Fatalf("veri çerçevesi yanlış: %q", f1)
	}

	_, f2 := readFrame(t, cli)
	if f2[0] != wsStreamStderr || !bytes.Equal(f2[1:], []byte("uyari")) {
		t.Fatalf("stderr çerçevesi yanlış: %q", f2)
	}
}

/*
 * ⚠️ POSTERN'İN KENDİ BAYTI, HEDEFİNKİYLE AYNI ETİKETTEN ÇIKMAZ.
 *
 * ÖLÇÜLEN AÇIK: postern kendi retlerini "postern: " önekiyle yazıyordu ve
 * panel o öneki KÖKEN KANITI sayıyordu. Ama hedefin STATUS mesajı
 * istemciye olduğu gibi geçiyor (internal/sftpaudit/status.go): hedefin
 * sahibi aynı öneki yazdığında panel onu bastion'ın gerekçesi diye
 * çiziyordu — denetlenen makine, denetleyenin ağzından konuşuyordu.
 *
 * Ölçülen şey, İÇERİĞİ AYNI iki yazmanın FARKLI etiketlerle çıkması:
 * ayrım metinde değil, hedefin yazamadığı yerde.
 */
func TestPosternsOwnBytesCarryTheirOwnTag(t *testing.T) {
	ch, cli, done := wsPair(t)
	defer done()

	// Aynı metin, dört yazma. İkisi hedefin, ikisi postern'in.
	same := []byte("postern: path is not permitted")
	for _, w := range []func([]byte) (int, error){
		ch.Write, ch.Stderr().Write, ch.WriteOwn, ch.WriteOwnStderr,
	} {
		if _, err := w(same); err != nil {
			t.Fatal(err)
		}
	}

	want := []byte{wsStreamData, wsStreamStderr, wsStreamOwn, wsStreamOwnStderr}
	var got []byte
	for range want {
		_, f := readFrame(t, cli)
		if !bytes.Equal(f[1:], same) {
			t.Fatalf("gövde değişmiş: %q", f[1:])
		}
		got = append(got, f[0])
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("etiketler = %v, %v bekleniyordu", got, want)
	}
}

/*
 * Etiket ile veri AYNI çerçevede.
 *
 * ⚠️ İki ayrı çerçeve göndermek, araya başka bir yazma girdiğinde etiketi
 * yanlış veriye bağlardı. Tek çerçeve, ayrımı taşınabilir kılıyor.
 */
func TestTagTravelsWithItsBytes(t *testing.T) {
	ch, cli, done := wsPair(t)
	defer done()

	payload := bytes.Repeat([]byte{0xAB}, 3000)
	if _, err := ch.Write(payload); err != nil {
		t.Fatal(err)
	}

	_, f := readFrame(t, cli)
	if len(f) != len(payload)+1 {
		t.Fatalf("çerçeve uzunluğu %d, %d bekleniyordu", len(f), len(payload)+1)
	}
	if f[0] != wsStreamData || !bytes.Equal(f[1:], payload) {
		t.Fatal("etiket ile veri ayrı çerçevelere düşmüş")
	}
}

/*
 * ⚠️ İKİLİ VERİ BOZULMADAN GEÇMELİ.
 *
 * SFTP uzunluk-önekli ikili bir protokol: 0x00 baytı, geçersiz UTF-8
 * dizisi ve uzun bloklar sıradan içerik. Tel biçimi bunları olduğu gibi
 * taşımıyorsa özellik daha başlamadan bozuk demektir.
 */
func TestArbitraryBinarySurvives(t *testing.T) {
	ch, cli, done := wsPair(t)
	defer done()

	payload := []byte{0x00, 0x01, 0xFF, 0xFE, 0x00, 0x80, 0xC0, 0x0A, 0x0D}
	if _, err := ch.Write(payload); err != nil {
		t.Fatal(err)
	}

	_, f := readFrame(t, cli)
	if !bytes.Equal(f[1:], payload) {
		t.Fatalf("ikili veri bozuldu: %x", f[1:])
	}
}

// Yazılan bayt sayısı ETİKETİ SAYMIYOR: io.Writer sözleşmesi "verdiğin
// baytlardan kaçı yazıldı" diyor, tel üzerindeki zarfı değil.
func TestWriteCountExcludesTheTag(t *testing.T) {
	ch, cli, done := wsPair(t)
	defer done()

	n, err := ch.Write([]byte("abcd"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("n = %d, 4 bekleniyordu — io.Copy kısa yazma sanır", n)
	}
	readFrame(t, cli)
}
