package httpapi

// WebSocket'i ssh.Channel gibi giydiren adaptör.
//
// NEDEN BÖYLE: broker (proxy.Broker) istemci tarafından bir ssh.Channel
// bekliyor. WebSocket'i o arayüze uydurursak broker, kayıt, denetim ve
// yeniden boyutlandırma mantığının TAMAMI olduğu gibi çalışır — web
// terminali için ikinci bir kopya yazmamış oluruz. S1.7'de record.Writer'ı
// io.Writer arkasına koyduğumuzda öğrendiğimiz şeyin büyük ölçekli hâli:
// dar bir arayüz, iki dünyayı birbirine tanıtmadan bağlar.
//
// PROTOKOL (plan S4 sözleşmesi):
//
//	binary frame  (her iki yön) : terminal verisi
//	text/JSON     (istemci→sunucu): {"type":"resize","cols":120,"rows":30}
//
// Neden ikisi ayrı: terminal verisi ham bayttır ve içinde her şey olabilir
// (kaçış dizileri, UTF-8 parçaları). Kontrol mesajlarını aynı akışa
// gömseydik, çıktının içinde geçen bir metni komut sanma riski doğardı —
// SSH'ın veri ve request'i ayrı taşımasının sebebi de bu.

import (
	"context"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/coder/websocket"
)

// wsChannel, ssh.Channel arayüzünü WebSocket üzerinde karşılar.
//
// ssh.Channel'ın gerektirdikleri:
//
//	io.ReadWriteCloser
//	CloseWrite() error
//	SendRequest(name string, wantReply bool, payload []byte) (bool, error)
//	Stderr() io.ReadWriter
//
// TODO(yigit): alanları tasarla.
//
// İpuçları:
//   - Read'in sözleşmesi io.Reader'ınki: çağıran küçük bir tampon verip
//     defalarca çağırabilir, ama WebSocket MESAJ tabanlıdır. Bir mesajı
//     okuyup tüketilmeyen kısmını saklaman gerekir (record.Writer'daki
//     "pending" fikri).
//   - conn.Reader(ctx) mesaj tipini de verir: websocket.MessageBinary
//     terminal verisi, websocket.MessageText kontrol mesajı. Kontrol
//     mesajı Read'e DÖNMEMELİ; ayrıştırılıp request kanalına gitmeli.
//   - Yazma tarafında conn.Write(ctx, websocket.MessageBinary, p) tek
//     çağrıda bir mesaj gönderir; io.Writer sözleşmesine uyar.
type wsChannel struct {
	conn *websocket.Conn
	ctx  context.Context
}

// newWSChannel, bağlantıyı sarar ve gelen kontrol mesajlarını request
// kanalına çeviren goroutine'i başlatır.
//
// TODO(yigit): implement.
//
// Dönen kanal broker'ın downR'ıdır: pty-req ve window-change buradan
// akacak. İki sentetik request üretmen gerekiyor:
//
//  1. Bağlantı kurulur kurulmaz bir "pty-req": broker bunu görünce
//     kaydın boyutunu ayarlıyor ve hedefe pty açtırıyor. Payload'ı
//     ssh.Marshal ile kur — sshd.PtyRequest'in alan sırası (Term,
//     Columns, Rows, Width, Height, Modes) tel formatının kendisi.
//     Ardından bir "shell" request'i: kabuk açılmadan terminal boş kalır.
//  2. Her resize mesajı için bir "window-change" (Columns, Rows, Width,
//     Height).
//
// ⚠️ WantReply=false ver: cevabı kimse okumayacak. true verirsen broker
// cevap göndermeye çalışır ve WS'te karşılığı olmayan bir yanıt kanalında
// bloklanabilir.
//
// ⚠️ Kanal KAPANMALI (close) bağlantı bitince: broker downR'ı range ile
// dinliyor; kapanmayan kanal o goroutine'i sonsuza dek yaşatır.
func newWSChannel(ctx context.Context, conn *websocket.Conn) (*wsChannel, <-chan *ssh.Request) {
	return nil, nil
}

// Read, istemciden gelen klavye girdisini döner.
//
// TODO(yigit): implement. (Yukarıdaki "mesaj tabanlı → akış tabanlı"
// notu; kontrol mesajları burada DEĞİL, request kanalında akar.)
func (c *wsChannel) Read(p []byte) (int, error) {
	return 0, io.EOF
}

// Write, terminal çıktısını istemciye binary frame olarak gönderir.
//
// TODO(yigit): implement.
func (c *wsChannel) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

// Close, WebSocket'i kapatır.
//
// TODO(yigit): implement. (websocket.StatusNormalClosure)
func (c *wsChannel) Close() error {
	return nil
}

// CloseWrite, SSH'ta "yazacağım bir şey kalmadı ama okumaya devam" demek.
//
// WebSocket'te yarı kapama YOK. En dürüst karşılık: hiçbir şey yapmamak
// ve nil dönmek — bağlantıyı burada kapatmak, hedeften hâlâ gelebilecek
// çıktıyı (exit mesajı gibi) keserdi.
//
// TODO(yigit): bu yorumu okuyup nil dönmenin doğru olduğuna ikna ol,
// sonra bu TODO'yu sil.
func (c *wsChannel) CloseWrite() error {
	return nil
}

// SendRequest, broker'ın istemciye ilettiği request'ler için: hedeften
// gelen "exit-status" gibi bildirimler.
//
// TODO(yigit): implement.
//
// Bunları JSON kontrol mesajı olarak istemciye iletmek işe yarar:
// {"type":"exit","status":0} → terminal "session ended" yazabilir.
// İletmemek de meşru bir seçim (bağlantı zaten kapanacak); hangisini
// seçtiğini yorumla belirt. wantReply=true gelirse false dön: WS'te
// karşılığı yok.
func (c *wsChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}

// Stderr, SSH'ta ayrı bir akıştır (extended data). Terminalde bunun
// karşılığı yok: xterm.js tek akış gösterir ve zaten pty modunda hedef
// stderr'i de aynı akışa yazar.
//
// TODO(yigit): Write'ı stdout ile aynı yere veren, Read'i EOF dönen
// küçük bir tip döndür. (io.ReadWriter arayüzü; writerFunc desenini
// hatırla — record/asciicast.go'da yapmıştık.)
func (c *wsChannel) Stderr() io.ReadWriter {
	return nil
}

// wsChannel'ın ssh.Channel'ı gerçekten karşıladığını DERLEME ZAMANINDA
// doğrula: imza değişirse hata testte değil derlemede çıksın.
var _ ssh.Channel = (*wsChannel)(nil)
