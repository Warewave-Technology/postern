package proxy

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/sftpaudit"
)

/*
 * ⚠️ VEDA CÜMLESİ SFTP ÇÖZÜMLEYİCİSİNE GİRMEMELİ.
 *
 * sayGoodbye, mesajı outputSink() üzerinden yazıyor ve o sink hedef
 * yönündeki sftpTap'i sarıyor: tap, SFTP oturumu açıkken yazılan her
 * baytı sftpaudit.Session.FromTarget'e besliyor. finishSFTP() oturumu
 * bitiriyor ama b.sftp'yi TEMİZLEMİYOR, dolayısıyla "postern: session
 * closed by an administrator" satırı çözümleyiciye hedeften gelmiş bir
 * paket gibi giriyordu — bozuk uzunluk başlığı, abortAudit, ve log'da
 * "sftp audit failed".
 *
 * Bedeli iki katmanlıydı: denetim çalışırken "denetim çöktü" deniyordu,
 * VE oturumun bitiş sebebi "yönetici kapattı"dan "denetim arızası"na
 * dönüşüyordu (Run, abortErr'i döndürüyor). Yöneticinin kendi bastığı
 * düğme, kayda bir arıza olarak geçiyordu.
 */
func TestGoodbyeDoesNotFakeAnSFTPAuditFailure(t *testing.T) {
	down, _, _ := newFakeChannel()
	up, _, _ := newFakeChannel()

	/*
	 * ⚠️ WithSFTP ŞART — YOKSA BU TESTİN ASIL İDDİASI ÖLÜ.
	 *
	 * tap(), sftpSink nil olduğunda sftpTap'i HİÇ takmıyor (broker.go:
	 * "varsayılan yol, bu özellik eklenmeden önceki yolla aynı kalıyor").
	 * Sink bağlanmadan yazılan veda cümlesi çözümleyiciye hiç uğramıyor,
	 * yani tarif edilen sahte denetim arızası bu kurulumda OLUŞAMIYOR ve
	 * aşağıdaki `<-b.aborted` iddiası düzeltme kaldırılsa bile geçiyordu.
	 *
	 * Ölçüldü: sink bağlanmadan, sayGoodbye'daki SFTP koruması
	 * kaldırıldığında test yine yeşil kalıyor.
	 */
	b := New(down, make(chan *ssh.Request), up, make(chan *ssh.Request),
		nil, false, RequestPolicy{}, testLogger()).
		WithSFTP(&memSink{})

	// Akan bir SFTP oturumu: gerçek kodda beginSFTP bunu kuruyor ve
	// finishSFTP onu TEMİZLEMİYOR.
	b.sftp.Store(sftpaudit.NewSession(func(sftpaudit.Event) {}))

	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(ErrTerminated)
	b.finishSFTP()
	b.sayGoodbye(ctx)

	select {
	case <-b.aborted:
		t.Fatalf("veda cümlesi sahte bir denetim arızası üretti: %v", b.abortErr)
	default:
	}

	// ⚠️ KANALA DA YAZILMAMALI. Karşı taraf ikili protokol okuyan bir
	// `sftp` istemcisi; ona insan cümlesi göndermek okunabilir bir
	// uyarı değil, protokol akışına çöp enjekte etmektir.
	if got := down.dataW.String(); got != "" {
		t.Errorf("SFTP akışına insan metni yazıldı: %q", got)
	}
}

/*
 * Kabuk oturumunda cümle YİNE gidiyor: sessizce kopan bir oturum ağ
 * arızasından ayırt edilemez. Düzeltmenin SFTP'ye özel kaldığını
 * ölçmeyen bir test, mesajı tamamen susturan bir değişikliği de
 * geçirirdi.
 */
func TestGoodbyeStillReachesAShell(t *testing.T) {
	down, _, _ := newFakeChannel()
	up, _, _ := newFakeChannel()

	b := New(down, make(chan *ssh.Request), up, make(chan *ssh.Request),
		nil, false, RequestPolicy{}, testLogger())

	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(ErrTerminated)
	b.sayGoodbye(ctx)

	if got := down.dataW.String(); !strings.Contains(got, "closed by an administrator") {
		t.Fatalf("kabuk oturumuna veda cümlesi gitmedi: %q", got)
	}
}
