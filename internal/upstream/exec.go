package upstream

/*
 * Hedefte tek bir komut çalıştırmak — kullanıcı oturumunun DIŞINDA.
 *
 * ⚠️ probe.go'daki run BU İŞ İÇİN YETMİYOR VE ONUN YERİNE GEÇMİYOR.
 * run hata aldığı an çıktıyı tamamen atıyor, stdin almıyor ve stderr'i
 * yok sayıyor. Probe için doğru (soru "komut çalıştı mı"); ama
 * yönetilebilirlik yoklamasında yanlış sonuç üretiyordu — ÖLÇÜLDÜ:
 * `command -v` döngüsünün çıkış kodu son komutunki, yani visudo'suz bir
 * makinede döngü sıfırdan farklı bitiyor ve run, BULDUĞU adduser'ın
 * yolunu da çöpe atıyordu. Rapor, makinede olan araçları "eksik" diye
 * listeliyordu.
 */

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

/*
 * ErrNoAnswer: hedef, komutun çalışıp çalışmadığını BİLDİRMEDİ.
 *
 * Üç ayrı durum aynı sınıfa düşüyor ve düşmeli: kanal hiç açılamadı,
 * hedef exec isteğini reddetti, ya da kanal çıkış kodu gelmeden kapandı.
 * Üçünde de elimizdeki tek doğru cümle "bilmiyoruz".
 *
 * ⚠️ İLK ADI "ErrLost" ("bağlantı koptu") İDİ VE YANLIŞTI: exec isteğini
 * reddeden hedef bağlantıyı koparmıyor, açıkça cevap veriyor. Operatöre
 * "makine gitti" demek onu ağa baktırırdı. Sebebi ayırt etmek için
 * x/crypto'nun hata metnini ayrıştırmıyoruz (bkz. hostkey.go: bir
 * bağımlılığın dizgisi değiştiği gün sessizce yanlış sınıfa düşülür);
 * kütüphanenin mesajı %w zincirinde operatöre ulaşıyor.
 *
 * ⚠️ ErrUnreachable DEĞİL: o, TCP'nin hiç kurulmadığını söylüyor.
 */
var ErrNoAnswer = errors.New("upstream: the target did not report whether the command ran")

/*
 * CommandError: hedef komutu ÇALIŞTIRDI ve sıfırdan farklı bir kodla
 * bitirdi.
 *
 * ⚠️ BU BİR ARIZA DEĞİL, BİR CEVAP. `command -v` bulamadığı ad için,
 * `sudo -n -l` yetkisiz hesap için sıfırdan farklı dönüyor; çağıran
 * hangisinin cevap hangisinin arıza olduğuna errors.As ile karar
 * veriyor. stderr burada taşınıyor çünkü operatörün okuyacağı sebep
 * ("useradd: group 'x' does not exist") yalnızca orada yazıyor.
 */
type CommandError struct {
	Status int
	Stderr string
}

func (e *CommandError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		return fmt.Sprintf("exited with status %d", e.Status)
	}

	return fmt.Sprintf("exited with status %d: %s", e.Status, msg)
}

/*
 * maxExecOutput, akış başına tutulan çıktı sınırı.
 *
 * ⚠️ HEDEFİN YAZDIĞI METİN SINIRSIZ OLAMAZ. Çıktı rapora, denetim
 * satırına ve panele giriyor; bozuk ya da düşmanca bir makine
 * megabaytlarca metinle veritabanını ve ekranı doldurabilirdi. 64 KiB,
 * useradd'in, visudo'nun ya da bir sudoers dosyasının söyleyebileceği
 * her şeyden fazlası.
 */
const maxExecOutput = 64 * 1024

/*
 * Exec, komutu hedefte çalıştırır ve STDOUT'u döner.
 *
 * ⚠️ STDOUT VE STDERR AYRI TUTULUYOR — BİRLEŞTİRMEK VERİYİ BOZUYOR.
 * Dönen dize yalnızca bir kayıt değil, VERİ olarak da okunuyor: plan,
 * hedefteki sudoers dosyasını `sudo -n cat` ile okuyup yazacağıyla
 * bayt bayt karşılaştırıyor. Bu makinelerde çok sık görülen
 * "sudo: unable to resolve host" uyarısı stdout'a karışsaydı, dosyalar
 * hiç eşleşmez ve plan her koşuda aynı dosyayı yeniden yazardı. Hata
 * sebebi kaybolmuyor: CommandError'da taşınıyor.
 *
 * Komut bir KABUĞA gidiyor (SSH exec): planın adımları `>/dev/null` ve
 * `&&` içeriyor ve bunlar argv'ye bölünseydi, tee adımı ">/dev/null"
 * adında bir dosya yaratıp sudoers dosyasını hiç yazmazdı.
 */
func (c *Conn) Exec(ctx context.Context, command, stdin string) (string, error) {
	if c == nil || c.client == nil {
		return "", fmt.Errorf("%w: no connection", ErrNoAnswer)
	}

	sess, err := c.openSession(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = sess.Close() }()

	stdout := &capped{left: maxExecOutput}
	stderr := &capped{left: maxExecOutput}
	sess.Stdout = stdout
	sess.Stderr = stderr

	/*
	 * ⚠️ İÇERİK STDIN'DEN, KOMUT SATIRINDAN DEĞİL. Plan sudoers metnini
	 * `sudo -n tee <yol>` ile yazıyor. Metni komuta gömmek onu hedefin
	 * işlem listesinde görünür kılar, ve bir kaçış hatası root kabuğunda
	 * komut enjeksiyonuna dönüşürdü. Okuyucu bittiğinde x/crypto stdin'i
	 * kapatıyor; kapatmasaydı tee hiç çıkmazdı.
	 */
	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}

	done := make(chan error, 1)
	go func() { done <- sess.Run(command) }()

	select {
	case runErr := <-done:
		return stdout.String(), classifyExec(runErr, stderr.String())
	case <-ctx.Done():
		/*
		 * ⚠️ OTURUM KAPATILIYOR. sess.Run bağlamı bilmiyor; kapatmasak
		 * asılı bir komut bağlantıda süresiz bir kanal tutardı. Kopyalama
		 * goroutine'leri hâlâ yazıyor olabilir, okuma kilitli.
		 */
		_ = sess.Close()
		return stdout.String(), fmt.Errorf("%w: %w", ErrNoAnswer, ctx.Err())
	}
}

/*
 * openSession, kanalı bağlama bağlı bir sınırla açar.
 *
 * ⚠️ NewSession'IN SÜRESİ YOK — dial.go'da ölçülüp yazılmış bir sınır:
 * el sıkışmayı bitirip sonra susan bir hedef kanal açılışını süresiz
 * tutuyor. Bir panel isteği ya da bir yayılım koşusu buna asılırsa
 * hiçbir şey onu kesmezdi. Bağlam iptal edilince BAĞLANTININ TAMAMI
 * kapatılıyor: kanal açamayan bir bağlantının kurtarılacak bir tarafı
 * yok, ve bekleyen goroutine ancak böyle dönüyor.
 */
func (c *Conn) openSession(ctx context.Context) (*ssh.Session, error) {
	type opened struct {
		sess *ssh.Session
		err  error
	}
	ch := make(chan opened, 1)
	go func() {
		s, err := c.client.NewSession()
		ch <- opened{s, err}
	}()

	select {
	case o := <-ch:
		if o.err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNoAnswer, o.err)
		}
		return o.sess, nil
	case <-ctx.Done():
		_ = c.client.Close()
		return nil, fmt.Errorf("%w: %w", ErrNoAnswer, ctx.Err())
	}
}

/*
 * classifyExec, çalıştırma hatasını cevap ile arıza arasında ayırır.
 */
func classifyExec(err error, stderr string) error {
	if err == nil {
		return nil
	}

	var exit *ssh.ExitError
	if errors.As(err, &exit) {
		return &CommandError{Status: exit.ExitStatus(), Stderr: stderr}
	}

	/*
	 * ⚠️ ExitMissingError "BAŞARILI" DEĞİL. Uzak uç çıkış kodunu
	 * bildirmeden kanalı kapattı; komutun çalışıp çalışmadığını
	 * bilmiyoruz. Başarı saymak, uygulanmamış bir adımı uygulanmış
	 * göstermek olurdu — ve sonraki adım onun üzerine kurulurdu.
	 */
	return fmt.Errorf("%w: %w", ErrNoAnswer, err)
}

/*
 * capped, sınırı aşan çıktıyı sessizce atan, eşzamanlı okunabilir
 * bir yazıcı.
 *
 * ⚠️ KİLİT ŞART. x/crypto akışı kendi goroutine'inde kopyalıyor; bağlam
 * iptalinde String() o goroutine hâlâ yazarken çağrılıyor.
 */
type capped struct {
	mu   sync.Mutex
	buf  strings.Builder
	left int
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.left > 0 {
		n := min(len(p), c.left)
		c.buf.Write(p[:n])
		c.left -= n
	}

	// Atılan baytlar da yazılmış sayılıyor: kısa yazma x/crypto'da hata
	// sayılıp komutu ortasından keserdi.
	return len(p), nil
}

func (c *capped) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.buf.String()
}
