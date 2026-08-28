package upstream

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/warewave/postern/internal/model"
)

/*
 * ProbeCommands, tanımada çalıştırılan SABİT komutlar.
 *
 * ⚠️ DEĞİŞKEN DEĞİL, SABİT — ve bu listenin yapılandırılabilir olmaması
 * özelliğin en önemli parçası. Operatörün komut yazabildiği bir alan,
 * config dosyasına erişebilen herkese denetim altındaki HER MAKİNEDE
 * uzaktan komut çalıştırma yetkisi verirdi; bastion'ı tam da engellemek
 * için var olduğu şeye çevirirdi. Bu yüzden liste derleme zamanında
 * sabit ve gözden geçirilebilir.
 *
 * İkisi de SALT OKUMA ve yan etkisiz. Kabuk yorumuna açık hiçbir şey
 * içermiyorlar (joker, boru, yönlendirme, değişken yok) — SSH exec
 * isteği dizeyi hedefin kabuğuna verdiği için bu önemli.
 */
var ProbeCommands = []string{
	"uname -srm",
	"cat /etc/os-release",
}

// maxProbeOutput, tek bir komuttan okunacak en fazla bayt.
//
// ⚠️ Sınırsız okuma, düşmanca (ya da yalnızca tuhaf) bir hedefin
// belleği doldurmasına izin verirdi: /etc/os-release yerine sonsuz bir
// akış koymak yeterli. 8 KiB gerçek bir os-release için fazlasıyla
// yeterli.
const maxProbeOutput = 8 << 10

/*
 * Probe, hedefte sabit okuma komutlarını çalıştırıp makineyi tanır.
 *
 * ⚠️ BU FONKSİYON YALNIZCA target_probe.enabled İLE ÇAĞRILIR. Kapalıyken
 * postern hedefte kullanıcının oturumu dışında hiçbir şey çalıştırmaz.
 *
 * ⚠️ KOMUTLAR KULLANICININ BAĞLANTISINDA ÇALIŞIR. Ayrı bir kimlik ya da
 * ayrı bir principal kullanmıyoruz: o, hedef tarafında postern için
 * ayrıca yetki açmak demekti — yani bastion'a kullanıcılardan bağımsız,
 * kalıcı bir erişim vermek. Bedeli şu: komutlar hedefin günlüklerinde
 * bağlanan kullanıcının adına görünür. Kabul edilebilir olmasının tek
 * sebebi özelliğin varsayılan kapalı ve her koşusunun denetime yazılıyor
 * olması.
 */
func (c *Conn) Probe(ctx context.Context) (model.TargetProbe, error) {
	if c == nil || c.client == nil {
		return model.TargetProbe{}, fmt.Errorf("upstream.Probe: no connection")
	}

	out := make([]string, len(ProbeCommands))
	for i, cmd := range ProbeCommands {
		v, err := c.run(ctx, cmd)
		if err != nil {
			// Tek komutun düşmesi tanımayı bitirmiyor: bazı hedeflerde
			// /etc/os-release yok (BSD, konteyner tabanları) ve o hedefi
			// tamamen tanımsız bırakmak, elde olan çekirdek bilgisini de
			// atmak olurdu.
			continue
		}
		out[i] = v
	}

	p := model.TargetProbe{
		Kernel: truncate(strings.TrimSpace(out[0]), 96),
		OSName: truncate(prettyName(out[1]), 96),
	}
	if p.Kernel == "" && p.OSName == "" {
		return model.TargetProbe{}, fmt.Errorf("upstream.Probe: target answered nothing")
	}
	return p, nil
}

// run, tek bir komutu sınırlı çıktı ve sınırlı süreyle çalıştırır.
func (c *Conn) run(ctx context.Context, cmd string) (string, error) {
	sess, err := c.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	var buf strings.Builder
	sess.Stdout = &limitWriter{w: &buf, left: maxProbeOutput}
	// stderr KASTEN atılıyor: hata metni de hedefin ürettiği bir dize ve
	// onu saklamak için sebep yok — komut ya çalıştı ya çalışmadı.
	sess.Stderr = nil

	// ⚠️ ctx iptalinde oturum KAPATILIYOR. sess.Run bağlamı bilmiyor;
	// kapatmasak asılı bir komut, kullanıcının oturumuyla paylaşılan
	// bağlantıda süresiz bir kanal tutardı.
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	select {
	case err := <-done:
		if err != nil {
			return "", err
		}
		return buf.String(), nil
	case <-ctx.Done():
		_ = sess.Close()
		return "", ctx.Err()
	}
}

// limitWriter, belirtilen bayttan sonrasını sessizce atar.
type limitWriter struct {
	w    *strings.Builder
	left int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.left > 0 {
		n := len(p)
		if n > l.left {
			n = l.left
		}
		l.w.Write(p[:n])
		l.left -= n
	}
	// Yazılmış gibi davranıyoruz: kısa yazma döndürmek komutu erken
	// hataya düşürür ve elimizdeki kısmi çıktıyı da kaybederdik.
	return len(p), nil
}

/*
 * prettyName, os-release içeriğinden PRETTY_NAME değerini çıkarır.
 *
 * Elle ayrıştırılıyor çünkü os-release bir kabuk dosyası gibi görünse de
 * onu kabukta kaynak göstermek (source) hedefin yazdığı metni bizim
 * tarafta çalıştırmak olurdu.
 */
func prettyName(osRelease string) string {
	sc := bufio.NewScanner(strings.NewReader(osRelease))
	var fallback string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "PRETTY_NAME":
			return v
		case "NAME":
			// PRETTY_NAME her dağıtımda yok; NAME neredeyse hep var.
			if fallback == "" {
				fallback = v
			}
		}
	}
	return fallback
}
