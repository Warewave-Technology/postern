package httpapi

import (
	"net/http"
	"testing"
)

func req(remote string, xff ...string) *http.Request {
	h := http.Header{}
	for _, v := range xff {
		h.Add("X-Forwarded-For", v)
	}
	return &http.Request{RemoteAddr: remote, Header: h}
}

func srv(t *testing.T, cidrs ...string) *Server {
	t.Helper()
	s := &Server{}
	if err := s.SetTrustedProxies(cidrs); err != nil {
		t.Fatalf("SetTrustedProxies: %v", err)
	}
	return s
}

/*
 * ⚠️ ARIZANIN KENDİSİ: vekil arkasında yönetici panelden kilitlenebiliyordu.
 *
 * ÖLÇÜM (düzeltmeden önce): farklı X-Forwarded-For, aynı RemoteAddr ->
 * aynı backoff anahtarı. Saldırgan "admin" hesabına on kez yanlış parola
 * yolladıktan sonra YÖNETİCİNİN beklemesi 4m59s oluyordu; ret sayacı
 * artırmadığı için maliyeti beş dakikada bir istekti.
 *
 * Bu test o senaryonun tamamını kuruyor: anahtarların ayrılması yetmez,
 * yöneticinin GERÇEKTEN beklemediği görülmeli.
 */
func TestProxiedAttackerCannotLockOutTheAdmin(t *testing.T) {
	s := srv(t, "10.0.0.9")

	saldirgan := req("10.0.0.9:5001", "203.0.113.7")
	yonetici := req("10.0.0.9:5002", "198.51.100.4")

	ka := backoffKey("admin", s.clientKey(saldirgan))
	ky := backoffKey("admin", s.clientKey(yonetici))
	if ka == ky {
		t.Fatal("anahtarlar aynı — vekil arkasında izolasyon yok")
	}

	bo := newGuessBackoff()
	for range 10 {
		bo.fail(ka)
	}
	if w := bo.retryAfter(ky); w != 0 {
		t.Errorf("yönetici %s bekliyor — kilit hâlâ mümkün", w)
	}
	// Saldırgan KENDİ adresinde gecikmeyi yemeli: sınır kalkmadı,
	// yalnızca doğru kişiye uygulanıyor.
	if w := bo.retryAfter(ka); w == 0 {
		t.Error("saldırgan hiç gecikme görmüyor — sınır tamamen kalkmış")
	}
}

/*
 * ⚠️ GÜVENİLMEYEN KAYNAKTAN GELEN BAŞLIK OKUNMAMALI.
 *
 * Bu, X-Forwarded-For'u koşulsuz okumamanın sebebi: okunsaydı, doğrudan
 * bağlanan bir saldırgan her istekte başka bir adres uydurup sınırı
 * tamamen atlardı.
 */
func TestForwardedHeaderIgnoredFromUntrustedPeer(t *testing.T) {
	s := srv(t, "10.0.0.9")

	a := s.clientKey(req("198.51.100.23:4444", "1.2.3.4"))
	b := s.clientKey(req("198.51.100.23:4445", "5.6.7.8"))
	if a != b {
		t.Fatalf("uydurma başlık anahtarı değiştirdi: %q vs %q", a, b)
	}
	if a != "198.51.100.23" {
		t.Errorf("anahtar = %q, gerçek kaynak adres bekleniyordu", a)
	}
}

// Liste boşken davranış eskisiyle BİT BİT AYNI olmalı: doğrudan açık
// bir bastion'ın bu değişiklikten hiç etkilenmemesi gerekiyor.
func TestEmptyListKeepsOldBehaviour(t *testing.T) {
	s := srv(t)
	if got := s.clientKey(req("203.0.113.5:9000", "10.0.0.1")); got != "203.0.113.5" {
		t.Errorf("anahtar = %q, 203.0.113.5 bekleniyordu", got)
	}
}

/*
 * ⚠️ ZİNCİR SAĞDAN SOLA. Soldaki girdileri istemci uydurabilir;
 * güvenilen vekiller sağdan elenince kalan ilk adres, doğrulayabildiğimiz
 * en uzak atlamadır. Soldan okumak, istemcinin başkasının kotasını
 * tüketmesine izin verirdi.
 */
func TestChainIsWalkedFromTheRight(t *testing.T) {
	s := srv(t, "10.0.0.0/8")

	// İstemci "1.1.1.1" uydurmuş; gerçek giriş 198.51.100.4, sonra iki
	// iç vekil.
	got := s.clientKey(req("10.0.0.9:1", "1.1.1.1, 198.51.100.4, 10.0.0.2"))
	if got != "198.51.100.4" {
		t.Errorf("anahtar = %q, 198.51.100.4 bekleniyordu", got)
	}
}

// Zincirin tamamı güvenilen vekilse elimizdeki en iyi bilgi doğrudan
// bağlanan adres — uydurma bir değere düşmemeli.
func TestAllTrustedFallsBackToPeer(t *testing.T) {
	s := srv(t, "10.0.0.0/8")
	if got := s.clientKey(req("10.0.0.9:1", "10.0.0.2, 10.0.0.3")); got != "10.0.0.9" {
		t.Errorf("anahtar = %q, 10.0.0.9 bekleniyordu", got)
	}
	if got := s.clientKey(req("10.0.0.9:1")); got != "10.0.0.9" {
		t.Errorf("başlıksız istekte anahtar = %q", got)
	}
}

// Çift yığınlı vekil: IPv4-mapped IPv6 adresi listede tanınmalı.
func TestMappedIPv6PeerIsRecognised(t *testing.T) {
	s := srv(t, "10.0.0.9")
	if got := s.clientKey(req("[::ffff:10.0.0.9]:1", "203.0.113.7")); got != "203.0.113.7" {
		t.Errorf("anahtar = %q — mapped IPv6 vekil tanınmadı", got)
	}
}

func TestBadCIDRIsRefused(t *testing.T) {
	s := &Server{}
	if err := s.SetTrustedProxies([]string{"10.0.0.0/33"}); err == nil {
		t.Error("bozuk CIDR kabul edildi — kurulum sessizce yanlış olurdu")
	}
}
