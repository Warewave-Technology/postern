package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

/*
 * İstemcinin gerçek adresi — ters vekil arkasında da.
 *
 * ⚠️ ÖLÇÜLEN ARIZA: vekil arkasında yönetici PANELDEN KİLİTLENEBİLİYORDU.
 *
 * İki ayrı doğru karar, birleşince yanlış davranıyordu. clientKey
 * bilerek yalnızca RemoteAddr okuyor (X-Forwarded-For'u koşulsuz okumak,
 * istemcinin kendi hız sınırı anahtarını seçmesine izin vermek olurdu).
 * backoffKey ise (hesap, adres) çiftiyle anahtarlıyor, çünkü yalnızca
 * hesaba göre saymak yabancıya "yöneticiyi dışarıda tut" düğmesi
 * verirdi. Ama TLS için ters vekil ŞART koştuğumuz topolojide RemoteAddr
 * herkes için vekilin adresine çöküyor, çift tekile iniyor ve
 * backoff.go'nun engellemek için yazıldığı senaryo aynı kapıdan geri
 * geliyordu.
 *
 * Ölçüm: farklı X-Forwarded-For, aynı RemoteAddr -> aynı backoff
 * anahtarı; saldırgan "admin" hesabına on kez yanlış parola yolladıktan
 * sonra yöneticinin beklemesi 4m59s. Ret sayacı artırmadığı için
 * saldırganın maliyeti BEŞ DAKİKADA BİR İSTEK, süresiz kilit. Hedefin
 * adını tahmin etmek de gerekmiyor: bootstrap varsayılan olarak "admin"
 * açıyor.
 *
 * ⚠️ ÇÖZÜM "XFF'İ OKU" DEĞİL, "KİMDEN GELDİĞİNE BAK". Başlık YALNIZCA
 * istek güvenilen bir vekilden geliyorsa okunuyor. Liste boşken —
 * varsayılan — davranış bugünküyle bit bit aynı: doğrudan açık bir
 * bastion, başlık uydurarak sınırı atlayan istemciye yem olmuyor.
 *
 * ⚠️ ZİNCİR SAĞDAN SOLA YÜRÜNÜYOR. XFF'i istemci de yazabilir; soldaki
 * girdiler uydurma olabilir. Güvenilen vekiller sağdan elenince geriye
 * kalan ilk adres, bizim doğrulayabildiğimiz EN UZAK atlama olur.
 * Soldan okumak, istemcinin "10.0.0.1" yazıp başkasının kotasını
 * tüketmesine izin verirdi.
 */

// trustedProxies, X-Forwarded-For'una güvenilen kaynak adresler.
type trustedProxies struct {
	nets []netip.Prefix
}

// parseTrustedProxies, CIDR listesini çözer. Boş liste = kapalı.
func parseTrustedProxies(cidrs []string) (*trustedProxies, error) {
	tp := &trustedProxies{}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// Tek adres de yazılabilsin: "10.0.0.5" -> "10.0.0.5/32".
		// Operatörün maskeyi hatırlamak zorunda kalması, listeyi boş
		// bırakmanın bir sebebi daha olurdu.
		if !strings.Contains(c, "/") {
			addr, err := netip.ParseAddr(c)
			if err != nil {
				return nil, err
			}
			tp.nets = append(tp.nets, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, err
		}
		tp.nets = append(tp.nets, p.Masked())
	}
	return tp, nil
}

// trusts, adresin güvenilen vekillerden biri olup olmadığını söyler.
func (t *trustedProxies) trusts(addr netip.Addr) bool {
	if t == nil {
		return false
	}
	// IPv4-mapped IPv6 ("::ffff:10.0.0.1") düz IPv4 gibi
	// karşılaştırılmalı; aksi hâlde çift yığınlı bir vekil listede
	// olduğu hâlde tanınmazdı.
	addr = addr.Unmap()
	for _, n := range t.nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// clientKey, hız sınırının anahtarı: istemcinin adresi.
func (s *Server) clientKey(r *http.Request) string {
	direct := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		direct = host
	}

	peer, err := netip.ParseAddr(direct)
	if err != nil || !s.trustedProxies.trusts(peer) {
		return direct
	}

	hops := forwardedHops(r)
	for i := len(hops) - 1; i >= 0; i-- {
		a, perr := netip.ParseAddr(hops[i])
		if perr != nil {
			// Ayrıştıramadığımız girdi zincirin sonu: ondan solunu
			// doğrulayamayız, bu yüzden vekilin kendi adresine düşüyoruz.
			break
		}
		if !s.trustedProxies.trusts(a) {
			return a.Unmap().String()
		}
	}

	// Zincirdeki her şey güvenilen vekil (ya da başlık hiç yok):
	// elimizdeki en iyi bilgi doğrudan bağlanan adres.
	return direct
}

// forwardedHops, X-Forwarded-For zincirini soldan sağa döner.
func forwardedHops(r *http.Request) []string {
	var out []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			// Bazı vekiller portu da ekliyor.
			if host, _, err := net.SplitHostPort(part); err == nil {
				part = host
			}
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}
