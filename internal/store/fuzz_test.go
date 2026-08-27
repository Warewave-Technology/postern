package store

// Bu paketten fuzz'lanabilen TEK şey dsn: saf, bellek içi, yan etkisiz.
// Store'un geri kalanı gerçek bir PostgreSQL istiyor (internal/testdb) ve
// saniyede binlerce çağrı altında konteyner açmak ölçüm değil, gürültü
// olurdu.

import (
	"net/url"
	"strings"
	"testing"
)

// sslmodeRank orders libpq's sslmode values by strictness.
//
// Sıra keyfi değil, libpq'nun kendi tanımı: disable hiç TLS denemez,
// prefer dener ve SESSİZCE düşer, require şifreler ama sunucuyu
// doğrulamaz, verify-* zinciri ve adı da doğrular. dsn'nin var oluş
// sebebi "belirtilmemiş" durumu bu sıranın EN ÜSTÜNE çekmek; testin
// koruduğu şey de tam olarak bu yönün hiç tersine dönmemesi.
var sslmodeRank = map[string]int{
	"disable":     0,
	"allow":       1,
	"prefer":      2,
	"require":     3,
	"verify-ca":   4,
	"verify-full": 5,
}

// qpair is one decoded key/value from a connection string's query.
type qpair struct{ key, value string }

// rawSegmentKey marks a query segment that could not be percent-decoded.
//
// "a=%zz" gibi bozuk bir kaçışı çözemeyiz, ama KAYBOLMADIĞINI yine de
// görmek istiyoruz: ham metnini sahte bir anahtarın değeri yapıp
// karşılaştırmaya öyle sokuyoruz. Aksi hâlde tam da kaybın olduğu
// girdiler sessizce testin dışında kalırdı.
const rawSegmentKey = "\x00raw-segment"

// refQuery is the strict reference parser for a raw query string.
//
// net/url'den AYRI durmasının sebebi sınanan hatanın ta kendisi: Go
// 1.17'den beri url.ParseQuery noktalı virgülü ayırıcı SAYMAZ, o parçayı
// atar ve hatayı döner. Operatör "?sslmode=require;application_name=x"
// yazdığında KASTETTİĞİ iki parametredir — referans o niyeti temsil
// etmeli, dsn'nin içindeki ayrıştırıcının kusurunu değil. Referansı
// sınanan koddan türetirsek test yalnızca kodun kendine benzediğini
// ispatlar.
func refQuery(raw string) []qpair {
	var out []qpair

	for _, seg := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '&' || r == ';'
	}) {
		k, v, _ := strings.Cut(seg, "=")

		dk, kerr := url.QueryUnescape(k)
		dv, verr := url.QueryUnescape(v)
		if kerr != nil || verr != nil {
			out = append(out, qpair{key: rawSegmentKey, value: seg})
			continue
		}
		out = append(out, qpair{key: dk, value: dv})
	}

	return out
}

// effectiveSSLMode returns the sslmode a driver would actually apply.
//
// İLK değer kazanıyor çünkü pgx'in parseURLSettings'i url.Values'tan
// v[0]'ı alıyor; "sonuncu kazanır" varsaymak testi sürücüyle ayrı
// düşürürdü.
func effectiveSSLMode(pairs []qpair) string {
	for _, p := range pairs {
		if p.key == "sslmode" {
			return p.value
		}
	}
	return ""
}

// count turns a pair list into a multiset.
func count(pairs []qpair) map[qpair]int {
	m := make(map[qpair]int, len(pairs))
	for _, p := range pairs {
		m[p]++
	}
	return m
}

// FuzzDSN checks that dsn never silently rewrites a connection string.
//
// Denetlenen özellikler — hepsi "sessizce başka bir şeye çevirme"
// kuralının bir yüzü:
//
//  1. BİÇİM SINIFI korunur. pgx bir bağlantı dizesinin URI mi yoksa
//     anahtar=değer mi olduğuna "postgres://" ÖNEKİNE bakarak karar
//     verir. Çıktıdan "//" düşerse aynı metin BAŞKA bir ayrıştırıcıya
//     gider: host, user, sslmode — hepsi başka anlama gelir.
//  2. sslmode ne eksilir ne gevşer.
//  3. Girdideki her parametre çıktıda durur (kayıpsızlık).
//  4. dsn(dsn(x)) == dsn(x).
//
// Tohumlar bilerek GEÇEN girdiler: bilinen kırık girdiyi tohuma koymak
// kampanyayı ilk saniyede durdurur ve motor hiç çalışmaz. Her tohum
// kırık komşusuna tek bayt uzaklıkta duruyor ("&" → ";", "/postern"
// silinmesi), bulmayı motora bırakıyoruz.
func FuzzDSN(f *testing.F) {
	f.Add("postgres://u:p@db.local:5432/postern")
	f.Add("postgres://u:p@db.local:5432/postern?sslmode=disable")
	f.Add("postgres://db.local/postern?application_name=postern")
	f.Add("postgres://db.local/postern?sslmode=require&application_name=postern")
	f.Add("postgresql://db.local:5432/postern?sslmode=verify-ca&connect_timeout=5")
	f.Add("postgres:///postern?host=/var/run/postgresql")
	f.Add("postgres://h/db?sslmode=")
	f.Add("postgres://h/db?a=%zz&sslmode=require")
	f.Add("://")

	f.Fuzz(func(t *testing.T, conn string) {
		// Anahtar=değer biçimi dsn'de olduğu gibi geçiyor; dönüşüm yok,
		// sınanacak özellik de yok.
		if !strings.Contains(conn, "://") {
			return
		}

		got, err := dsn(conn)
		u, parseErr := url.Parse(conn)

		if err != nil {
			// REDDETMEK GEÇERLİ BİR SONUÇ ve bu hedefin asıl bulduğu şey
			// buydu: dsn eskiden url.Parse'ın hoş gördüğü bozuk sorgu
			// dizelerini kabul edip sessizce YENİDEN YAZIYORDU
			// (noktalı virgüllü parametreler kayboluyor, operatörün
			// yazdığı sslmode değişiyordu). Artık reddediyor.
			//
			// Bu yüzden burada "url.Parse kabul ediyorsa dsn de
			// kabul etmeli" diye bir iddia YOK — o iddia tam olarak
			// düzeltilen davranışı geri isterdi. Sözleşme şu: dsn ya
			// reddeder ya da hiçbir şeyi sessizce değiştirmez.
			//
			// Hata mesajı yine de anlamlı olmalı: açılışta düşen bir
			// yapılandırmanın sebebi okunabilir olsun.
			if err.Error() == "" {
				t.Fatalf("dsn(%q) sebepsiz reddetti", conn)
			}
			return
		}
		if parseErr != nil {
			t.Fatalf("dsn(%q) = %q kabul etti ama url.Parse reddediyor: %v", conn, got, parseErr)
		}

		out, outErr := url.Parse(got)
		if outErr != nil {
			t.Fatalf("dsn(%q) = %q ayrıştırılamıyor: %v", conn, got, outErr)
		}

		// 1. BİÇİM SINIFI.
		if !strings.Contains(got, "://") {
			t.Fatalf("dsn(%q) = %q — URI biçimi kayboldu; pgx bunu artık "+
				"anahtar=değer olarak ayrıştırır ve host/user/sslmode'un "+
				"tamamı başka anlama gelir", conn, got)
		}

		in := refQuery(u.RawQuery)
		res := refQuery(out.RawQuery)

		inMode := effectiveSSLMode(in)
		outMode := effectiveSSLMode(res)

		// 2. sslmode ne eksik ne gevşek.
		//
		// Boş bırakmak da eksik saymak gerekiyor: pgx boş değeri
		// "belirtilmemiş" kabul eder ve libpq varsayılanına (prefer)
		// düşer — düz metne sessiz iniş tam olarak budur.
		if outMode == "" {
			t.Errorf("dsn(%q) = %q — çıktıda sslmode yok/boş; sürücü "+
				"libpq varsayılanına (prefer) düşer", conn, got)
		}
		inRank, inKnown := sslmodeRank[inMode]
		outRank, outKnown := sslmodeRank[outMode]
		switch {
		case inKnown && !outKnown:
			t.Errorf("dsn(%q) = %q — sslmode %q iken tanınmayan %q oldu",
				conn, got, inMode, outMode)
		case inKnown && outKnown && outRank < inRank:
			t.Errorf("dsn(%q) = %q — sslmode %q → %q, TLS gevşedi",
				conn, got, inMode, outMode)
		}

		// 3. KAYIPSIZLIK.
		//
		// Tek muafiyet sslmode: girdideki etkin değer boşsa onu
		// doldurmak dsn'nin işi (bkz. doc). Başka HİÇBİR parametrenin
		// kaybolmaya ya da değişmeye hakkı yok — bağlantı dizesi
		// operatörün yazdığı şeydir.
		have := count(res)
		for _, p := range in {
			if p.key == "sslmode" && inMode == "" {
				continue
			}
			if have[p] > 0 {
				have[p]--
				continue
			}
			t.Errorf("dsn(%q) = %q — girdideki %q=%q parametresi çıktıda yok",
				conn, got, p.key, p.value)
		}

		// 4. SABİT NOKTA. Yapılandırma yeniden okunduğunda (yeniden
		// başlatma, hot reload) dizenin bir daha değişmemesi gerekir.
		again, againErr := dsn(got)
		if againErr != nil {
			t.Errorf("dsn(dsn(%q)) hata verdi: %v", conn, againErr)
		} else if again != got {
			t.Errorf("dsn sabit nokta değil: dsn(%q) = %q, dsn(o) = %q", conn, got, again)
		}
	})
}
