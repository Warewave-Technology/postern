package sshd

import (
	"strings"
	"testing"
)

// refParseUsername is an independent model of ParseUsername's accept set,
// written from the S1.3 contract rather than from username.go.
//
// Ayrı bir model yazmanın sebebi: aynı kodu kendisiyle karşılaştırmak hiçbir
// şey kanıtlamaz. Bu model sınırları (255) ve ayracın İLK ':' olduğunu elle
// pinler; username.go'daki bir sabit sessizce değişirse fuzz bunu yakalar.
func refParseUsername(raw string) (Route, bool) {
	i := strings.IndexByte(raw, ':')
	if i < 0 {
		return Route{}, false
	}

	user, target := raw[:i], raw[i+1:]

	if user == "" || target == "" {
		return Route{}, false
	}

	// Sınır BAYT cinsinden: çok baytlı bir ad, rune sayısı azken bile
	// sınırı aşabilir ve iki taraf aynı birimi saymazsa model ayrışır.
	if len(user) > 255 || len(target) > 255 {
		return Route{}, false
	}

	return Route{User: user, Target: target}, true
}

// FuzzParseUsername pins the parser's losslessness, not its absence of panics.
//
// Asıl mesele şu: handleChannel, route.User'ı Permissions'taki doğrulanmış
// "postern-user" ile == ile karşılaştırıyor. Parser bir gün adı kırpar,
// küçük harfe çevirir ya da Unicode normalize ederse, karşılaştırılan dizge
// DOĞRULANAN dizge olmaktan çıkar: "Yigit:web01" ile giren biri "yigit"
// olarak doğrulanmış bir oturumun kimlik kontrolünden geçebilir. O yüzden
// burada aranan özellik "panik atmıyor" değil, "tek bayt bile değiştirmiyor".
func FuzzParseUsername(f *testing.F) {
	// username_test.go'daki tablonun tamamı — tablo neyi çiviliyorsa fuzz
	// oradan başlasın.
	seeds := []string{
		"yigit:web01",
		"yigit",
		"yigit:",
		":web01",
		"yigit:web:01",
		"yigit:web01:extra",
		"",
		"yigit:" + strings.Repeat("w", 506),
		strings.Repeat("u", 256) + ":web01",

		// Sınırın tam üstü ve tam altı: 255 kabul, 256 ret olmalı.
		"a:" + strings.Repeat("b", 255),
		"a:" + strings.Repeat("b", 256),

		// Satır sonu ve NUL: hedef adı log'a ve DB'ye gidiyor; parser'ın
		// bunları temizlemediğini (ve temizlemeye BAŞLAMADIĞINI) sabitle.
		"a:b\nc",
		"a:b\x00c",

		// Çok baytlı ad: normalize edilirse burada yakalanır.
		"şeyma:web01",
		":",
		"::",
		"a::b",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		got, err := ParseUsername(raw)

		wantRoute, wantOK := refParseUsername(raw)

		if (err == nil) != wantOK {
			t.Fatalf("kabul kümesi ayrıştı: ParseUsername(%q) err=%v, model kabul=%v", raw, err, wantOK)
		}

		if err != nil {
			// Reddedilen girdide yarım bir Route dönmemeli: çağıran hatayı
			// gözden kaçırırsa kısmen dolu bir hedefe yönlenir.
			if got != (Route{}) {
				t.Fatalf("reddedilen girdide Route dolu: %q → %+v", raw, got)
			}
			return
		}

		if got != wantRoute {
			t.Fatalf("ParseUsername(%q) = %+v, model %+v", raw, got, wantRoute)
		}

		// KAYIPSIZLIK: parçalar ayraçla birleştirildiğinde ham girdinin
		// BAYT BAYT aynısı çıkmalı. Kırpma/normalize buradan geçemez.
		if rejoined := got.User + routeSep + got.Target; rejoined != raw {
			t.Fatalf("kayıp var: ParseUsername(%q) → %q (User=%q Target=%q)", raw, rejoined, got.User, got.Target)
		}

		// User içinde ayraç kalmamalı: kalırsa "a:b:c" iki farklı şekilde
		// bölünebilir ve kimlik karşılaştırması belirsizleşir.
		if strings.Contains(got.User, routeSep) {
			t.Fatalf("User ayraç içeriyor: %q", got.User)
		}

		if got.User == "" || got.Target == "" {
			t.Fatalf("boş parça kabul edildi: %+v (raw %q)", got, raw)
		}

		// IDEMPOTENS: birleştirilmiş dizgeyi yeniden ayrıştırmak aynı
		// Route'u vermeli. Vermezse ayrıştırma "sabit nokta" değildir ve
		// aynı kullanıcı adı iki katmanda iki farklı hedefe çözülebilir.
		again, err := ParseUsername(got.User + routeSep + got.Target)
		if err != nil {
			t.Fatalf("yeniden ayrıştırma reddedildi: %q (raw %q): %v", got.User+routeSep+got.Target, raw, err)
		}
		if again != got {
			t.Fatalf("idempotens ihlali: %+v → %+v (raw %q)", got, again, raw)
		}
	})
}
