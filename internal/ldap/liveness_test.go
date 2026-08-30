package ldap

import (
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// entryWith, tek öznitelikli sahte bir giriş kurar.
func entryWith(name, value string) *goldap.Entry {
	return &goldap.Entry{
		DN: "uid=x,ou=people,dc=example,dc=com",
		Attributes: []*goldap.EntryAttribute{
			{Name: name, Values: []string{value}, ByteValues: [][]byte{[]byte(value)}},
		},
	}
}

// filetime, Unix zamanını AD'nin FILETIME biçimine çevirir (testin
// üretici tarafı: kod tüketici tarafını yazıyor, ikisi ayrı hesaplansın).
func filetime(t time.Time) int64 {
	return (t.Unix() + filetimeEpochOffsetSeconds) * filetimeTicksPerSecond
}

/*
 * ⚠️ SÜRESİ DOLMUŞ HESAP KAPALI SAYILIR.
 *
 * Süreli hesap, taşeron/danışman nüfusunun standart yönetim biçimi ve o
 * gün geldiğinde KİMSE bir şey yapmaz: disable bayrağı düşmez, grup
 * üyeliği kalkmaz, kayıt silinmez. Yalnızca bu alan geçmişte kalır —
 * yani tam da kimsenin müdahale etmediği için gözden kaçan nüfus.
 */
func TestAccountExpiredAD(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

	past := filetime(now.Add(-24 * time.Hour))
	e := entryWith("accountExpires", itoa(past))
	if expired, why := accountExpired(e, now); !expired {
		t.Fatal("dün dolmuş hesap süresiz sayıldı")
	} else if why == "" {
		t.Fatal("sebep boş — operatör neden reddedildiğini göremez")
	}

	future := filetime(now.Add(24 * time.Hour))
	if expired, _ := accountExpired(entryWith("accountExpires", itoa(future)), now); expired {
		t.Fatal("yarın dolacak hesap bugün dolmuş sayıldı")
	}
}

/*
 * ⚠️ AD "SÜRESİZ"İ İKİ AYRI DEĞERLE YAZIYOR ve ikisi de sahada var:
 * 0 (hiç ayarlanmamış) ve int64 tavanı (arayüzden "asla" seçilmiş).
 *
 * Yalnızca birini bilen kod, diğerini "1601 yılında dolmuş" diye okur
 * ve o dizindeki HERKESİ dışarı atar. Bu testin varlık sebebi o.
 */
func TestAccountExpiresNeverValues(t *testing.T) {
	now := time.Now()
	for _, v := range []string{"0", "9223372036854775807"} {
		if expired, why := accountExpired(entryWith("accountExpires", v), now); expired {
			t.Fatalf("accountExpires=%s süresiz olmalıydı, %q dendi", v, why)
		}
	}
}

// POSIX shadowExpire: 1970'ten itibaren GÜN. Negatif = süresiz.
func TestAccountExpiredShadow(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

	pastDays := now.Add(-48*time.Hour).Unix() / 86400
	if expired, _ := accountExpired(entryWith("shadowExpire", itoa(pastDays)), now); !expired {
		t.Fatal("geçmiş shadowExpire süresiz sayıldı")
	}

	futureDays := now.Add(48*time.Hour).Unix() / 86400
	if expired, _ := accountExpired(entryWith("shadowExpire", itoa(futureDays)), now); expired {
		t.Fatal("gelecek shadowExpire dolmuş sayıldı")
	}

	// ⚠️ -1 "süresiz"in POSIX yazımı; dolmuş saymak herkesi keserdi.
	if expired, _ := accountExpired(entryWith("shadowExpire", "-1"), now); expired {
		t.Fatal("shadowExpire=-1 dolmuş sayıldı")
	}
}

/*
 * ⚠️ ÇÖZÜMLENEMEYEN DEĞER "DOLMUŞ" DEĞİLDİR.
 *
 * liveness.go'nun genel yönü: koruma uygulanamıyorsa davranış eskisi
 * gibi kalır. Aksi hâlde bir şema farkı, toplu erişim kaybına dönerdi.
 */
func TestAccountExpiredIgnoresUnparseableValues(t *testing.T) {
	now := time.Now()
	for _, v := range []string{"", "never", "20261231000000Z", "abc"} {
		if expired, why := accountExpired(entryWith("accountExpires", v), now); expired {
			t.Fatalf("accountExpires=%q dolmuş sayıldı (%s)", v, why)
		}
		if expired, why := accountExpired(entryWith("shadowExpire", v), now); expired {
			t.Fatalf("shadowExpire=%q dolmuş sayıldı (%s)", v, why)
		}
	}
	// Öznitelik hiç yoksa da sessiz.
	if expired, _ := accountExpired(&goldap.Entry{}, now); expired {
		t.Fatal("özniteliksiz giriş dolmuş sayıldı")
	}
}

// accountDisabled, süre kontrolünü de kapsıyor: çağıranların hepsi tek
// soruya bakıyor ve ikinci bir dal eklemek zorunda kalmamalı.
func TestAccountDisabledCoversExpiry(t *testing.T) {
	past := filetime(time.Now().Add(-time.Hour))
	disabled, why := accountDisabled(entryWith("accountExpires", itoa(past)))
	if !disabled {
		t.Fatal("süresi dolmuş hesap accountDisabled'dan geçti")
	}
	if why == "" {
		t.Fatal("sebep boş")
	}
}

func itoa(v int64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b []byte
	for v > 0 {
		b = append([]byte{digits[v%10]}, b...)
		v /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
