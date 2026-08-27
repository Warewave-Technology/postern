package store

// Veritabanı lehçesine bağımlı olan her şey burada toplanıyor.
//
// Bir önceki turda burası SQLite'ı kapsıyordu; taşıma bu dosyayı ve
// migrations/ klasörünü yeniden yazmaya indi — store.go'nun 1500 satırına
// hiç dokunulmadı. Dosya, motorun bir gün yine değişebileceği varsayımıyla
// duruyor.

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	// Sürücü: database/sql'e "pgx" adıyla kendini kaydeder (yan etki) ve
	// *pgconn.PgError tipini hata sınıflandırması için verir.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// driverName, database/sql'e kayıtlı sürücü adı.
const driverName = "pgx"

// limitClause, "sınırsız" durumunu lehçeye uygun biçimde döner.
//
// PostgreSQL'de "sınırsız" diye bir LIMIT değeri yok (LIMIT ALL ya da
// cümlenin hiç olmaması gerekir). Sınırı sorgu METNİNDE çözmek her iki
// durumu da tek yoldan halleder: sınırsızsa cümleyi hiç koyma.
func limitClause(limit int, placeholder string) string {
	if limit <= 0 {
		return ""
	}
	return "\n\t\tLIMIT " + placeholder
}

// limitArgs, limitClause ile birlikte kullanılacak argümanları döner.
func limitArgs(limit int, base ...any) []any {
	if limit <= 0 {
		return base
	}
	return append(base, limit)
}

// --- hata sınıflandırma ---
//
// PostgreSQL ihlalleri SQLSTATE ile bildirir:
//
//	23505 unique_violation
//	23503 foreign_key_violation
//	23514 check_violation

const (
	sqlstateUniqueViolation     = "23505"
	sqlstateForeignKeyViolation = "23503"
)

// pgCode, hatanın SQLSTATE'ini döner; PostgreSQL hatası değilse "".
func pgCode(err error) string {
	var e *pgconn.PgError
	if !errors.As(err, &e) {
		return ""
	}
	return e.Code
}

// isUniqueViolation, "bu kayıt zaten var" hatası mı?
//
// İfade indekslerini de kapsar: 009'daki lower() indekslerinin ihlali de
// 23505 döner, sütun üzerindeki düz UNIQUE ile aynı kod.
func isUniqueViolation(err error) bool {
	return pgCode(err) == sqlstateUniqueViolation
}

// isForeignKeyViolation, "işaret ettiğin satır yok" hatası mı? (INSERT)
//
// ⚠️ isRestrictViolation ile AYNI SQLSTATE'e bakıyor — PostgreSQL ikisini
// ayırmaz. Ayrım çağrının yönünden geliyor: DELETE yapan fonksiyonlar
// önce isRestrictViolation'a soruyor (ve ErrConflict diyor), INSERT
// yolundaki hata ise translateErr'e düşüyor (ve ErrNotFound diyor).
// Yani iki fonksiyonun ayrı durmasının sebebi kod farkı değil, ÇAĞRI
// YERİNİN taşıdığı bilgi. (SQLite'ta gerçekten iki ayrı koddu: 787 ve
// RESTRICT için 1811.)
func isForeignKeyViolation(err error) bool {
	return pgCode(err) == sqlstateForeignKeyViolation
}

// isRestrictViolation, "bu satıra hâlâ referans var" hatası mı? (DELETE)
func isRestrictViolation(err error) bool {
	return pgCode(err) == sqlstateForeignKeyViolation
}

// dsn, bağlantı dizesini hazırlar.
//
// SQLite'takinin aksine burada bir dosya yolu değil, ağ üzerinden bir
// sunucuya bağlantı var. Zorunlu tek müdahale: sslmode belirtilmemişse
// VARSAYILANI KAPALI DEĞİL, doğrulanmış TLS yapmak.
//
// libpq'nun varsayılanı "prefer"dır: TLS'i dener, sunucu istemezse düz
// metne SESSİZCE düşer. Bir bastion'ın kimlik ve denetim verisi için bu
// kabul edilemez — düşürme saldırısı zaten tam olarak budur. Belirtmeyen
// yapılandırma "verify-full" alır; gerçekten TLS istemeyen kurulum
// (localhost, sidecar) bunu DSN'de AÇIKÇA yazmak zorunda.
func dsn(conn string) (string, error) {
	if strings.TrimSpace(conn) == "" {
		return "", fmt.Errorf("empty connection string")
	}

	// Anahtar=değer biçimi (host=... user=...) URL değil; olduğu gibi
	// geçiyoruz. sslmode'u oradan da zorlamak metin biçimini elle
	// kurcalamak demek ve o biçimi kullanan zaten pgx'e hâkim demektir.
	if !strings.Contains(conn, "://") {
		return conn, nil
	}

	u, err := url.Parse(conn)
	if err != nil {
		return "", fmt.Errorf("parse connection string: %w", err)
	}

	// ⚠️ u.Query() DEĞİL url.ParseQuery: ilki ayrıştırma hatasını YUTAR
	// ve kısmi sonucu döner. Noktalı virgülle ayrılmış ya da kaçışı
	// bozuk bir sorgu dizesinde bu, parametrelerin sessizce kaybolması
	// ve operatörün yazdığı sslmode'un fark edilmeden değişmesi demekti.
	// (Ölçüldü: "?sslmode=require;application_name=postern" girdisi
	// "?sslmode=verify-full" çıktısına dönüşüyordu.) Bağlantı dizesini
	// sessizce yeniden yazmak yerine reddediyoruz.
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", fmt.Errorf("parse connection string query: %w", err)
	}

	// Anahtar VAR ama değeri boş: "sslmode=" yazan bir yapılandırma
	// libpq varsayılanına (prefer) düşer, yani TLS kurulamazsa sessizce
	// düz metne iner. Üstüne bir ikincisini eklemek de işe yaramaz —
	// pgx ilkini okur. Sessizce düzeltmek yerine reddediyoruz.
	if _, present := q["sslmode"]; present && q.Get("sslmode") == "" {
		return "", fmt.Errorf("connection string has an empty sslmode " +
			"(remove it to get verify-full, or state one explicitly)")
	}

	if q.Get("sslmode") != "" {
		// ⚠️ ORİJİNAL METİN dönülüyor, u.String() değil.
		//
		// url.String() normalleştirme yapıyor ve host'suz bir URI'de
		// "//"yi düşürüyor: "postgres://?host=db.internal&..." çıktıda
		// "postgres:?host=..." oluyor. pgx parser'ı düz "postgres://"
		// ÖNEKİNE bakarak seçtiği için iki karakterin düşmesi onu
		// anahtar=değer parser'ına çeviriyor — ölçüldü: host yerel
		// sokete, veritabanı boşa, kullanıcı süreç sahibine düşüyor ve
		// TLS TAMAMEN KAYBOLUYOR. TLS düşürmesini önlemek için yazılmış
		// fonksiyonun kendisi düşürmeye sebep oluyordu.
		return conn, nil
	}

	// sslmode yok: orijinal metne EKLEYEREK ilerliyoruz, yeniden
	// serileştirerek değil. Fragment varsa ondan önce giriyor.
	base, fragment := conn, ""
	if i := strings.IndexByte(conn, '#'); i >= 0 {
		base, fragment = conn[:i], conn[i:]
	}

	// Ayırıcı METNE göre seçiliyor, u.RawQuery'ye göre değil: "?" ile
	// biten bir URI'de sorgu VAR ama BOŞ, ve RawQuery'ye bakan kod
	// oraya ikinci bir "?" koyardı. (Fuzz bunu buldu: "A://?")
	sep := "?"
	if strings.ContainsRune(base, '?') {
		sep = "&"
	}

	return base + sep + "sslmode=verify-full" + fragment, nil
}

// ciColumns, harf duyarsız karşılaştırılan sütunlar — şemadaki
// 009_case_insensitive_indexes göçünün Go tarafındaki karşılığı.
//
// ⚠️ Şemaya harf duyarsız bir sütun eklenirse BURAYA da eklenmeli;
// TestCIColumnsMatchesSchema ikisinin aynı hizada kalmasını denetler.
var ciColumns = map[string]bool{
	"targets.name":                  true,
	"group_mappings.external_group": true,
	"unmapped_groups.name":          true,
}

// ciEq, harf duyarsız eşitlik koşulu üretir.
//
// PostgreSQL'de sütuna gömülü harf duyarsız collation yok (CITEXT bir
// eklenti), o yüzden karşılaştırma sorguda AÇIKÇA duruyor. 009'daki
// lower() ifade indeksleri bu koşulu indeksten karşılar.
//
// placeholder'ı da lower()'a sarıyoruz: aranan değerin büyük/küçük
// yazımı çağırandan geliyor ve normalize edildiğine güvenemeyiz.
func ciEq(column, placeholder string) string {
	return "lower(" + column + ") = lower(" + placeholder + ")"
}

// ciOrder, harf duyarsız sıralama ifadesi üretir.
//
// Düz ORDER BY'ın sonucu veritabanının collation'ına göre değişir —
// C collation'da "Web01" < "app01", en_US.UTF-8'de tersi. lower() bu
// ortam bağımlılığını ortadan kaldırıyor.
func ciOrder(column string) string {
	return "lower(" + column + ")"
}

// tableExistsQuery, "bu adda bir tablo var mı" sorusunun SQL'i.
//
// current_schema() bilerek: testler her koşuyu ayrı bir şemaya alıyor ve
// sabit 'public' yazmak onları birbirine bağlardı.
const tableExistsQuery = `
	SELECT COUNT(*)
	FROM information_schema.tables
	WHERE table_schema = current_schema()
	  AND table_name = $1;
`
