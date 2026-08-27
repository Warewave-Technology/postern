package store

// Veritabanı lehçesine bağımlı olan her şey burada toplanıyor.
//
// NEDEN: SQLite geçici bir motor; üretimde PostgreSQL kullanılacak. O gün
// geldiğinde değişecek yerlerin dosyanın geneline dağılmış olması, taşımayı
// "her satırı gözden geçir" işine çevirirdi. Burada toplandığında taşıma
// bu dosyayı ve migrations/ klasörünü yeniden yazmaya iner.
//
// Sorguların kendisi zaten nötr tutuluyor: yer tutucular $1 biçiminde
// (ikisi de kabul ediyor), harf duyarsız karşılaştırmalar lower() ile
// açıkça yazılıyor, LIMIT koşullu kuruluyor.

import (
	"errors"
	"fmt"

	// Sürücü: database/sql'e "sqlite" adıyla kendini kaydeder (yan etki)
	// ve *sqlite.Error tipini hata sınıflandırması için verir.
	// modernc.org/sqlite saf Go — cgo yok, -race ile çalışır, tek binary.
	//
	// PostgreSQL'e taşınırken DEĞİŞECEK TEK IMPORT bu olmalı.
	"modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"
)

// limitClause, "sınırsız" durumunu lehçeye uygun biçimde döner.
//
// SQLite'ta LIMIT -1 "sınırsız" demek; PostgreSQL'de böyle bir şey yok
// (LIMIT ALL ya da cümlenin hiç olmaması gerekir). Sınırı sorgu METNİNDE
// çözerek ikisinde de çalışan tek yol: sınırsızsa cümleyi hiç koyma.
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
// PostgreSQL'e taşınırken burası SQLSTATE'lere çevrilecek:
//   23505 unique_violation      → ErrConflict
//   23503 foreign_key_violation → bağlama göre ErrNotFound / ErrConflict
//   23514 check_violation       → doğrulama hatası

// isUniqueViolation, "bu kayıt zaten var" hatası mı?
func isUniqueViolation(err error) bool {
	var e *sqlite.Error
	if !errors.As(err, &e) {
		return false
	}
	code := e.Code()
	return code == sqlitelib.SQLITE_CONSTRAINT_UNIQUE ||
		code == sqlitelib.SQLITE_CONSTRAINT_PRIMARYKEY
}

// isForeignKeyViolation, "işaret ettiğin satır yok" hatası mı? (INSERT)
func isForeignKeyViolation(err error) bool {
	var e *sqlite.Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Code() == sqlitelib.SQLITE_CONSTRAINT_FOREIGNKEY
}

// isRestrictViolation, "bu satıra hâlâ referans var" hatası mı? (DELETE)
//
// SQLite ON DELETE RESTRICT'i içeride tetikleyiciyle uyguladığı için
// ihlali TRIGGER (1811) olarak raporlar; varsayılan NO ACTION ise
// FOREIGNKEY (787) verir. PostgreSQL ikisini de 23503 der ve ayrımı
// çağrının yönünden (INSERT mi DELETE mi) çıkarmak gerekecek.
func isRestrictViolation(err error) bool {
	var e *sqlite.Error
	if !errors.As(err, &e) {
		return false
	}
	code := e.Code()
	return code == sqlitelib.SQLITE_CONSTRAINT_FOREIGNKEY ||
		code == sqlitelib.SQLITE_CONSTRAINT_TRIGGER
}

// dsn, bağlantı dizesini kurar.
//
// PRAGMA'lar SQLite'a özgü: PostgreSQL'de foreign key her zaman zorunlu,
// WAL kavramı yok, kilit bekleme sunucu tarafında.
func dsn(path string) string {
	return fmt.Sprintf("%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)
}

// driverName, database/sql'e kayıtlı sürücü adı.
const driverName = "sqlite"

// ciColumns, harf duyarsız karşılaştırılan sütunlar — şemadaki
// 009_case_insensitive_indexes göçünün Go tarafındaki karşılığı.
//
// ⚠️ Şemaya harf duyarsız bir sütun eklenirse BURAYA da eklenmeli.
// Unutulursa sorgu SQLite'ta (NOCASE sayesinde) çalışmaya devam eder ama
// PostgreSQL'de sessizce harf duyarlı olur — yani hata değil, davranış
// kayması. Bu yüzden liste tek yerde duruyor ve testi var.
var ciColumns = map[string]bool{
	"targets.name":                  true,
	"group_mappings.external_group": true,
	"unmapped_groups.name":          true,
}

// ciEq, harf duyarsız eşitlik koşulu üretir.
//
// lower() İKİ motorda da var; COLLATE NOCASE yalnız SQLite'ta,
// CITEXT yalnız PostgreSQL'de. Ortak payda lower() olduğu için
// karşılaştırma sorgunun içinde açıkça duruyor — sütun tanımına
// gömülü olmadığından motor değişince davranış değişmiyor.
//
// placeholder'ı da lower()'a sarıyoruz: aranan değerin büyük/küçük
// yazımı çağırandan geliyor ve normalize edildiğine güvenemeyiz.
func ciEq(column, placeholder string) string {
	return "lower(" + column + ") = lower(" + placeholder + ")"
}

// ciOrder, harf duyarsız sıralama ifadesi üretir.
//
// Sıralama da lehçeye bağlı: PostgreSQL'de düz ORDER BY sonucu veritabanı
// collation'ına göre değişir (C collation'da "Web01" < "app01"), SQLite'ta
// ise sütunun COLLATE'ine göre. lower() ikisini de ortadan kaldırıyor.
func ciOrder(column string) string {
	return "lower(" + column + ")"
}

// tableExistsQuery, "bu adda bir tablo var mı" sorusunun SQL'i.
//
// Katalog sorgusu tamamen lehçeye bağlı ve ORTAK BİR YAZIMI YOK:
// SQLite'ta sqlite_master, PostgreSQL'de information_schema.tables
// (ya da pg_catalog.pg_class). Bu yüzden burada duruyor.
//
// PostgreSQL karşılığı:
//
//	SELECT COUNT(*) FROM information_schema.tables
//	WHERE table_schema = current_schema() AND table_name = $1;
const tableExistsQuery = `
	SELECT COUNT(*)
	FROM sqlite_master
	WHERE type = 'table'
	  AND name = $1;
`
