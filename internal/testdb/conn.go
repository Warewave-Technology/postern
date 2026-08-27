package testdb

import (
	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// openRaw, şema kurulumu/temizliği için çıplak bir bağlantı açar.
//
// store.Open KULLANILMIYOR: bu paket store'a bağımlı olmamalı — store'un
// kendi testleri buradan DSN alıyor ve tersi bir bağımlılık döngü olurdu.
func openRaw(dsn string) (*sql.DB, error) {
	return sql.Open("pgx", dsn)
}
