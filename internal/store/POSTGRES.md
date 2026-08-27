# PostgreSQL taşıması — kalan iş listesi

SQLite geçici bir motordu. Bu tur `internal/store` **lehçe-nötr** hale
getirildi: Go içindeki SQL artık iki motorda da aynı anlama geliyor.
Aşağıdaki liste, gerçekten motora bağlı kalan her şeyi sayıyor.

Kural: bu dosyada yazmayan bir yerde motor bağımlılığı bulursanız, ya
liste eskimiştir ya da nötrleştirme kaçmıştır — ikisi de düzeltilmeli.

## 1. Go tarafı: yalnızca `dialect.go`

`store.go` (1500+ satır) ve `migrate.go` içinde tek bir SQLite referansı
yok. Motor bağımlılığının tamamı `dialect.go` içinde:

| Sembol | Şimdi | PostgreSQL'de |
|---|---|---|
| `driverName` | `"sqlite"` | `"pgx"` |
| `dsn(path)` | dosya yolu + PRAGMA | `postgres://…` bağlantı dizesi |
| `isUniqueViolation` | SQLite 2067 / 1555 | SQLSTATE `23505` |
| `isForeignKeyViolation` | SQLite 787 | SQLSTATE `23503` |
| `isRestrictViolation` | SQLite 787 / 1811 | SQLSTATE `23503` |
| `tableExistsQuery` | `sqlite_master` | `information_schema.tables` |
| `limitClause` / `limitArgs` | koşullu `LIMIT` | aynı — değişmez |
| `ciEq` / `ciOrder` | `lower()` | aynı — değişmez |

`limitClause` ve `ciEq` bilerek listede: ikisi de **iki motorda da**
çalışan yazımı seçiyor, yani taşınırken dokunulmayacak. Orada olmalarının
sebebi motor değişmesi değil, "bu karar lehçe yüzünden verildi" bilgisinin
tek yerde durması.

### Yer tutucular

Tüm sorgular `?` yerine `$1, $2, …` kullanıyor. SQLite ikisini de kabul
ediyor, PostgreSQL yalnızca numaralı olanı. Bu yüzden dönüşüm bu turda
yapıldı ve mevcut testler koruyor.

### İşlem yalıtımı

Göç çalıştırıcısı `sql.LevelSerializable` istiyor. SQLite'ta bu zaten
tek yazar demek; PostgreSQL'de gerçek serializable yalıtımıdır ve
**serialization failure (SQLSTATE `40001`) döndürebilir**. Göç
çalıştırıcısına yeniden deneme eklenmeli ya da `ReadCommitted`'a
inilmeli — göçler zaten advisory lock ile korunacaksa ikincisi yeterli.

### Çok ifadeli `Exec`

`applySingleMigration` bir göç dosyasının tamamını tek `Exec` ile
gönderiyor. `pgx`'in **stdlib sürücüsü genişletilmiş protokol kullanır ve
tek çağrıda birden fazla ifadeyi kabul etmez.** Seçenekler: dosyayı `;`
ile bölmek (dolar-tırnaklı gövdeler yüzünden kırılgan), `pgx`'i simple
protocol'e almak, ya da her göçü tek ifadeye indirmek. **Karar verilmeli.**

## 2. Şema tarafı: yeniden yazılacak

Göç dosyaları SQLite ağzıyla yazıldı. PostgreSQL şeması sıfırdan
yazılacak; taşınacak farklar:

### `COLLATE NOCASE` → `lower()` ifade indeksi *(hazır)*

PostgreSQL'de `NOCASE` diye bir collation yok. Karşılığı ya `CITEXT`
eklentisi ya da `lower()` ifade indeksi; **`lower()` seçildi**, çünkü
eklenti gerektirmiyor ve SQLite'ta da çalışıyor.

`009_case_insensitive_indexes` bu indeksleri **zaten kurdu** ve
sorgular onları kullanıyor. PostgreSQL şemasına 009'daki üç
`CREATE UNIQUE INDEX` olduğu gibi taşınacak, sütunlardaki
`COLLATE NOCASE` ise hiç yazılmayacak:

- `targets (lower(name))`
- `group_mappings (lower(external_group), role_id)`
- `unmapped_groups (lower(name))`

Doğrulama hazır: `TestCaseInsensitiveWithoutNOCASE` göçleri
`COLLATE NOCASE` sökülmüş halde uygular — yani PostgreSQL şemasının
aynısını kurar — ve harf duyarsız sayılan her yolu koşturur.
`TestCIColumnsMatchesSchema` de listenin şemadan kaymadığını kontrol eder.

### `AUTOINCREMENT` → kimlik sütunu

Tek yer: `004_admin_log.up.sql`

```sql
id INTEGER PRIMARY KEY AUTOINCREMENT   -- SQLite
id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY   -- PostgreSQL
```

`BIGSERIAL` de olur ama IDENTITY standart olan ve sütunu elle yazmaya
karşı koruyor — denetim kaydında istediğimiz tam olarak bu.

### Tip eşlemesi

Şemada yalnızca iki tip var: 36 `TEXT`, 12 `INTEGER`.

- `TEXT` → `TEXT` (PostgreSQL'de `VARCHAR(n)`'den performans farkı yok)
- Zaman sütunları (`INTEGER`, Unix saniye) → **`BIGINT` olarak kalacak.**
  `TIMESTAMPTZ`'ye çevirmek daha "doğru" görünür ama Go tarafındaki
  `time.Unix` dönüşümleri ve testler buna göre yazılı; taşımayı tek
  hamlede bitirmek için tip değişmiyor. (Karar: 2026-08-27)
- Boole sütunları (`is_admin`, `sso_only`, `settings.encrypted`) →
  **`BOOLEAN` yapılacak.**

  Okuma tarafı iki motorda da sorunsuz: kod doğrudan `*bool` tarıyor ve
  `driver.Bool` INTEGER 0/1'i zaten çeviriyor. Kırılan yer **yazma**:
  kod parametre olarak Go `bool` gönderiyor (`SET is_admin = $1`) ve
  PostgreSQL `INTEGER` sütununa boolean kabul etmez —
  *"column is of type integer but expression is of type boolean"*.

  Sütunu `BOOLEAN` yapmak bunu **Go tarafına hiç dokunmadan** çözer;
  `INTEGER`'da bırakıp Go tarafında 0/1'e çevirmek ise üç yazma
  noktasını da elle düzeltmek demek. Ucuz olan taraf şema.

### Bağlantı ayarları

`dsn()` içindeki PRAGMA'ların hiçbirinin PostgreSQL karşılığı yok ve
gerekmiyor:

| PRAGMA | Neden vardı | PostgreSQL |
|---|---|---|
| `foreign_keys(1)` | SQLite FK'yi varsayılan kapalı tutar | Her zaman açık |
| `busy_timeout(5000)` | Tek yazar kilidi | Yok — MVCC |
| `journal_mode(WAL)` | Okur/yazar çakışmasın | Yok — MVCC |

Yerine gelecekler: `sslmode`, havuz ayarları (`SetMaxOpenConns`,
`SetMaxIdleConns`, `SetConnMaxLifetime`) ve bağlantı zaman aşımı.
SQLite'ta havuz ayarı anlamsızdı, PostgreSQL'de **gerekli**.

## 3. Test tarafı

- `newEmptyStore` bir dosya yolu açıyor; PostgreSQL'de yerine
  testcontainers ile ayağa kalkan bir örnek ya da test başına ayrı
  şema (`CREATE SCHEMA test_xxx`) gelecek.
- `dialect_test.go` içindeki `newPostgresLikeStore` taşıma bitince
  **silinecek**: gerçek PostgreSQL'e karşı koştuktan sonra taklide
  gerek kalmıyor.
- `migrate_test.go` içindeki `tableExists` yardımcısı doğrudan
  `sqlite_master` sorguluyor — `tableExistsQuery`'ye geçmeli.

## 4. Taşıma sırası

1. `dialect.go`'yu PostgreSQL'e göre yaz, `driverName`'i çevir.
2. Göç dosyalarını PostgreSQL ağzıyla yeniden yaz (yukarıdaki farklar).
3. Çok ifadeli `Exec` kararını uygula.
4. Test altyapısını testcontainers'a taşı.
5. SQLite'ı ve `newPostgresLikeStore`'u sil.

Veri taşıması **yok**: SQLite üretimde hiç çalışmadı.
