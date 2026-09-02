package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

/*
 * Kullanıcı girdisiyle çalışan denetim aramalarının SUNUCU TARAFI
 * zaman sınırı.
 *
 * ⚠️ NEDEN VAR: bağlantı havuzu 25 (store.go: SetMaxOpenConns) ve o
 * havuzu SSH KİMLİK DOĞRULAMASI paylaşıyor — auth.go'daki
 * UserByPublicKey ve AccountState her girişte oradan bağlantı alıyor.
 * Yani denetim ekranında çalışan birkaç pahalı sorgu, insanların
 * bastion'a girmesiyle aynı 25 bağlantı için yarışıyor. Kodun hiçbir
 * yerinde bir sorgu süresi sınırı YOKTU: yavaş bir arama, bitene kadar
 * bir bağlantıyı tutuyordu.
 *
 * ⚠️ DSN'e KONULMADI, SORGUYA KONULDU. Bağlantı dizesine global bir
 * statement_timeout yazmak göçleri de kapsardı — büyük bir tabloda
 * indeks kuran bir göç tam da o yüzden yarıda kesilirdi. Sınır
 * yalnızca dışarıdan gelen ölçütlerle çalışan okumalara ait.
 *
 * ⚠️ SET LOCAL, SET DEĞİL. Havuzdaki bağlantı bir sonraki isteğe geri
 * veriliyor; oturum düzeyinde SET yapmak, sınırı o bağlantıyı sonra
 * kullanan HERKESE — göç çalıştıran bir komuta bile — sızdırırdı.
 * SET LOCAL işlem bitince kendiliğinden kalkıyor.
 */

// searchTimeout, bir denetim aramasının veritabanında durabileceği süre.
//
// İndeksli aramalar milisaniye mertebesinde (bkz. 030 ve 031'deki
// ölçümler); 5 saniye "bir şeyler yanlış" demek için fazlasıyla geniş.
const searchTimeout = 5 * time.Second

/*
 * SetSearchTimeoutForTest, sunucu tarafı sınırı kısaltır.
 *
 * ⚠️ YALNIZCA TESTLER İÇİN. Sınırın gerçekten UYGULANDIĞINI ölçmenin
 * tek yolu onu aşan bir sorgu çalıştırmak; 5 saniyelik varsayılanla o
 * test her CI koşusuna beş saniye eklerdi ve büyük ihtimalle hiç
 * yazılmazdı. Ölçülmeyen bir koruma, olmayan bir korumadır.
 */
func (s *Store) SetSearchTimeoutForTest(d time.Duration) { s.searchTimeout = d }

// limit, yürürlükteki sunucu tarafı sınırı.
func (s *Store) searchLimit() time.Duration {
	if s.searchTimeout > 0 {
		return s.searchTimeout
	}
	return searchTimeout
}

/*
 * clientGrace, istemci tarafı iptalin sunucu tarafından SONRA gelmesi
 * için bırakılan pay.
 *
 * ⚠️ İKİ SAYAÇ VAR VE SIRALARI ÖNEMLİ. İstemci tarafı önce dolsaydı
 * hata "context deadline exceeded" olurdu — operatöre hiçbir şey
 * söylemeyen bir cümle. Sunucu tarafı önce dolunca 57014 geliyor ve
 * aramanın neden durduğunu söyleyebiliyoruz. İstemci sayacı yalnızca
 * son çare: veritabanına giden bağlantı tamamen takılırsa
 * statement_timeout'un raporu da gelmez.
 */
const clientGrace = 3 * time.Second

// ErrTooSlow, arama sunucu tarafı zaman sınırına takıldı.
//
// ErrInvalid DEĞİL: istek biçimsel olarak geçerliydi. Çağıranın
// söylemesi gereken şey "isteğin hatalı" değil, "bu arama fazla geniş".
var ErrTooSlow = errors.New("store: search took too long and was stopped")

/*
 * searchRows, sorguyu zaman sınırlı bir işlemde çalıştırır ve her
 * satır için scan'i çağırır.
 *
 * ⚠️ SATIRLAR İÇERİDE OKUNUYOR. *sql.Rows'u dışarı vermek, işlem
 * kapandıktan sonra okumaya çalışmak demek olurdu; sınırı kuran
 * işlemin ömrü, satırların okunduğu ömürle aynı olmak zorunda.
 *
 * ⚠️ COMMIT YOK, ROLLBACK VAR. Okuma işlemi; geri almak hem doğru hem
 * ucuz ve "buradan yazma çıkmaz"ı okuyana söylüyor.
 */
func (s *Store) searchRows(ctx context.Context, op, query string,
	args []any, scan func(*sql.Rows) error) error {

	limit := s.searchLimit()

	ctx, cancel := context.WithTimeout(ctx, limit+clientGrace)
	defer cancel()

	/*
	 * ⚠️ BURADA DA translateSearchErr. Havuz doluyken BeginTx, boş bir
	 * bağlantı bekleyerek bloke oluyor ve süre dolunca çıplak
	 * context.DeadlineExceeded dönüyor; translateErr onu tanımıyor ve
	 * operatöre 500 "internal error" gidiyordu. Oysa clientGrace'in
	 * var olma sebebi TAM OLARAK bu durum — veritabanına giden yolun
	 * takılması — ve kapsamadığı tek yer burasıydı.
	 */
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return translateSearchErr(op, err)
	}
	defer tx.Rollback() //nolint:errcheck // okuma işlemi

	// ⚠️ Süre PARAMETRE OLARAK GEÇİLEMİYOR: SET LOCAL bir yer tutucu
	// kabul etmiyor. Değer sabitten üretiliyor, dışarıdan gelen hiçbir
	// şey bu metne girmiyor.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(
		"SET LOCAL statement_timeout = %d;", limit.Milliseconds())); err != nil {
		return translateSearchErr(op, err)
	}

	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return translateSearchErr(op, err)
	}
	defer rows.Close()

	for rows.Next() {
		if err := scan(rows); err != nil {
			return translateSearchErr(op, err)
		}
	}
	return translateSearchErr(op, rows.Err())
}

/*
 * translateSearchErr, zaman aşımını ayırıp geri kalanı translateErr'e
 * bırakır.
 *
 * ⚠️ İKİ AYRI SAYAÇ, TEK CÜMLE. Sunucu tarafı sınır 57014 üretiyor;
 * istemci tarafı süre ise — ölçüldü — bambaşka bir hata veriyor:
 * "timeout: context deadline exceeded", SQLSTATE'siz. İkincisini
 * elemeseydik veritabanına giden bağlantının takıldığı durumda
 * operatör "internal error" görürdü; oysa olan şey aynı: arama
 * bitmedi.
 *
 * ⚠️ context.Canceled ELENMİYOR. O, istemcinin gitmesi demek —
 * sekmesini kapatan birine "aramanız fazla uzun sürdü" demenin
 * anlamı yok, zaten kimse okumuyor.
 */
func translateSearchErr(op string, err error) error {
	if err == nil {
		return nil
	}
	if isQueryCanceled(err) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", op, ErrTooSlow)
	}
	return translateErr(op, err)
}
