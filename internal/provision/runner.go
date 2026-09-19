package provision

/*
 * Planı hedefte postern'in KENDİ yönetim hesabıyla koşturan Runner.
 *
 * ⚠️ BU DOSYA, CANLI TESTTEKİ `ssh` ÇAĞRISININ YERİNİ ALIYOR — VE ASIL
 * SEBEP TEST DEĞİL. Test, bir insanın elinde duran sertifikayla
 * bağlanıyordu; ürünün kendisi bunu hiç yapmıyordu. Yani ölçülen şey
 * ürünün yolu değil, testin kendi kurduğu bir yoldu. Burada bağlantıyı
 * postern kuruyor: sertifika bellekte üretiliyor, iki dakika yaşıyor ve
 * kimsenin eline geçmiyor.
 */

import (
	"context"
	"errors"
	"fmt"

	"github.com/Warewave-Technology/postern/v2/internal/ca"
	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/upstream"
)

/*
 * SSHRunner, açık bir yönetim bağlantısı üzerinde adımları çalıştırır.
 *
 * ⚠️ BAĞLANTI ADIM BAŞINA DEĞİL, KOŞU BAŞINA. Her adım için yeniden
 * bağlanmak, hedefin günlüğüne bir yayılım koşusu başına onlarca root
 * girişi yazardı — makinenin sahibi için okunamaz bir iz.
 */
type SSHRunner struct {
	conn *upstream.Conn
}

/*
 * Connect, hedefe yönetim hesabıyla bağlanır ve bir Runner döner.
 *
 * actor ve reason hedefin kendi sshd günlüğüne düşen KeyID'ye giriyor
 * (bkz. upstream.DialManagement).
 *
 * ⚠️ HATA upstream'İN SINIFIYLA, ErrUnreachable'A SARILMADAN DÖNÜYOR —
 * VE İLK HÂLİ SARIYORDU. Sarmak, reddedilen bir sertifikayı ve değişmiş
 * bir host anahtarını da "ulaşılamadı" kovasına atıyordu: panelde "hedef
 * sertifikayı reddetti" cümlesinin hemen altında ham metin "target could
 * not be reached:" diye başlıyor, iki satır birbirini çürütüyordu. Daha
 * önemlisi yanlış iş söylüyordu: ulaşılamayan makinede beklemek işe
 * yarar, CA'ya güvenmeyen makinede asla. upstream/hostkey.go bu
 * düzleştirmeyi ölçüp ayrı sınıflar koymuştu. Bağlantı kurulamadıysa
 * ortada bir Apply raporu yok; çağıran upstream.ErrRefused,
 * ErrHostKeyMismatch, ErrHandshake ve ErrUnreachable'a bakarak karar
 * veriyor.
 */
func Connect(ctx context.Context, t model.Target, authority *ca.CA, actor, reason string) (*SSHRunner, error) {
	conn, err := upstream.DialManagement(ctx, t, authority, actor, reason)
	if err != nil {
		return nil, err
	}

	return &SSHRunner{conn: conn}, nil
}

// Close, yönetim bağlantısını kapatır.
func (r *SSHRunner) Close() error {
	if r == nil || r.conn == nil {
		return nil
	}

	return r.conn.Close()
}

// Conn, yeteneği ölçmek gibi plan dışı okumalar için bağlantının kendisi.
func (r *SSHRunner) Conn() *upstream.Conn { return r.conn }

/*
 * Exec, tek bir adımı çalıştırır ve STDOUT'u döner.
 *
 * ⚠️ "KOMUT DÜŞTÜ" İLE "MAKİNEYE ULAŞAMADIM" AYRIMI BURADA TAHMİN DEĞİL.
 * `ssh` ikilisiyle koşarken elimizde yalnızca çıkış kodu vardı ve 255'i
 * sezgiyle yorumluyorduk — uzak komutun kendisi de 255 dönebilir.
 * Protokol seviyesinde belirsizlik yok: CommandError, hedefin komutu
 * çalıştırıp bir kod bildirdiği anlamına geliyor; öbür her şey
 * cevapsızlık.
 *
 * Hata sebebi (stderr) CommandError'ın metninde duruyor ve Apply onu
 * Result.Err olarak kaydediyor; stdout'a karıştırılmıyor, çünkü stdout
 * VERİ olarak da okunuyor (bkz. upstream.Conn.Exec).
 */
func (r *SSHRunner) Exec(ctx context.Context, command, stdin string) (string, error) {
	if r == nil || r.conn == nil {
		return "", fmt.Errorf("%w: no management connection", ErrUnreachable)
	}

	return answer(r.conn.Exec(ctx, command, stdin))
}

/*
 * answer, upstream'in cevabını Apply'ın sınıflarına çevirir.
 *
 * ⚠️ HEDEFİN CEVABI OLDUĞU GİBİ GEÇİYOR, CEVAPSIZLIK ErrUnconfirmed
 * OLUYOR — ErrUnreachable DEĞİL, ve ilk hâli öyleydi. Cevapsız kalan
 * bir adım makinede koşmuş olabilir (bağlam komutun ortasında dolunca
 * OpenSSH çocuğu öldürmüyor); "ulaşılamadı" demek "hiçbir şey olmadı"
 * demek ve bu yanlış olabilir. Her hatayı "başarısız" saymak da yanlış:
 * sudoers doğrulaması düşen bir makine bir cevap, bakılacak yer hedefin
 * kendisi. Üç sınıf, üç ayrı cümle.
 */
func answer(stdout string, err error) (string, error) {
	if err == nil {
		return stdout, nil
	}

	var cmdErr *upstream.CommandError
	switch {
	case errors.As(err, &cmdErr):
		return stdout, err
	case errors.Is(err, upstream.ErrNoAnswer):
		return stdout, fmt.Errorf("%w: %w", ErrUnconfirmed, err)
	}

	return stdout, fmt.Errorf("%w: %w", ErrUnreachable, err)
}
