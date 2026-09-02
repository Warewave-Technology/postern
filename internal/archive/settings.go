package archive

import (
	"context"
	"errors"
	"fmt"

	"github.com/warewave/postern/internal/objstore"
	"github.com/warewave/postern/internal/store"
)

/*
 * Yükleme kimliğinin panelden verilebilmesi.
 *
 * ⚠️ YALNIZCA KİMLİK — HEDEF DEĞİL. endpoint, bucket, region, prefix ve
 * ca_file config dosyasında kalıyor ve panelden DEĞİŞTİRİLEMİYOR.
 *
 * Sebebi ölçülmüş bir saldırı sınıfı: federation.go'daki yorum, panel
 * admininin ldap.url'i kendi sunucusuna çevirip saklanan bind parolasını
 * aldığı yolu anlatıyor. S3'te aynı yol var, üstüne bir fazlası daha:
 * saldırgan kendi kovasını gösterip TAZE bir kimlik girdiğinde postern
 * bundan sonraki HER OTURUM KAYDINI ona yükler. Bu, "hedef değişirse
 * sırrı düşür" ile kapanmıyor — hedefi seçebilmenin kendisinden geliyor.
 *
 * Panelden is_admin verilmemesiyle aynı raf: ele geçirilmiş bir panel
 * oturumu, denetim izini başka bir yere yönlendirebilmemeli. Anahtar
 * döndürmek rutin bir iş ve panelde; hedefi taşımak bir kurulum kararı
 * ve host'ta.
 */

// Ayar anahtarları.
const (
	// KeyAccessKeyID, erişim anahtarı kimliği. Sır değil ama kimliğin
	// diğer yarısıyla birlikte durması gerekiyor.
	KeyAccessKeyID = "archive.access_key_id"

	// KeySecretAccessKey, gizli anahtar. MÜHÜRLÜ saklanıyor ve
	// panele hiç geri okunmuyor.
	KeySecretAccessKey = "archive.secret_access_key"
)

// CredentialSource, kimliğin NEREDEN geldiği. Panelin doğruyu
// söyleyebilmesi için gerekli: "buradan değiştiremezsin" demek,
// "değiştirdin ama hiçbir şey olmadı"dan iyidir.
type CredentialSource string

const (
	// FromHost: ortam değişkeni ya da 0600 dosya. Panel yazamaz.
	FromHost CredentialSource = "host"
	// FromPanel: ayarlar tablosundan.
	FromPanel CredentialSource = "panel"
	// FromNowhere: kimlik yok, yükleme duruyor.
	FromNowhere CredentialSource = "none"
)

/*
 * Credentials, yürürlükteki kimliği ve kaynağını çözer.
 *
 * ⚠️ HOST ÖNCE. Bu sıra, panelin sessizce yok sayılmasını değil, açıkça
 * "buradan yönetilmiyor" demesini sağlıyor: kaynak FromHost dönerse
 * panel alanı salt okunur çiziliyor. Tersi olsaydı, dosyayı koyan
 * operatörün ayarı panelden gelen bir değerle sessizce değişirdi.
 */
func Credentials(ctx context.Context, db *store.Store, hostKeyID, hostSecret string) (objstore.Credentials, CredentialSource, error) {
	if hostSecret != "" {
		return objstore.Credentials{
			AccessKeyID: hostKeyID, SecretAccessKey: hostSecret,
		}, FromHost, nil
	}

	id, err := db.Setting(ctx, KeyAccessKeyID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return objstore.Credentials{}, FromNowhere, fmt.Errorf("archive.Credentials: %w", err)
	}
	secret, err := db.Setting(ctx, KeySecretAccessKey)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return objstore.Credentials{}, FromNowhere, fmt.Errorf("archive.Credentials: %w", err)
	}

	// ⚠️ YARIM KİMLİK KİMLİK DEĞİL: yalnızca biri girilmişse yükleme
	// başlamıyor ve sebebi söyleniyor.
	if id == "" || secret == "" {
		return objstore.Credentials{}, FromNowhere, nil
	}
	return objstore.Credentials{AccessKeyID: id, SecretAccessKey: secret}, FromPanel, nil
}
