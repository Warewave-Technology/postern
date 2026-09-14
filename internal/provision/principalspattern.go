package provision

import (
	"context"
	"fmt"
	"strings"

	"github.com/Warewave-Technology/postern/internal/model"
)

/*
 * PrincipalsPatternFor, AuthorizedPrincipalsFile deseninin HESABIN
 * BAĞLAMINDA etkin değerini okur.
 *
 * ⚠️ BAĞLAMSIZ OKUMA MATCH BLOKLARINI GÖRMÜYOR ve bu ölçüldü. Yetenek
 * sondası `sudo -n sshd -T` çalıştırıyor; o çıktı yalnızca genel
 * yapılandırmanın birleşimi. Demo hedefine
 *
 *     Match User jitayse
 *       AuthorizedPrincipalsFile /etc/ssh/jit_principals/%u
 *
 * eklenip iki okuma karşılaştırıldı: bağlamsız okuma
 * `/etc/ssh/auth_principals/%u`, `-C user=jitayse` ile okuma
 * `/etc/ssh/jit_principals/%u` dedi. Yani Match bloklu bir kurulumda
 * postern dosyayı sshd'nin BAKMADIĞI yere yazıyor; hak "uygulandı"
 * görünüyor ve kişi giremiyor.
 *
 * ⚠️ KOMUTA GİREN TEK DEĞİŞKEN, ŞEKLİ DOĞRULANMIŞ HESAP ADI.
 * CapabilityCommands bilerek sabit; oraya değişken koymak config'e
 * erişen herkese filoda komut çalıştırma yetkisi verirdi. Burası plan
 * katmanı: ad zaten `^[a-z_][a-z0-9_.-]{0,31}$` kümesinde (kabuk
 * metakarakteri yok) ve uymayan ad için komut hiç kurulmuyor, genel
 * değere düşülüyor.
 *
 * ⚠️ OKUNAMAZSA GENEL DEĞER. sshd'si olmayan, sudo'suz ya da yaşlı bir
 * hedefte bu okuma başarısız olabiliyor; o durumda bağlamsız değer
 * bugünkü davranışın aynısı. Sessiz değil: çağıran farkı raporluyor.
 */
func PrincipalsPatternFor(ctx context.Context, r Runner, user, fallback string) string {
	if !model.ValidOSUserName(user) {
		return fallback
	}
	out, err := r.Exec(ctx, fmt.Sprintf(
		"sudo -n sshd -T -C user=%s 2>/dev/null | "+
			"awk 'tolower($1)==\"authorizedprincipalsfile\"{print $2}'", user), "")
	if err != nil {
		return fallback
	}
	got := strings.TrimSpace(out)
	// "none" = yönerge kapalı; boş = okunamadı. İkisi de genel değeri
	// ezmiyor: kapalıysa üst katman zaten principals dosyası yazmıyor.
	if got == "" || strings.EqualFold(got, "none") {
		return fallback
	}

	return got
}
