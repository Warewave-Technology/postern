package provision

import (
	"context"
	"testing"
)

/*
 * ⚠️ MATCH BLOĞU OLAN HEDEFTE GENEL OKUMA YANLIŞ YOLU VERİYOR — demo
 * hedefinde ölçüldü. sshd_config'e
 *
 *     Match User jitayse
 *       AuthorizedPrincipalsFile /etc/ssh/jit_principals/%u
 *
 * eklendiğinde `sshd -T` hâlâ /etc/ssh/auth_principals/%u diyor,
 * `sshd -T -C user=jitayse` ise /etc/ssh/jit_principals/%u. Postern
 * dosyayı ilkine yazsa hak "uygulandı" görünür ve kişi giremezdi.
 *
 * Kabul karşı örneği: Match bloğu yokken iki okuma da aynı şeyi
 * söylüyor, yani ret/kabul farkı komutun kendisinden geliyor.
 */
func TestPrincipalsPatternReadsTheAccountsOwnContext(t *testing.T) {
	ctx := context.Background()
	const global = "/etc/ssh/auth_principals/%u"

	matched := runnerFor(t, hostAnswers(map[string]string{
		"sudo -n sshd -T -C user=jitayse 2>/dev/null | awk 'tolower($1)==\"authorizedprincipalsfile\"{print $2}'": "/etc/ssh/jit_principals/%u\n",
	}))
	if got := PrincipalsPatternFor(ctx, matched, "jitayse", global); got != "/etc/ssh/jit_principals/%u" {
		t.Errorf("Match bloğu görülmedi: %q", got)
	}

	plain := runnerFor(t, hostAnswers(map[string]string{
		"sudo -n sshd -T -C user=jitayse 2>/dev/null | awk 'tolower($1)==\"authorizedprincipalsfile\"{print $2}'": global + "\n",
	}))
	if got := PrincipalsPatternFor(ctx, plain, "jitayse", global); got != global {
		t.Errorf("Match bloğu yokken değer değişti: %q", got)
	}
}

/*
 * ⚠️ OKUNAMAYAN HEDEF BUGÜNKÜ DAVRANIŞTA KALIYOR, BOŞ YOLA DÜŞMÜYOR.
 * Boş desen "principals dosyası yazma" demek; okunamayan bir hedefte
 * ona düşmek, sshd'si dosya bekleyen bir makinede hesabı açıp kapıyı
 * kapalı bırakırdı.
 *
 * ⚠️ AD KOMUTA GİRMEDEN ÖNCE ELENİYOR. Kabuk metakarakteri taşıyan bir
 * ad için komut hiç kurulmuyor; CapabilityCommands'ın sabit olma
 * kararı bu katmanda ad doğrulamasıyla korunuyor.
 */
func TestPrincipalsPatternFallsBackInsteadOfGuessing(t *testing.T) {
	ctx := context.Background()
	const global = "/etc/ssh/auth_principals/%u"

	silent := runnerFor(t, answerSilence)
	if got := PrincipalsPatternFor(ctx, silent, "jitayse", global); got != global {
		t.Errorf("cevapsız hedefte genel değere düşülmedi: %q", got)
	}

	none := runnerFor(t, hostAnswers(map[string]string{
		"sudo -n sshd -T -C user=jitayse 2>/dev/null | awk 'tolower($1)==\"authorizedprincipalsfile\"{print $2}'": "none\n",
	}))
	if got := PrincipalsPatternFor(ctx, none, "jitayse", global); got != global {
		t.Errorf("\"none\" genel değeri ezdi: %q", got)
	}

	var asked string
	spy := execFunc(func(ctx context.Context, command, stdin string) (string, error) {
		asked = command
		return "/tmp/pwned/%u\n", nil
	})
	if got := PrincipalsPatternFor(ctx, spy, "evil; rm -rf /", global); got != global {
		t.Errorf("kabuk metakarakterli ad kabul edildi: %q", got)
	}
	if asked != "" {
		t.Errorf("geçersiz ad için komut kuruldu: %q", asked)
	}
}

// execFunc, Runner'ı tek bir fonksiyonla karşılayan yardımcı.
type execFunc func(ctx context.Context, command, stdin string) (string, error)

func (f execFunc) Exec(ctx context.Context, command, stdin string) (string, error) {
	return f(ctx, command, stdin)
}
