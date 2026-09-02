package ldap

import (
	"context"
	"testing"

	"github.com/warewave/postern/internal/ldap/ldaptest"
)

/*
 * ⚠️ İPTAL KANCASI SERBEST BIRAKILMALI.
 *
 * connect, ctx iptal edilirse bağlantıyı koparan bir
 * context.AfterFunc kaydediyor. Kaydın dönüş değeri (stop) atılıyordu:
 * `stop := ...; _ = stop`. AfterFunc kaydı ebeveyn context'e çocuk
 * olarak takılıyor ve yalnızca stop çağrılınca çözülüyor — yani her
 * arama, ebeveyn yaşadığı sürece bir kayıt ve kapalı bir bağlantıyı
 * canlı tutan bir closure bırakıyordu. Senkronizasyon koşusunda
 * kullanıcı başına bir tane.
 *
 * ⚠️ BU TESTİN ÖLÇTÜĞÜ SINIR. Kaydın gerçekten çözüldüğünü doğrudan
 * gözlemenin dışarıdan bir yolu yok: children haritası context
 * paketinin içinde. Burada ölçülen, sözleşmenin çağıranın elinde
 * OLMASI: connect bir release döndürüyor, çağrılabiliyor ve iki kez
 * çağrılmak güvenli. Sızıntının kendisini kapatan şey, altı çağrı
 * yerinin de `defer conn.Close()` yerine `defer release()` demesi —
 * ki bunu derleyici zorluyor, connect artık Close'a yetecek bir şey
 * döndürmüyor.
 */
func TestConnectHandsBackAWayToReleaseTheCancelHook(t *testing.T) {
	srv, err := ldaptest.New(func(string, string, []string) ldaptest.Response {
		return ldaptest.Response{}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	src, err := New(Config{
		URL:      srv.URL(),
		UserBase: "ou=people,dc=test", UserFilter: "(cn=%s)",
		GroupBase: "ou=groups,dc=test", GroupFilter: "(member=%s)",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, release, err := src.connect(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if conn == nil || release == nil {
		t.Fatal("connect bağlantıyı ya da serbest bırakmayı vermedi")
	}

	release()
	// ⚠️ İKİ KEZ ÇAĞRILABİLMELİ: bind hatasında connect kendisi
	// çağırıyor ve çağıran da defer etmiş olabilir.
	release()
}
