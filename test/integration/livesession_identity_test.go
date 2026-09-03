//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/store"
)

/*
 * ⚠️ KİMLİK YALNIZCA EL SIKIŞMADA DENETLENİYORDU — VE BEDELİ ÖLÇÜLDÜ.
 *
 * Bir SSH bağlantısı süresiz açık kalabiliyor: `ssh -N`, ya da pek çok
 * kurumsal ssh_config'de varsayılan olan ControlMaster. Her yeni kanal
 * proxy.Open'a gidiyor ve orası kullanıcı satırını ADLA okuyup
 * rollerine bakıyordu; hesabın DURUMUNA hiç bakmıyordu.
 *
 * Sonucu: hesabı kapatmak — kayıtlı oturumu olan gerçek bir kullanıcı
 * için TEK işten çıkarma kolu, çünkü DeleteUser onları reddediyor —
 * kurulu bağlantıyı hiç etkilemiyordu. Ölçümde silinmiş hesap AYNI
 * bağlantı üzerinde yeni kanal açıp hedefte komut çalıştırdı ve bunun
 * için TAZE bir sertifika imzalandı.
 *
 * Bu iki test o pencereyi kapatıyor: ilki hesabın kapatılmasını, ikincisi
 * adın devredilmesini ölçüyor. İkisi de AYNI canlı bağlantı üzerinde.
 */
func TestDeactivatedAccountCannotOpenNewSessionsOnALiveConnection(t *testing.T) {
	caKeyPath, caAuthorizedKey := newTestCA(t)
	tgt := startCertTarget(t, caAuthorizedKey)
	tc := tgt.target()
	tc.Name = "web01"

	addr, hostPub, signer, db := testServerWithDB(t, caKeyPath, tc)
	ctx := context.Background()

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatalf("proxy'ye bağlanılamadı: %v", err)
	}
	defer client.Close()

	// Önce çalıştığını görüyoruz: kurgu tutmazsa ikinci yarının "başarısız"
	// olması hiçbir şey ölçmez.
	first, err := client.NewSession()
	if err != nil {
		t.Fatalf("ilk NewSession: %v", err)
	}
	out, err := first.Output("echo canli-baglanti")
	if err != nil {
		t.Fatalf("ilk exec: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "canli-baglanti" {
		t.Fatalf("ilk çıktı = %q", got)
	}
	first.Close()

	// ⚠️ İşten çıkarmanın ilk adımı. Bağlantı AÇIK kalıyor.
	if err := db.SetAccountState(ctx, "yigit", store.StateDeleted); err != nil {
		t.Fatalf("SetAccountState: %v", err)
	}

	second, serr := client.NewSession()
	if serr != nil {
		// Kanalın reddedilmesi de doğru cevap.
		return
	}
	defer second.Close()
	out2, eerr := second.Output("echo hesap-kapatildiktan-sonra")
	if eerr == nil && strings.Contains(string(out2), "hesap-kapatildiktan-sonra") {
		t.Fatalf("KAPATILMIŞ hesap aynı bağlantı üzerinde yeni oturum açıp "+
			"hedefte komut çalıştırdı (çıktı %q) — hesabı kapatmak SSH'ı "+
			"kapatmıyor, yani işten çıkarma erişimi bitirmiyor",
			strings.TrimSpace(string(out2)))
	}
}

/*
 * ⚠️ AD SERBEST BIRAKILINCA ESKİ BAĞLANTI YENİ SAHİBE ÇÖZÜLMEMELİ.
 *
 * Bağlantı yalnızca kullanıcı adını taşıyordu. purge adı bıraktıktan
 * sonra o metin başka bir GERÇEK İNSANIN satırına çözülüyor: ayrılan
 * kişinin açık bağlantısı yeni kişinin os_user'ı ve rolleriyle çalışıp
 * denetim defterine ONUN adına yazıyordu.
 *
 * Panel bu sınıfı iki kez düzeltti (af371db, ce78e29) ve
 * RefuseIfDeletedByID'nin doc yorumu neden adın güvenli bir tutamak
 * OLMADIĞINI zaten yazıyor. Asıl kapı — SSH — hâlâ adı kullanıyordu.
 *
 * Denetim önceliği olan bir üründe yanlış insana yazılmış bir oturum,
 * eksik olandan daha kötü: yüzeyinde şüpheli olduğunu gösteren hiçbir
 * şey yok.
 */
func TestReleasedUsernameDoesNotHandTheConnectionToTheNewHolder(t *testing.T) {
	caKeyPath, caAuthorizedKey := newTestCA(t)
	tgt := startCertTarget(t, caAuthorizedKey)
	tc := tgt.target()
	tc.Name = "web01"

	addr, hostPub, signer, db := testServerWithDB(t, caKeyPath, tc)
	ctx := context.Background()

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatalf("proxy'ye bağlanılamadı: %v", err)
	}
	defer client.Close()

	first, err := client.NewSession()
	if err != nil {
		t.Fatalf("ilk NewSession: %v", err)
	}
	if _, err := first.Output("echo ayrilmadan-once"); err != nil {
		t.Fatalf("ilk exec: %v", err)
	}
	first.Close()

	// Ayrılıyor: purge yalnızca 'deleted' bir satırdan adı bırakabiliyor.
	if err := db.SetAccountState(ctx, "yigit", store.StateDeleted); err != nil {
		t.Fatalf("SetAccountState: %v", err)
	}
	if _, err := db.PurgeAccount(ctx, "yigit", time.Now()); err != nil {
		t.Fatalf("PurgeAccount: %v", err)
	}

	// Adı yeni bir insan alıyor — ve hedeflere erişimi var.
	if _, err := db.CreateUser(ctx, "yigit", "yeni@warewave.io", "postern"); err != nil {
		t.Fatalf("yeni kullanıcı: %v", err)
	}
	if err := db.SyncRoles(ctx, "yigit", []string{"ops"}); err != nil {
		t.Fatalf("SyncRoles: %v", err)
	}
	before := sessionCountFor(t, db)

	second, serr := client.NewSession()
	if serr == nil {
		out, eerr := second.Output("echo ad-devredildikten-sonra")
		second.Close()
		if eerr == nil && strings.Contains(string(out), "ad-devredildikten-sonra") {
			t.Errorf("AYRILAN kişinin bağlantısı, adı devralan yeni kişinin " +
				"yetkileriyle hedefte komut çalıştırdı")
		}
	}

	if after := sessionCountFor(t, db); after != before {
		t.Errorf("yeni sahibin adına yazılan oturum sayısı %d → %d; ayrılan "+
			"kişinin bağlantısı denetim defterine BAŞKA BİRİNİN adına "+
			"yazıyor", before, after)
	}
}

/*
 * sessionCountFor, "yigit" adına yazılmış oturum sayısı.
 *
 * ⚠️ AD ÜZERİNDEN SAYIYOR — VE ÖLÇÜLEN ZARAR TAM OLARAK BU. sessions
 * tablosu kullanıcı adını METİN olarak tutuyor; ayrılan kişinin
 * bağlantısının açtığı bir oturum, adı devralan yeni kişinin
 * satırlarından ayırt edilemez biçimde aynı deftere düşüyor.
 */
func sessionCountFor(t *testing.T, db *store.Store) int {
	t.Helper()
	rows, err := db.Sessions(context.Background(), "yigit", 100)
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	return len(rows)
}
