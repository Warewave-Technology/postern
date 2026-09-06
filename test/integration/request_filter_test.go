//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/store"
)

// Bu dosya, ÖLÇÜLMÜŞ bir boşluğun kapandığını doğruluyor.
//
// Süzgeç yazılmadan önce burada koşan bir sonda şunu gösterdi:
// `subsystem sftp` postern üzerinden UÇTAN UCA çalışıyordu (hedef
// SFTP_VERSION dönüyordu) ve transfer, asciicast kaydına ham ikili
// protokol olarak düşüyordu — oynatılamaz, dosya seviyesinde
// denetlenemez. Aşağıdaki testler o yolun kapandığını ve meşru
// oturumların bozulmadığını sabitliyor.

// SFTP artık POSTERN tarafından reddedilmeli.
//
// ⚠️ Testin ayırt ediciliği hedefin sftp-server'a SAHİP OLMASINA
// dayanıyor: certtarget'ta sftp-server var ve süzgeçten önce bu istek
// başarılıydı. Şimdi başarısızsa reddeden postern'dir.
func TestSFTPSubsystemIsRefused(t *testing.T) {
	client := proxyClient(t)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	if err := sess.RequestSubsystem("sftp"); err == nil {
		t.Fatal("subsystem sftp kabul edildi — denetlenemeyen dosya transferi açık")
	}
}

// Reddedilen bir subsystem OTURUMU DÜŞÜRMEMELİ: istemci başka bir şey
// deneyebilmeli. Süzgeç bir kapı, giyotin değil.
func TestRefusedSubsystemLeavesConnectionUsable(t *testing.T) {
	client := proxyClient(t)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := sess.RequestSubsystem("sftp"); err == nil {
		t.Fatal("subsystem sftp kabul edildi")
	}
	sess.Close()

	// Aynı bağlantı üzerinde yeni bir oturum hâlâ açılabilmeli.
	sess2, err := client.NewSession()
	if err != nil {
		t.Fatalf("red sonrası NewSession: %v", err)
	}
	defer sess2.Close()

	out, err := sess2.Output("echo hayatta")
	if err != nil {
		t.Fatalf("red sonrası komut: %v", err)
	}
	if !strings.Contains(string(out), "hayatta") {
		t.Errorf("çıktı = %q", out)
	}
}

// Süzgeç config'ten GERÇEKTEN besleniyor mu?
//
// Birim testleri politikayı doğruluyor ama yanlış bağlanmış bir config
// alanını göremez. Bu test iki yönü birden sabitliyor: whitelist'teki ad
// hedefe ULAŞIYOR, whitelist dışındaki ad ULAŞMIYOR — hedef ikisini de
// kabul etmeye hazır olduğu hâlde (certtarget'ta AcceptEnv ikisini de
// sayıyor), yani eleyen postern.
func TestEnvWhitelistIsWiredEndToEnd(t *testing.T) {
	caKeyPath, caAuthorizedKey := newTestCA(t)
	tgt := startCertTarget(t, caAuthorizedKey)
	tc := tgt.target()
	tc.Name = "web01"

	addr, hostPub, signer := withConfig(t, caKeyPath, func(c *config.Config) {
		c.Session.AcceptEnv = []string{"POSTERN_ALLOWED"}
	}, tc)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	t.Run("whitelistteki ad hedefe ulasir", func(t *testing.T) {
		sess, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer sess.Close()

		if err := sess.Setenv("POSTERN_ALLOWED", "gecti"); err != nil {
			t.Fatalf("Setenv reddedildi: %v", err)
		}

		out, err := sess.Output(`echo "[$POSTERN_ALLOWED]"`)
		if err != nil {
			t.Fatalf("komut: %v", err)
		}
		if !strings.Contains(string(out), "gecti") {
			t.Errorf("çıktı = %q, değer hedefe ulaşmamış", strings.TrimSpace(string(out)))
		}
	})

	t.Run("whitelist disindaki ad ulasmaz", func(t *testing.T) {
		sess, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer sess.Close()

		// Hedef bu adı kabul etmeye HAZIR (AcceptEnv'inde var); tek
		// engel postern.
		if err := sess.Setenv("POSTERN_DENIED", "sizdi"); err == nil {
			t.Error("Setenv kabul edildi — postern süzmedi")
		}

		out, err := sess.Output(`echo "[$POSTERN_DENIED]"`)
		if err != nil {
			t.Fatalf("komut: %v", err)
		}
		if strings.Contains(string(out), "sizdi") {
			t.Errorf("değer hedefe ULAŞTI: %q", strings.TrimSpace(string(out)))
		}
	})
}

// Varsayılan whitelist'te olmayan bir ad, config hiç yazılmasa da geçmez.
func TestDefaultEnvWhitelistRefusesArbitraryNames(t *testing.T) {
	client := proxyClient(t)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	if err := sess.Setenv("POSTERN_ALLOWED", "sizdi"); err == nil {
		t.Error("varsayılan whitelist rastgele bir adı geçirdi")
	}
}

/*
 * ⚠️ POSTERN'İN KENDİ REDDİ DENETİM DEFTERİNE DÜŞMELİ.
 *
 * ÖLÇÜLEN BOŞLUK: ret veriliyordu ama geriye yalnızca bir log satırı
 * kalıyordu. session_files'taki ok=false satırlarının tamamı HEDEFİN
 * cevabından üretiliyor — yani "reddedilen bir aktarım reddedilmiş olarak
 * durur" cümlesi postern'in KENDİ kararı için doğru değildi ve "SFTP
 * kapalıyken kim denedi" sorusunun cevabı defterde yoktu.
 *
 * Bu testin ayırt ediciliği: yukarıdaki TestSFTPSubsystemIsRefused reddin
 * verildiğini ölçüyor, bu ise reddin İZ BIRAKTIĞINI. İkisi ayrı arızalar;
 * ret çalışıp iz bırakmayan bir sürüm ilkini geçer, bunu geçmez.
 */
func TestPosternsOwnRefusalIsRecorded(t *testing.T) {
	caKeyPath, caAuthorizedKey := newTestCA(t)

	tgt := startCertTarget(t, caAuthorizedKey)
	tc := tgt.target()
	tc.Name = "web01"

	srv, hostPub, signer, db := newBastionOpts(t, caKeyPath, false, tc)
	addr := startBastion(t, srv)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := sess.RequestSubsystem("sftp"); err == nil {
		t.Fatal("subsystem sftp kabul edildi")
	}
	sess.Close()
	client.Close()

	// Oturumun kapanıp satırın yazılması için kısa bir pencere.
	var found *store.SessionFile
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		sessions, lerr := db.Sessions(t.Context(), "", 20)
		if lerr != nil {
			t.Fatal(lerr)
		}
		for _, s := range sessions {
			files, ferr := db.SessionFiles(t.Context(), s.ID)
			if ferr != nil {
				t.Fatal(ferr)
			}
			for i := range files {
				if strings.HasPrefix(files[i].Op, "denied.") {
					found = &files[i]
				}
			}
		}
		if found != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}

	if found == nil {
		t.Fatal("ret defterde yok — 'kim sftp denedi' sorusunun cevabı yalnızca log'da")
	}
	if found.OK {
		t.Error("ret satırı ok=true taşıyor")
	}
	if found.Op != "denied.subsystem" {
		t.Errorf("op = %q, \"denied.subsystem\" bekleniyordu", found.Op)
	}
	if found.Detail == "" {
		t.Error("ret sebebi yazılmamış; satır neden reddedildiğini söylemiyor")
	}
	// Yol BOŞ olmalı: reddedilen şey alt sistemin kendisi, bir dosya değil.
	if found.Path != "" {
		t.Errorf("path = %q, boş bekleniyordu", found.Path)
	}
}
