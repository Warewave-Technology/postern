//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/proxy"
	"github.com/warewave/postern/internal/record"
	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/testdb"
)

/*
 * SSO'ya bağlı kullanıcı ve anahtar kapısı.
 *
 * Eskiden koşulsuz REDDEDİLİYORDU ve gerekçesi doğruydu: anahtar kapısı
 * kimlik sağlayıcıya bakmıyor, roller yalnızca SSO girişinde
 * senkronize ediliyordu, yani anahtar bayat bir yetkiyi süresiz
 * taşıyabilirdi.
 *
 * SSH'ın anahtara sabitlendiği üründe o reddetme dizin kullanıcılarının
 * SSH'ını tamamen kapatır. Tazelik artık oturum AÇILIŞINDA sağlanıyor —
 * ama yalnızca kaynak kullanıcı ADIYLA sorgulanabiliyorsa. Grupları
 * token'dan okuyan bir kurulumda anahtarla açılan oturumda sorulacak
 * bir şey yok ve eski gerekçe aynen geçerli.
 */
func TestKeyDoorRefusesSSOUserWhenRolesCannotBeRefreshed(t *testing.T) {
	caKeyPath, _ := newTestCA(t)
	srv, hostPub, clientSigner, db := newBastion(t, caKeyPath)

	if err := db.SetUserSSOOnly(context.Background(), "yigit", true); err != nil {
		t.Fatal(err)
	}
	// Kaynak dokunulmadı: varsayılan ClaimGroups, adla sorgulanamaz.
	addr := startBastion(t, srv)

	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("tazelenemeyen SSO kullanıcısı anahtarla içeri girdi — " +
			"anahtar bayat bir yetkiyi süresiz taşırdı")
	}
	t.Logf("beklenen ret: %v", err)
}

// Kaynak adla sorgulanabiliyorsa aynı kullanıcı el sıkışmayı GEÇMELİ:
// tazelik oturum açılışında sağlanacak.
func TestKeyDoorAllowsSSOUserWhenDirectoryCanAnswer(t *testing.T) {
	caKeyPath, _ := newTestCA(t)
	srv, hostPub, clientSigner, db := newBastion(t, caKeyPath)

	if err := db.SetUserSSOOnly(context.Background(), "yigit", true); err != nil {
		t.Fatal(err)
	}
	srv.UseGroupSource(auth.NewSwitchableGroupSource(namedDirectory{}))
	addr := startBastion(t, srv)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dizin cevap verebilirken anahtar kapısı reddetti: %v", err)
	}
	defer client.Close()
}

// namedDirectory, kullanıcı adıyla sorgulanabilen sahte kaynak.
type namedDirectory struct{}

func (namedDirectory) Groups(context.Context, auth.Identity) (auth.GroupResult, error) {
	return auth.GroupResult{Presence: auth.GroupsPresent, Groups: []string{"ops"}}, nil
}
func (namedDirectory) ResolvesByUsername() bool { return true }

// dirSource, verilen cevabı döndüren sahte dizin kaynağı.
type dirSource struct{ res auth.GroupResult }

func (d dirSource) Groups(context.Context, auth.Identity) (auth.GroupResult, error) {
	return d.res, nil
}
func (dirSource) ResolvesByUsername() bool { return true }

/*
 * openWithDirectory, proxy.Open'ı verilen dizin cevabıyla çalıştırır.
 *
 * ⚠️ NEDEN proxy.Open, SSH ÜZERİNDEN DEĞİL: ilk yazdığım hâlde
 * bastion'a hedef vermemiştim ve testler "target not found" yüzünden
 * geçiyordu — yani reddi ölçtüğünü sanan iki test aslında hiçbir şey
 * ölçmüyordu. Burada hedef VAR (yalnızca ulaşılamaz), dolayısıyla
 * ErrAccessDenied ile "hedefe bağlanamadım" birbirinden ayrılıyor.
 */
func openWithDirectory(t *testing.T, res auth.GroupResult) error {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, testdb.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := db.CreateUser(ctx, "yigit", "yigit@warewave.io", "yigit"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetUserSSOOnly(ctx, "yigit", true); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignRole(ctx, "yigit", "ops", time.Time{}); err != nil {
		t.Fatal(err)
	}
	// Hedef VAR ama kapalı bir portta: yetki geçerse bağlantı hatası
	// alırız, ki bu ErrAccessDenied'dan farklı bir cevap.
	if _, err := db.CreateTarget(ctx, model.Target{
		Name: "web01", Host: "127.0.0.1", Port: 1, HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIcLUQM0UcoZdJVh2EokribDvFZyyNyAVURM/LrCugFM",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.GrantTarget(ctx, "ops", "web01"); err != nil {
		t.Fatal(err)
	}

	recStore, err := record.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src := auth.NewSwitchableGroupSource(dirSource{res: res})

	deps := proxy.Deps{
		Store:     db,
		Records:   recStore,
		Authority: testAuthority(t),
		Logger:    slog.New(slog.DiscardHandler),
		FreshenRoles: func(c context.Context, username string) error {
			r, gerr := src.Groups(c, auth.Identity{Username: username})
			if gerr != nil {
				return gerr
			}
			switch r.Presence {
			case auth.GroupsPresent:
				if r.Disabled {
					return fmt.Errorf("%w: %s", proxy.ErrDirectoryRefused, r.DisabledReason)
				}
			case auth.GroupsAbsent:
				return fmt.Errorf("%w: not in the directory", proxy.ErrDirectoryRefused)
			default:
				return nil
			}
			roles, _, rerr := db.RolesForGroups(c, r.Groups)
			if rerr != nil {
				return rerr
			}
			return db.SyncRoles(c, username, roles)
		},
	}

	// Kimlik kapıda çözülüyor; burada onun yerine geçiyoruz. Boş
	// bırakmak proxy.Open'da ret demek ve bu testin ölçtüğü şeyi
	// gizlerdi — hepsi "erişim reddedildi" dönerdi.
	accountID, aerr := db.AccountID(ctx, "yigit")
	if aerr != nil {
		t.Fatalf("AccountID: %v", aerr)
	}

	_, oerr := proxy.Open(ctx, deps, proxy.Request{
		Username: "yigit", AccountID: accountID, TargetName: "web01",
	})
	return oerr
}

/*
 * ⚠️ DEVRE DIŞI BIRAKILMIŞ HESAP OTURUM AÇAMAMALI.
 *
 * Bu, eski "SSO kullanıcısı anahtarla giremez" kuralının koruduğu asıl
 * şeydi ve tazelemeyi yalnızca GRUPLARA bakarak yazdığımda kaybolmuştu.
 * Bir hesabı devre dışı bırakmak işten ayrılmada ve olay müdahalesinde
 * atılan İLK adımdır — ama AD'de bu ne girişi siler ne de grup
 * üyeliklerini kaldırır. Yalnızca gruplara bakan tazeleme o hesabı
 * "present, rolleri şunlar" diye okuyup rollerini YENİDEN YAZIYORDU.
 */
func TestSessionRefusedWhenDirectoryAccountIsDisabled(t *testing.T) {
	err := openWithDirectory(t, auth.GroupResult{
		Presence: auth.GroupsPresent, Groups: []string{"ops"},
		Disabled: true, DisabledReason: "userAccountControl has ACCOUNTDISABLE",
	})
	if !errors.Is(err, proxy.ErrAccessDenied) {
		t.Fatalf("hata = %v, ErrAccessDenied bekleniyordu — dizinde KAPATILMIŞ "+
			"hesap oturum açabiliyorsa hesabı devre dışı bırakmak erişimi bitirmiyor", err)
	}
}

// Dizinde olmayan kullanıcı da oturum açamamalı. Rol SİLİNMİYOR —
// yalnızca bu oturuma hayır deniyor; iptal, patlama yarıçapı korumaları
// olan senkronizasyon döngüsünün işi.
func TestSessionRefusedWhenUserAbsentFromDirectory(t *testing.T) {
	err := openWithDirectory(t, auth.GroupResult{Presence: auth.GroupsAbsent})
	if !errors.Is(err, proxy.ErrAccessDenied) {
		t.Fatalf("hata = %v, ErrAccessDenied bekleniyordu", err)
	}
}

/*
 * Dizin CEVAP VEREMEDİĞİNDE yetki kontrolü GEÇMELİ.
 *
 * "Bilmiyorum" bir yetki kararı değil. Burada reddetmek, bir dizin
 * kesintisini bütün kurumun SSH erişiminin kesilmesine çevirirdi.
 *
 * Hedef kapalı bir portta olduğu için oturum yine açılmıyor — ama
 * REDDEDİLEREK değil, BAĞLANAMAYARAK. Ayrımın kendisi test ediliyor.
 */
func TestSessionAllowedWhenDirectoryCannotAnswer(t *testing.T) {
	err := openWithDirectory(t, auth.GroupResult{Presence: auth.GroupsUnknown})
	if errors.Is(err, proxy.ErrAccessDenied) {
		t.Fatalf("dizin cevap veremezken yetki reddedildi: %v — "+
			"kesinti yetki yokluğu değildir", err)
	}
	t.Logf("yetki geçti, hedefe bağlanılamadı (beklenen): %v", err)
}
