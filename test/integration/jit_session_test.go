//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * ⚠️ SÜRELİ HAKLA AÇILAN OTURUM KAYITTA ÖYLE YAZIYOR — rolle açılan
 * yazmıyor. yigit'in jit-host'ta rolü yok; onu içeri alan tek şey
 * uygulanmış, süresi dolmamış bir hak. Denetçi bunu satırda görmeli;
 * hak geri alındıktan sonra jit_grants'a bakıp "o saatte açık mıydı"
 * diye türetmek, denetim kaydını başka bir tablonun sonraki hâline
 * bağlar.
 */
func TestASessionOpenedThroughAGrantIsMarkedTemporary(t *testing.T) {
	caKeyPath, caAuthorizedKey := newTestCA(t)
	tgt := startCertTarget(t, caAuthorizedKey)
	roleHost := tgt.target()
	roleHost.Name = "web01"
	addr, hostPub, signer, db := testServerWithDB(t, caKeyPath, roleHost)

	ctx := context.Background()
	// Aynı konteyner, ikinci ad: bu ada hiçbir rol gitmiyor.
	jitHost := tgt.target()
	jitHost.Name = "jit-host"
	if _, err := db.CreateTarget(ctx, jitHost); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	id, err := db.CreateJITGrant(ctx, store.JITGrant{
		Username: "yigit", Target: "jit-host", OSUser: "deploy",
		GrantedBy: "ops", GrantedAt: now, ExpiresAt: now.Add(time.Hour), CleanupGroups: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.MarkJITGrantApplied(ctx, id, true, "", now); err != nil {
		t.Fatal(err)
	}

	open := func(target string) {
		t.Helper()
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User: "yigit:" + target, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.FixedHostKey(hostPub), Timeout: 15 * time.Second,
		})
		if err != nil {
			t.Fatalf("%s: proxy'ye bağlanılamadı: %v", target, err)
		}
		defer client.Close()
		sess, err := client.NewSession()
		if err != nil {
			t.Fatalf("%s: NewSession: %v", target, err)
		}
		defer sess.Close()
		if err := sess.Run("true"); err != nil {
			t.Fatalf("%s: komut: %v", target, err)
		}
	}
	open("jit-host")
	open("web01")

	sessions, err := db.Sessions(ctx, "yigit", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("%d oturum, 2 bekleniyordu: %+v", len(sessions), sessions)
	}
	marked := map[string]bool{}
	for _, s := range sessions {
		marked[s.Target] = s.Temporary
	}
	if !marked["jit-host"] {
		t.Errorf("hakla açılan oturum işaretsiz: %+v", sessions)
	}
	if marked["web01"] {
		t.Errorf("rolle açılan oturum 'temporary' işaretli: %+v", sessions)
	}
}
