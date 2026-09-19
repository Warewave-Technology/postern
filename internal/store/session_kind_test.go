package store

import (
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
)

/*
 * ⚠️ AYNI GÖRÜNEN İKİ SATIR DENETİM KAYDI DEĞİL.
 *
 * Biri bir makinede dururken panelin dosya tarayıcısını açmak İKİNCİ bir
 * oturum açıyor ve iki satır, yöneticinin görebildiği her sütunda
 * birbirinin aynısıydı: aynı kişi, aynı hedef, aynı hesap, aynı saniye.
 * "İki oturum açık" demek ama hangisinin ne olduğunu söylememek, tek
 * satırdan kötü — kopya gibi okunuyor.
 */
func TestTwoSessionsOnTheSameTargetSayHowEachWasOpened(t *testing.T) {
	s, target := hostAcctEnv(t)
	ctx := t.Context()

	now := time.Unix(1_700_000_000, 0)
	for _, tc := range []struct{ id, kind string }{
		{"sess-ssh", model.SessionFromSSH},
		{"sess-files", model.SessionFromFiles},
	} {
		if err := s.StartSession(ctx, SessionStart{
			ID: tc.id, Username: "ayse", TargetName: target, OSUser: "ayse",
			SrcIP: "10.0.0.5", StartedAt: now, RecordingPath: tc.id + ".cast",
			Kind: tc.kind,
		}); err != nil {
			t.Fatal(err)
		}
	}

	got := map[string]string{}
	for _, id := range []string{"sess-ssh", "sess-files"} {
		sess, err := s.Session(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		got[id] = sess.Kind
	}
	if got["sess-ssh"] != model.SessionFromSSH || got["sess-files"] != model.SessionFromFiles {
		t.Fatalf("kapılar ayrışmadı: %+v", got)
	}

	// Liste ve açık oturumlar sorgusu da taşıyor: panelin iki ayrı yolu.
	list, err := s.Sessions(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, sess := range list {
		kinds[sess.ID] = sess.Kind
	}
	if kinds["sess-files"] != model.SessionFromFiles {
		t.Errorf("listede kapı yok: %+v", kinds)
	}

	open, err := s.OpenSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, sess := range open {
		if sess.Kind == "" {
			t.Errorf("açık oturumda kapı boş: %s", sess.ID)
		}
	}
}

/*
 * ⚠️ BOŞ KAPI YAZILMIYOR. Sütun, tam da bir soruyu cevaplamak için var;
 * boş bırakmak onu cevapsız yapardı. Kapıyı söylemeyen çağıran "ssh"
 * sayılıyor — göç de eski satırlara aynı şeyi yazdı.
 */
func TestASessionWithNoDoorIsRecordedAsSSH(t *testing.T) {
	s, target := hostAcctEnv(t)
	ctx := t.Context()

	if err := s.StartSession(ctx, SessionStart{
		ID: "sess-bare", Username: "ayse", TargetName: target, OSUser: "ayse",
		SrcIP: "10.0.0.5", StartedAt: time.Unix(1_700_000_000, 0),
		RecordingPath: "bare.cast",
	}); err != nil {
		t.Fatal(err)
	}
	sess, err := s.Session(ctx, "sess-bare")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Kind != model.SessionFromSSH {
		t.Fatalf("kapı = %q", sess.Kind)
	}
}
