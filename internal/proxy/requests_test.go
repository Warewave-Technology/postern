package proxy

import (
	"github.com/Warewave-Technology/postern/internal/record"
	"log/slog"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// sshString, SSH tel biçiminde bir string kodlar (4 bayt uzunluk + gövde).
func sshString(s string) []byte {
	n := len(s)
	return append([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, s...)
}

// envPayload, "env" request'inin gövdesi: ad + değer.
func envPayload(name, value string) []byte {
	return append(sshString(name), sshString(value)...)
}

func TestPolicyClientRequests(t *testing.T) {
	var p RequestPolicy

	cases := []struct {
		name    string
		req     ssh.Request
		allowed bool
	}{
		// Oturumun çalışması için gerekli olanlar.
		{"pty-req gecer", ssh.Request{Type: "pty-req"}, true},
		{"shell gecer", ssh.Request{Type: "shell"}, true},
		{"exec gecer", ssh.Request{Type: "exec"}, true},
		{"window-change gecer", ssh.Request{Type: "window-change"}, true},
		{"signal gecer", ssh.Request{Type: "signal"}, true},

		// Ölçülmüş boşluk: bunlar bu süzgeç yazılana kadar geçiyordu.
		{"subsystem sftp REDDEDILIR", ssh.Request{Type: "subsystem", Payload: sshString("sftp")}, false},
		{"subsystem baska REDDEDILIR", ssh.Request{Type: "subsystem", Payload: sshString("netconf")}, false},
		{"x11-req REDDEDILIR", ssh.Request{Type: "x11-req"}, false},
		{"agent yonlendirme REDDEDILIR", ssh.Request{Type: "auth-agent-req@openssh.com"}, false},

		// Varsayılan reddet: bilinmeyen tip geçmez.
		{"bilinmeyen tip REDDEDILIR", ssh.Request{Type: "yarin-eklenen-uzanti@example.com"}, false},

		// Hedeften gelmesi gereken bir tip, kullanıcıdan gelirse geçmez.
		{"exit-status kullanicidan REDDEDILIR", ssh.Request{Type: "exit-status"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := p.allow(fromClient, &tc.req)
			if got != tc.allowed {
				t.Errorf("allow(%s) = %v (%q), beklenen %v", tc.req.Type, got, reason, tc.allowed)
			}
			if !got && reason == "" {
				t.Error("red edildi ama sebep boş — log satırı işe yaramaz")
			}
		})
	}
}

// Reddedilen subsystem'in ADI sebebe girmeli: operatörün ilk sorusu
// "sftp mi denendi, başka bir şey mi" olacak.
func TestSubsystemDenialNamesTheSubsystem(t *testing.T) {
	var p RequestPolicy

	_, reason := p.allow(fromClient, &ssh.Request{
		Type: "subsystem", Payload: sshString("sftp"),
	})
	if !strings.Contains(reason, "sftp") {
		t.Errorf("sebep = %q, %q geçmeliydi", reason, "sftp")
	}
}

func TestPolicyTargetRequests(t *testing.T) {
	var p RequestPolicy

	cases := []struct {
		typ     string
		allowed bool
	}{
		{"exit-status", true},
		{"exit-signal", true},
		{"xon-xoff", true},
		{"eow@openssh.com", true},

		// Hedef kullanıcının istemcisini sürmemeli.
		{"pty-req", false},
		{"x11-req", false},
		{"subsystem", false},
		{"auth-agent-req@openssh.com", false},
	}

	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			got, _ := p.allow(fromTarget, &ssh.Request{Type: tc.typ})
			if got != tc.allowed {
				t.Errorf("allow(fromTarget, %s) = %v, beklenen %v", tc.typ, got, tc.allowed)
			}
		})
	}
}

func TestEnvWhitelist(t *testing.T) {
	t.Run("varsayilan: LANG ve LC_* gecer", func(t *testing.T) {
		var p RequestPolicy

		for _, name := range []string{"LANG", "LC_ALL", "LC_CTYPE", "LC_TIME"} {
			ok, reason := p.allow(fromClient, &ssh.Request{
				Type: "env", Payload: envPayload(name, "tr_TR.UTF-8"),
			})
			if !ok {
				t.Errorf("env %s reddedildi: %s", name, reason)
			}
		}
	})

	t.Run("varsayilan: kod calistiranlar REDDEDILIR", func(t *testing.T) {
		var p RequestPolicy

		// Bunların her biri hedefte NE ÇALIŞACAĞINI değiştirebilir.
		for _, name := range []string{"LD_PRELOAD", "PATH", "BASH_ENV", "PERL5LIB", "PYTHONPATH", "LD_LIBRARY_PATH"} {
			ok, _ := p.allow(fromClient, &ssh.Request{
				Type: "env", Payload: envPayload(name, "/tmp/kotu"),
			})
			if ok {
				t.Errorf("env %s GEÇTİ — hedefte kod çalıştırma yolu açık", name)
			}
		}
	})

	t.Run("LANGUAGE, LANG'in onekiyle SIZMAZ", func(t *testing.T) {
		// "LANG" tam eşleşme kuralı; önek eşleşmesi olsaydı LANGUAGE de
		// geçerdi. Joker yalnız sonuna * yazılmış desenlerde çalışır.
		var p RequestPolicy

		ok, _ := p.allow(fromClient, &ssh.Request{
			Type: "env", Payload: envPayload("LANGUAGE", "tr"),
		})
		if ok {
			t.Error("LANGUAGE geçti — tam eşleşme öneke dönüşmüş")
		}
	})

	t.Run("bos liste hicbirini gecirmez", func(t *testing.T) {
		p := RequestPolicy{AcceptEnv: []string{}}

		ok, _ := p.allow(fromClient, &ssh.Request{
			Type: "env", Payload: envPayload("LANG", "C"),
		})
		if ok {
			t.Error("boş whitelist ile LANG geçti — nil ile karıştırılmış")
		}
	})

	t.Run("ozel liste uygulanir", func(t *testing.T) {
		p := RequestPolicy{AcceptEnv: []string{"TZ", "MY_*"}}

		for name, want := range map[string]bool{
			"TZ":        true,
			"MY_APP":    true,
			"MY_":       true,
			"LANG":      false,
			"TZDATA":    false,
			"NOT_MY_NO": false,
		} {
			ok, _ := p.allow(fromClient, &ssh.Request{
				Type: "env", Payload: envPayload(name, "x"),
			})
			if ok != want {
				t.Errorf("env %s = %v, beklenen %v", name, ok, want)
			}
		}
	})

	t.Run("bozuk payload REDDEDILIR", func(t *testing.T) {
		var p RequestPolicy

		bad := [][]byte{
			nil,
			{1, 2},               // 4 bayttan kısa
			{0, 0, 0, 99, 'L'},   // uzunluk gövdeden büyük
			{255, 255, 255, 255}, // taşma denemesi
		}
		for i, payload := range bad {
			ok, _ := p.allow(fromClient, &ssh.Request{Type: "env", Payload: payload})
			if ok {
				t.Errorf("bozuk payload %d geçti", i)
			}
		}
	})
}

// parseString uydurma uzunluklarda panik etmemeli: payload ağdan geliyor.
func TestParseStringDoesNotPanicOnHostileInput(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{0},
		{0, 0, 0},
		{0, 0, 0, 1},         // uzunluk 1, gövde yok
		{255, 255, 255, 255}, // uint32 üst sınır
		{127, 255, 255, 255, 'a'},
	}
	for i, in := range inputs {
		if _, _, ok := parseString(in); ok {
			t.Errorf("girdi %d geçerli sayıldı: %v", i, in)
		}
	}
}

// Reddedilen request HEDEFE GİTMEMELİ ve denetim satırı bırakmalı.
//
// İki ayrı iddia, ikisi de ayrıca test edilmeye değer: birincisi
// güvenlik özelliği (istek köprüyü geçmedi), ikincisi denetim özelliği
// (operatör bunu sonradan görebilir). Süzgeç sessizce çalışsaydı
// "kim sftp denedi" sorusu cevapsız kalırdı.
func TestDeniedRequestIsNotForwardedAndIsLogged(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	dst, _, _ := newFakeChannel()
	src := make(chan *ssh.Request, 1)

	b := &Broker{logger: logger}

	done := make(chan struct{})
	go func() {
		b.relayRequests(dst, src, fromClient, false)
		close(done)
	}()

	// WantReply false: ssh.Request.Reply gerçek bir bağlantı ister ve
	// buradaki iddia "hedefe gitmedi + loglandı". Reddin gönderene
	// başarısız cevap döndürmesi uçtan uca sınanıyor
	// (TestSFTPSubsystemIsRefused).
	src <- &ssh.Request{Type: "subsystem", WantReply: false, Payload: sshString("sftp")}
	close(src)
	<-done

	if got := dst.sentRequests(); len(got) != 0 {
		t.Errorf("reddedilen request hedefe gitti: %+v", got)
	}

	line := logs.String()
	for _, want := range []string{"session request denied", "subsystem", "sftp", "client->target"} {
		if !strings.Contains(line, want) {
			t.Errorf("log satırında %q yok:\n%s", want, line)
		}
	}
}

// İzin verilen request hedefe GİTMELİ — süzgeç meşru trafiği kesmemeli.
func TestAllowedRequestIsForwarded(t *testing.T) {
	dst, _, _ := newFakeChannel()
	src := make(chan *ssh.Request, 1)

	b := &Broker{logger: testLogger()}

	done := make(chan struct{})
	go func() {
		b.relayRequests(dst, src, fromClient, false)
		close(done)
	}()

	src <- &ssh.Request{Type: "pty-req", WantReply: false, Payload: []byte("x")}
	close(src)
	<-done

	got := dst.sentRequests()
	if len(got) != 1 || got[0].name != "pty-req" {
		t.Errorf("iletilen request'ler = %+v, [pty-req] bekleniyordu", got)
	}
}

// ⚠️ exec KOMUTU kayda düşmeli.
//
// Kapatılan boşluk: `exec` istekleri hedefe geçiyor ama komut satırı
// hiçbir yere yazılmıyordu. `ssh user:target@bastion 'rm -rf /veri'`
// çalışıyor, kısa çıktısı kayda düşüyor ama KOMUTUN KENDİSİ ne
// kayıtta, ne sessions tablosunda, ne logda görünüyordu. Bu, subsystem
// engelinin gerekçesiyle aynı boşluk — orada kapatıp burada açık
// bırakmak tutarsızdı.
func TestExecCommandIsRecorded(t *testing.T) {
	var sink memCloser

	w, err := record.NewWriter(&sink, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}

	b := &Broker{rec: w, logger: testLogger()}
	b.recordIntent(&ssh.Request{
		Type:    "exec",
		Payload: ssh.Marshal(ExecRequest{Command: "cat /etc/shadow"}),
	})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	got := sink.String()
	if !strings.Contains(got, "cat /etc/shadow") {
		t.Errorf("komut kayda düşmedi:\n%s", got)
	}
}

// Ayrıştırılamayan bir exec de SESSİZ geçmemeli: denetim kaydı
// "burada bir exec vardı" demeli.
func TestUnparsableExecIsStillRecorded(t *testing.T) {
	var sink memCloser

	w, err := record.NewWriter(&sink, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}

	b := &Broker{rec: w, logger: testLogger()}
	b.recordIntent(&ssh.Request{Type: "exec", Payload: []byte{0xff, 0xff}})
	w.Close()

	if !strings.Contains(sink.String(), "exec") {
		t.Errorf("ayrıştırılamayan exec kayda hiç düşmedi:\n%s", sink.String())
	}
}

// shell de kayda düşmeli: oturumun ne için açıldığı ilk satırda
// görünsün.
func TestShellIntentIsRecorded(t *testing.T) {
	var sink memCloser

	w, _ := record.NewWriter(&sink, 80, 24, nil)
	b := &Broker{rec: w, logger: testLogger()}
	b.recordIntent(&ssh.Request{Type: "shell"})
	w.Close()

	if !strings.Contains(sink.String(), "shell") {
		t.Errorf("shell kayda düşmedi:\n%s", sink.String())
	}
}
