package provision

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/sudoers"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

/*
 * sshRunner, planı GERÇEK bir makinede koşturur.
 *
 * ⚠️ YALNIZCA POSTERN_LIVE_TARGET verildiğinde çalışıyor. CI'da bir
 * hedef yok; testin varlık sebebi, planın ürettiği komutların gerçekten
 * çalıştığını kâğıt üzerinde değil makinede görmek.
 */
type sshRunner struct{ key, addr, port string }

func (s sshRunner) Exec(ctx context.Context, command, stdin string) (string, error) {
	cmd := exec.CommandContext(ctx, "ssh", "-q", "-i", s.key,
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", s.port, "postern@"+s.addr, command)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()

	return string(out), err
}

func TestApplyAgainstARealTarget(t *testing.T) {
	key := os.Getenv("POSTERN_LIVE_KEY")
	addr := os.Getenv("POSTERN_LIVE_TARGET")
	if key == "" || addr == "" {
		t.Skip("POSTERN_LIVE_TARGET ve POSTERN_LIVE_KEY verilmedi")
	}
	port := os.Getenv("POSTERN_LIVE_PORT")
	if port == "" {
		port = "22"
	}

	r := sshRunner{key: key, addr: addr, port: port}
	caps := upstream.ManageCapabilities{
		Sudo: true, AddUser: "/usr/sbin/useradd", AddGroup: "/usr/sbin/groupadd",
		ModUser: "/usr/sbin/usermod", Visudo: "/usr/sbin/visudo", Family: "debian",
	}

	d := Desired{
		Groups: []Group{{Name: "yayilim", Sudo: sudoers.Rule{
			Commands: []sudoers.Command{{Path: "/usr/bin/nginx", Args: []string{"-t"}}},
		}}},
		Users: []User{{Name: "suheda", Groups: []string{"yayilim"}}},
	}

	steps, err := Plan(caps, d, empty())
	if err != nil {
		t.Fatal(err)
	}

	rep := Apply(context.Background(), r, steps)
	t.Logf("ilk koşu: %s", rep.Summary())
	for _, res := range rep.Results {
		if res.Outcome != OutcomeDone {
			t.Errorf("%s %s: %v — %s", res.Step.Kind, res.Outcome, res.Err, res.Output)
		}
	}
	if !rep.OK() {
		t.Fatal("gerçek hedefte plan uygulanamadı")
	}

	/*
	 * ⚠️ İKİNCİ KOŞU, İDEMPOTENSLİĞİN GERÇEK ÖLÇÜSÜ. Birim testi
	 * gözlenen durumu ELLE veriyor; burada durumu makinenin kendisi
	 * söylüyor.
	 */
	obs := observe(t, r, d)
	again, err := Plan(caps, d, obs)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		for _, s := range again {
			t.Errorf("ikinci koşu iş üretti: %s — %s", s.Kind, s.Command)
		}
	}
}

// observe, hedefin şu anki durumunu okur.
func observe(t *testing.T, r sshRunner, d Desired) Observed {
	t.Helper()
	ctx := context.Background()
	o := Observed{
		Groups: map[string]bool{}, Users: map[string][]string{},
		PosternSudoers: map[string]string{},
	}

	for _, g := range d.Groups {
		if _, err := r.Exec(ctx, "getent group "+g.Name, ""); err == nil {
			o.Groups[g.Name] = true
		}
		out, err := r.Exec(ctx, "sudo -n cat "+sudoPath(g.Name), "")
		if err == nil {
			o.PosternSudoers[sudoPath(g.Name)] = out
		}
	}
	for _, u := range d.Users {
		out, err := r.Exec(ctx, "id -Gn "+u.Name, "")
		if err != nil {
			continue
		}
		o.Users[u.Name] = strings.Fields(strings.TrimSpace(out))
	}

	return o
}
