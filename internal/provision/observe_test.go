package provision

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/sudoers"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

/*
 * ⚠️ OKUNAN DURUM, PLANIN "HİÇBİR ŞEY YAPMA" DİYECEĞİ KADAR EKSİKSİZ OLMALI.
 * Bir alan okunmazsa plan onu eksik sanır ve her koşuda yeniden yazar —
 * sudoers dosyası için bu, her koşuda üç root komutu demek.
 */
func TestObserveReadsEverythingThePlanCompares(t *testing.T) {
	rule := sudoers.Rule{Commands: []sudoers.Command{{Path: "/usr/bin/nginx", Args: []string{"-t"}}}}
	groupFile, _ := sudoers.Render("%dba", rule, "group dba — written by postern")
	userFile, _ := sudoers.Render("jit-ayse", rule, "user jit-ayse — written by postern")

	r := runnerFor(t, hostAnswers(map[string]string{
		"getent group dba":                        "dba:x:1005:jit-ayse\n",
		"getent group " + JITGroup:                JITGroup + ":x:1006:jit-ayse\n",
		"id -Gn jit-ayse":                         "jit-ayse dba " + JITGroup + "\n",
		"sudo -n cat " + SudoPath("dba"):          groupFile,
		"sudo -n cat " + UserSudoPath("jit-ayse"): userFile,
	}))
	d := Desired{
		Groups: []Group{{Name: "dba", Sudo: rule}},
		Users:  []User{{Name: "jit-ayse", Groups: []string{"dba"}, JIT: true, Sudo: &rule}},
	}

	obs, err := Observe(context.Background(), r, d)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := Plan(able(), d, obs)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 0 {
		t.Errorf("her şey yerindeyken plan iş üretti:\n%s", commandsOf(steps))
	}

	// Eksik olanlar "yok" diye okunmalı: makine 127 ile cevap veriyor.
	obs, err = Observe(context.Background(), runnerFor(t, hostAnswers(nil)), d)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Groups["dba"] || obs.Groups[JITGroup] || len(obs.Users) != 0 || len(obs.PosternSudoers) != 0 {
		t.Errorf("hiçbir şey yokken bir şey var göründü: %+v", obs)
	}
}

/*
 * ⚠️ CEVAPSIZLIK "YOK" DEĞİL, HATA. Cevapsız kalan `getent` grubu yok
 * gösterir, plan onu yeniden yaratmaya kalkar; cevapsız kalan `id`
 * silinmemiş bir hesabı "gitti" gösterir. Canlı testin ilk yardımcısı tam
 * olarak bunu yapıyordu.
 */
func TestObserveTreatsSilenceAsAnErrorNotAsAbsence(t *testing.T) {
	r := runnerFor(t, answerSilence)

	if _, err := Observe(context.Background(), r, Desired{Groups: []Group{{Name: "dba"}}}); !errors.Is(err, upstream.ErrNoAnswer) {
		t.Errorf("Observe: err = %v, ErrNoAnswer bekleniyordu", err)
	}
	if _, err := Account(context.Background(), r, "ayse"); !errors.Is(err, upstream.ErrNoAnswer) {
		t.Errorf("Account: err = %v, ErrNoAnswer bekleniyordu", err)
	}
}

// Sökme planının üç girdisi ölçümden geliyor: numara, ev, üyelik.
func TestAccountReadsWhatTheRevokePlanNeeds(t *testing.T) {
	r := runnerFor(t, hostAnswers(map[string]string{
		"getent passwd jit-ayse": "jit-ayse:x:1042:1042::/srv/homes/jit-ayse:/bin/bash\n",
		"id -Gn jit-ayse":        "jit-ayse " + JITGroup + " dba\n",
	}))

	a, err := Account(context.Background(), r, "jit-ayse")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Exists || a.UID != 1042 || a.Home != "/srv/homes/jit-ayse" || !a.InJITGroup() {
		t.Errorf("hesap yanlış okundu: %+v", a)
	}

	gone, err := Account(context.Background(), r, "yok")
	if err != nil {
		t.Fatal(err)
	}
	if gone.Exists {
		t.Errorf("olmayan hesap var göründü: %+v", gone)
	}
}

/*
 * ⚠️ GRUP ENVANTERİ NUMARASIYLA OKUNUYOR ve 1000'in altı korunuyor. Panelin
 * seçicisi bu listeyle çiziliyor; numara olmadan docker'ı dba'dan ayıramaz.
 * Sınır tam 1000'de: GID_MIN'in kendisi kullanıcı grubudur.
 */
func TestGroupsAreReadWithTheirNumbersAndProtection(t *testing.T) {
	r := runnerFor(t, hostAnswers(map[string]string{
		"getent group": "root:x:0:\nwheel:x:10:ayse\nusers:x:100:\ndocker:x:998:veli\n" +
			"ops:x:1000:\ndba:x:1001:ayse,veli\n" + JITGroup + ":x:1002:\n",
	}))
	groups, err := Groups(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"root": true, "wheel": true, "users": true, "docker": true,
		"ops": false, "dba": false, JITGroup: false,
	}
	if len(groups) != len(want) {
		t.Fatalf("%d grup bekleniyordu, %d okundu: %+v", len(want), len(groups), groups)
	}
	for _, g := range groups {
		if g.Protected() != want[g.Name] {
			t.Errorf("%s (gid %d): protected=%v, beklenen %v", g.Name, g.GID, g.Protected(), want[g.Name])
		}
		if g.Name == "dba" && strings.Join(g.Members, ",") != "ayse,veli" {
			t.Errorf("dba üyeleri yanlış okundu: %v", g.Members)
		}
		if g.Name == "root" && g.Members == nil {
			t.Error("üyesiz grup nil üye listesiyle döndü — JSON'da null olur, panel .length okuyamaz")
		}
	}

	// Cevapsızlık envanter değil, hata.
	if _, err := Groups(context.Background(), runnerFor(t, answerSilence)); err == nil {
		t.Fatal("cevapsız hedef boş bir envanter gibi döndü")
	}
	if _, err := Groups(context.Background(), runnerFor(t, hostAnswers(map[string]string{
		"getent group": "broken line\n",
	}))); err == nil {
		t.Fatal("bozuk satır sessizce yutuldu")
	}
}

// Plan sistem grubunu numarasından tanıyor; numara Observe'dan geliyor.
func TestObserveRecordsGroupNumbers(t *testing.T) {
	r := runnerFor(t, hostAnswers(map[string]string{"getent group docker": "docker:x:998:\n"}))
	obs, err := Observe(context.Background(), r, Desired{Groups: []Group{{Name: "docker"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !obs.Groups["docker"] || obs.GIDs["docker"] != 998 {
		t.Fatalf("docker'ın numarası okunmadı: %+v", obs)
	}
}

// Principals dosyası okunuyor ki plan onu bayt bayt karşılaştırabilsin.
func TestObserveReadsTheTemporaryAccountsPrincipalsFile(t *testing.T) {
	r := runnerFor(t, hostAnswers(map[string]string{
		"sudo -n cat /etc/ssh/auth_principals/jitayse": "jitayse\n",
		"id -Gn jitayse":           "jitayse " + JITGroup + "\n",
		"getent group " + JITGroup: JITGroup + ":x:1006:jitayse\n",
	}))
	d := Desired{Users: []User{{Name: "jitayse", JIT: true}}, PrincipalsFile: "/etc/ssh/auth_principals/%u"}
	obs, err := Observe(context.Background(), r, d)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Principals["/etc/ssh/auth_principals/jitayse"] != "jitayse\n" {
		t.Fatalf("principals dosyası okunmadı: %+v", obs.Principals)
	}
	steps, err := Plan(able(), d, obs)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 0 {
		t.Errorf("her şey yerindeyken plan iş üretti:\n%s", commandsOf(steps))
	}
}
