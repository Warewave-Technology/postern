package provision

import (
	"context"
	"errors"
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
