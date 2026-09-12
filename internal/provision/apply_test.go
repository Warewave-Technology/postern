package provision

import (
	"context"
	"errors"
	"strings"
	"testing"
)

/*
 * fakeRunner, komutları kaydeden ve istenen adımda düşen bir hedef.
 */
type fakeRunner struct {
	ran     []string
	stdins  []string
	failOn  string
	failErr error
}

func (f *fakeRunner) Exec(_ context.Context, cmd, stdin string) (string, error) {
	f.ran = append(f.ran, cmd)
	f.stdins = append(f.stdins, stdin)
	if f.failOn != "" && strings.Contains(cmd, f.failOn) {
		return "hedefin söyledikleri", f.failErr
	}

	return "ok", nil
}

func steps(cmds ...string) []Step {
	out := make([]Step, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, Step{Kind: StepKind(c), Command: c})
	}

	return out
}

/*
 * ⚠️ BU DOSYANIN TEK BÜYÜK İDDİASI: İLK HATADA DURULUYOR.
 *
 * Devam etmek soyut bir risk değil. Doğrulama adımı düşmüşken kurulum
 * adımını koşturmak, geçersiz bir sudoers dosyasını yerine koyar ve o
 * makinede herkesin sudo'sunu götürür — postern'in kendi hesabı dahil,
 * yani makine kendini onaramaz hâle gelir.
 */
func TestApplyStopsAtTheFirstFailure(t *testing.T) {
	r := &fakeRunner{failOn: "visudo", failErr: errors.New("syntax error")}

	rep := Apply(context.Background(), r,
		steps("sudo -n groupadd dba", "sudo -n tee staged", "sudo -n visudo -cf staged",
			"sudo -n install staged dest"))

	for _, ran := range r.ran {
		if strings.Contains(ran, "install") {
			t.Fatal("DOĞRULAMA DÜŞTÜKTEN SONRA KURULUM KOŞTU: "+
				"geçersiz sudoers dosyası yerine konurdu", ran)
		}
	}
	if rep.Done() != 2 || rep.Failed() != 1 || rep.Skipped() != 1 {
		t.Errorf("sayılar = %d/%d/%d, 2/1/1 bekleniyordu (%s)",
			rep.Done(), rep.Failed(), rep.Skipped(), rep.Summary())
	}
}

/*
 * ⚠️ DENENMEYEN ADIM DA RAPORDA. Eksik bir liste, "geri kalanı yapıldı
 * mı" sorusunu cevapsız bırakır ve makinenin hangi noktada kaldığı
 * görünmez olur.
 */
func TestUnattemptedStepsAreStillReported(t *testing.T) {
	r := &fakeRunner{failOn: "iki", failErr: errors.New("düştü")}

	rep := Apply(context.Background(), r, steps("bir", "iki", "üç", "dört"))

	if len(rep.Results) != 4 {
		t.Fatalf("rapor %d adım taşıyor, 4 bekleniyordu", len(rep.Results))
	}
	if rep.Results[2].Outcome != OutcomeSkipped || rep.Results[3].Outcome != OutcomeSkipped {
		t.Errorf("denenmeyen adımlar işaretlenmedi: %v", rep.Results)
	}
	if !strings.Contains(rep.Summary(), "not attempted") {
		t.Errorf("özet denenmeyenleri söylemiyor: %q", rep.Summary())
	}
}

// ⚠️ Hedefin söyledikleri kaydediliyor: denetim satırına giren şey o.
func TestTargetOutputIsKept(t *testing.T) {
	r := &fakeRunner{failOn: "iki", failErr: errors.New("düştü")}

	rep := Apply(context.Background(), r, steps("bir", "iki"))

	if rep.Results[1].Output != "hedefin söyledikleri" {
		t.Errorf("arızanın çıktısı kaydedilmedi: %q", rep.Results[1].Output)
	}
	if rep.FirstError() == nil {
		t.Error("durduran hata raporda yok")
	}
}

// ⚠️ Kural metni stdin'den gidiyor; komut satırına girmiyor.
func TestContentGoesOnStdin(t *testing.T) {
	r := &fakeRunner{}

	Apply(context.Background(), r, []Step{{
		Kind: StepSudoStage, Command: "sudo -n tee x >/dev/null",
		Content: "%dba ALL=(root) NOPASSWD: /usr/bin/nginx -t\n",
	}})

	if !strings.Contains(r.stdins[0], "NOPASSWD") {
		t.Errorf("içerik stdin'e verilmedi: %q", r.stdins[0])
	}
	if strings.Contains(r.ran[0], "NOPASSWD") {
		t.Errorf("KURAL METNİ KOMUT SATIRINA GİRDİ: %q", r.ran[0])
	}
}

/*
 * ⚠️ İPTAL EDİLEN İŞ, BİTMİŞ İŞ GİBİ RAPORLANMAMALI. Süre dolduğunda
 * ya da operatör durdurduğunda makine yarım kalıyor; raporun bunu
 * söylemesi gerekiyor.
 */
func TestCancelledRunIsNotReportedAsFinished(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rep := Apply(ctx, &fakeRunner{}, steps("bir", "iki"))

	if rep.OK() {
		t.Fatal("İPTAL EDİLEN KOŞU BAŞARILI SAYILDI")
	}
	if rep.Done() != 0 {
		t.Errorf("iptalden sonra adım koştu: %s", rep.Summary())
	}
}

// Boş plan başarılı ve bunu söylüyor: yapacak bir şey yoktu.
func TestEmptyPlanIsSuccessAndSaysSo(t *testing.T) {
	rep := Apply(context.Background(), &fakeRunner{}, nil)

	if !rep.OK() {
		t.Error("boş plan başarısız sayıldı")
	}
	if rep.Summary() != "nothing to do" {
		t.Errorf("özet = %q", rep.Summary())
	}
}

/*
 * ⚠️ DENENMEMİŞ ADIM TAŞIYAN RAPOR "TAMAM" DEĞİL — VE BU İDDİA
 * Apply'IN AKIŞINA DEĞİL, TİPİN KENDİSİNE AİT.
 *
 * Bugünkü akışta atlanan adım yalnızca bir hatadan sonra oluşuyor,
 * dolayısıyla şart Apply üzerinden ölçülemiyor: kaldırdığımda testler
 * yeşil kalıyordu. Ama Report dışarıya açık bir tip ve paneli besleyen
 * taraf onu süzerek ya da birleştirerek kurabilir. O durumda yarım
 * uygulanmış bir makineyi tam göstermek, bu paketin reddettiği tek
 * şeyi yapmak olurdu.
 */
func TestReportWithUnattemptedStepsIsNotOK(t *testing.T) {
	rep := Report{Results: []Result{
		{Step: Step{Kind: StepGroupAdd}, Outcome: OutcomeDone},
		{Step: Step{Kind: StepUserAdd}, Outcome: OutcomeSkipped},
	}}

	if rep.OK() {
		t.Fatal("YARIM KOŞU TAMAM SAYILDI: denenmemiş adım taşıyan rapor " +
			"makinenin tam yapılandırıldığını söylüyor")
	}
	if !strings.Contains(rep.Summary(), "not attempted") {
		t.Errorf("özet denenmeyeni söylemiyor: %q", rep.Summary())
	}
}
