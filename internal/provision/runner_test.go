package provision

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Warewave-Technology/postern/internal/upstream"
)

/*
 * ⚠️ HEDEFİN REDDİ "BAŞARISIZ", CEVAPSIZLIK "ULAŞILAMADI" OLARAK
 * RAPORLANMALI — Apply'ın gerçek bir bağlantıdan gelen hatayı doğru
 * kovaya koyabildiği tek yer bu çeviri.
 *
 * İki yönde de yanlış gidilebiliyor ve ikisi de operatörü yanlış yere
 * yollar: sudoers doğrulaması düşen bir makineyi "ulaşılamadı" demek
 * tekrar denetir (aynı ret gelir), cevapsız kalan bir makineyi "başarısız"
 * demek hedefin günlüklerine baktırır (orada hiçbir şey yoktur).
 */
func TestRunnerSortsAnswersFromSilence(t *testing.T) {
	refused := &upstream.CommandError{Status: 1, Stderr: "visudo: parse error"}
	silent := fmt.Errorf("%w: channel closed", upstream.ErrNoAnswer)

	rep := Apply(context.Background(), scripted{
		"sudo -n visudo -cf a": refused,
		"sudo -n visudo -cf b": silent,
	}, []Step{
		{Kind: StepSudoCheck, Command: "sudo -n visudo -cf a"},
	})
	if rep.Failed() != 1 || rep.Unreachable() != 0 {
		t.Errorf("hedefin reddi yanlış sınıflandı: %s", rep.Summary())
	}
	if !errors.As(rep.FirstError(), new(*upstream.CommandError)) {
		t.Errorf("reddin sebebi kayboldu: %v", rep.FirstError())
	}

	rep = Apply(context.Background(), scripted{
		"sudo -n visudo -cf b": silent,
	}, []Step{
		{Kind: StepSudoCheck, Command: "sudo -n visudo -cf b"},
	})
	if rep.Unreachable() != 1 || rep.Failed() != 0 {
		t.Errorf("cevapsızlık yanlış sınıflandı: %s", rep.Summary())
	}
	// upstream'in sınıfı da zincirde kalmalı: panel sebebi oradan okuyor.
	if !errors.Is(rep.FirstError(), upstream.ErrNoAnswer) {
		t.Errorf("upstream sınıfı kayboldu: %v", rep.FirstError())
	}
}

// scripted, komuta göre upstream'in döndüreceği hatayı verir ve cevabı
// SSHRunner'ın kullandığı çeviriden geçirir.
type scripted map[string]error

func (s scripted) Exec(_ context.Context, command, _ string) (string, error) {
	return answer("", s[command])
}

// Bağlantısız bir Runner'dan gelen hata ulaşılamazlık olmalı, panik değil.
func TestRunnerWithoutAConnectionIsUnreachable(t *testing.T) {
	var r *SSHRunner
	if _, err := r.Exec(context.Background(), "true", ""); !errors.Is(err, ErrUnreachable) {
		t.Errorf("err = %v, ErrUnreachable bekleniyordu", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
