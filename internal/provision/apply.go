package provision

// Planın hedefte uygulanması.

import (
	"context"
	"fmt"
	"strings"
)

/*
 * Runner, hedefte tek bir komut çalıştırabilen şey.
 *
 * ⚠️ ARAYÜZ, SSH'A BAĞLI DEĞİL. Uygulamanın kararları — nerede durulacak,
 * ne kaydedilecek — bir bağlantı kurmadan ölçülebilmeli; yoksa "ilk
 * hatada dur" gibi bir kuralın testi, gerçek bir makineye ve gerçek bir
 * arızaya bağlı olurdu.
 */
type Runner interface {
	// Exec, komutu çalıştırır; stdin boş değilse girdi olarak verir.
	Exec(ctx context.Context, command, stdin string) (string, error)
}

// Outcome, tek bir adımın sonucu.
type Outcome string

const (
	OutcomeDone Outcome = "done"
	OutcomeFail Outcome = "failed"
	// OutcomeSkipped, önceki bir adım düştüğü için HİÇ DENENMEDİ.
	OutcomeSkipped Outcome = "not attempted"
)

// Result, bir adımın sonucu ve hedefin söyledikleri.
type Result struct {
	Step    Step
	Outcome Outcome
	// Output, hedefin çıktısı — denetim satırına giren şey.
	Output string
	Err    error
}

/*
 * Report, bir hedefteki koşunun tamamı.
 *
 * ⚠️ "KAÇ TANE YAPILDI" YETMİYOR, "KAÇ TANE DENENMEDİ" DE GEREKİYOR.
 * Yarıda kalmış bir koşuda kalan adımları saymamak, makinenin ne
 * durumda olduğunu okuyamamak demek — ve bu paketin reddettiği tek şey
 * yarım uygulanmış makine.
 */
type Report struct {
	Results []Result
}

func (r Report) count(o Outcome) int {
	n := 0
	for _, res := range r.Results {
		if res.Outcome == o {
			n++
		}
	}

	return n
}

func (r Report) Done() int    { return r.count(OutcomeDone) }
func (r Report) Failed() int  { return r.count(OutcomeFail) }
func (r Report) Skipped() int { return r.count(OutcomeSkipped) }

// OK, koşunun tamamının uygulandığı.
func (r Report) OK() bool { return r.Failed() == 0 && r.Skipped() == 0 }

// Summary, panelde ve denetim satırında görünecek cümle.
func (r Report) Summary() string {
	if len(r.Results) == 0 {
		return "nothing to do"
	}
	if r.OK() {
		return fmt.Sprintf("%d applied", r.Done())
	}

	return fmt.Sprintf("%d applied, %d failed, %d not attempted",
		r.Done(), r.Failed(), r.Skipped())
}

// FirstError, koşuyu durduran hata.
func (r Report) FirstError() error {
	for _, res := range r.Results {
		if res.Outcome == OutcomeFail {
			return res.Err
		}
	}

	return nil
}

/*
 * Apply, adımları sırayla çalıştırır ve İLK HATADA DURUR.
 *
 * ⚠️ DEVAM ETMEK, YARIM UYGULAMANIN KENDİSİ. Örnekler soyut değil:
 * doğrulama adımı düşmüşken kurulum adımını koşturmak, geçersiz bir
 * sudoers dosyasını yerine koyar ve o makinede herkesin sudo'sunu
 * götürür — postern'in kendi hesabı dahil, yani makine kendini
 * onaramaz. Grup açılamamışken kullanıcıyı o gruba eklemek de hata
 * verir, ama daha kötüsü: hata mesajı asıl sebebi değil sonucu
 * gösterir.
 *
 * ⚠️ DENENMEYEN ADIMLAR DA RAPORA GİRİYOR. Operatör makinenin hangi
 * noktada kaldığını görmeli; eksik bir liste, "geri kalanı yapıldı
 * mı" sorusunu cevapsız bırakır.
 */
func Apply(ctx context.Context, r Runner, steps []Step) Report {
	rep := Report{Results: make([]Result, 0, len(steps))}

	stopped := false
	for _, s := range steps {
		if stopped {
			rep.Results = append(rep.Results, Result{Step: s, Outcome: OutcomeSkipped})
			continue
		}

		/*
		 * ⚠️ BAĞLAM İPTALİ DE BİR DURUŞ. Kullanıcı işi iptal ettiğinde
		 * ya da süre dolduğunda kalan adımlar "denenmedi" olarak
		 * yazılmalı; sessizce bitmiş gibi raporlamak, yarım bir
		 * makineyi tam göstermek olurdu.
		 */
		if err := ctx.Err(); err != nil {
			rep.Results = append(rep.Results, Result{
				Step: s, Outcome: OutcomeFail, Err: err,
			})
			stopped = true
			continue
		}

		out, err := r.Exec(ctx, s.Command, s.Content)
		if err != nil {
			rep.Results = append(rep.Results, Result{
				Step: s, Outcome: OutcomeFail, Output: out,
				Err: fmt.Errorf("%s: %w", s.Kind, err),
			})
			stopped = true
			continue
		}

		rep.Results = append(rep.Results, Result{
			Step: s, Outcome: OutcomeDone, Output: strings.TrimSpace(out),
		})
	}

	return rep
}
