package hostacct

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/store"
)

// fakePeek, kişinin kendi bağlantısı: tek komut, sabit cevap.
type fakePeek struct {
	out  string
	err  error
	seen []string
}

func (p *fakePeek) Exec(_ context.Context, cmd, _ string) (string, error) {
	p.seen = append(p.seen, cmd)

	return p.out, p.err
}

// verifyCase, bir doğrulama koşusunun gözlenen bütün etkileri.
type verifyCase struct {
	deps    VerifyDeps
	peek    *fakePeek
	saved   []store.HostAccount
	audited []string
	repairs int
	saveErr error
}

func newVerifyCase(row store.HostAccount, answer string, answerErr error) *verifyCase {
	c := &verifyCase{peek: &fakePeek{out: answer, err: answerErr}}
	c.deps = VerifyDeps{
		Rules: func(context.Context) (map[string]store.GroupSudo, error) { return nil, nil },
		Row: func(context.Context, string, string) (store.HostAccount, error) {
			return row, nil
		},
		Save: func(_ context.Context, a store.HostAccount) error {
			if c.saveErr != nil {
				return c.saveErr
			}
			c.saved = append(c.saved, a)

			return nil
		},
		Audit: func(_ context.Context, _, _, detail string) error {
			c.audited = append(c.audited, detail)

			return nil
		},
		Repair: func(context.Context, model.User, model.Target) error {
			c.repairs++

			return nil
		},
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	}

	return c
}

func (c *verifyCase) run(t *testing.T) {
	t.Helper()
	Verify(t.Context(), c.deps, c.peek, sweepUsers["ayse"],
		model.Target{Name: "db01", Host: "10.0.0.1", Port: 22})
}

var activeRow = store.HostAccount{
	TargetName: "db01", Username: "ayse", OSUser: "acctayse",
	Origin: store.OriginCreated, State: store.HostAccountActive,
	DesiredFP: "abc", AppliedFP: "abc",
}

/*
 * ⚠️ MAKİNE DOĞRULUYORSA HİÇBİR ŞEY YAZILMIYOR — ama koşu yine deftere
 * giriyor. Komut kişinin hesabında, hedefin günlüğünde onun adına koştu;
 * izsiz bırakmak, yoklamada bir kez ölçülüp kapatılan hata.
 */
func TestAMachineThatAgreesIsOnlyRecorded(t *testing.T) {
	c := newVerifyCase(activeRow, "acctayse postern-managed postern-dba\n", nil)
	c.run(t)

	if len(c.saved) > 0 {
		t.Errorf("makine doğrularken satır yazıldı: %+v", c.saved)
	}
	if c.repairs > 0 {
		t.Errorf("makine doğrularken onarım koştu (%d)", c.repairs)
	}
	if len(c.audited) != 1 {
		t.Fatalf("%d defter satırı, bir tane bekleniyordu: %v", len(c.audited), c.audited)
	}
	if !strings.Contains(c.audited[0], groupsCommand) {
		t.Errorf("satır hangi komutun koştuğunu söylemiyor: %q", c.audited[0])
	}
	if !strings.Contains(c.audited[0], "has every group") {
		t.Errorf("satır ölçümün sonucunu söylemiyor: %q", c.audited[0])
	}
}

/*
 * ⚠️ ASIL ÖLÇÜM BU: EKSİK GRUP, KAYDI YALANLIYOR.
 *
 * Hedef postern'in ayağının altından yeniden kurulduğunda satır hâlâ
 * "uyguladım" der ve sıcak yol hedefe hiç bağlanmaz. Kişinin kendi
 * bağlantısı bunu görüyor: parmak izi düşürülüyor (artık hızlı şerit
 * yok) ve onarım hemen koşuyor.
 */
func TestAMissingGroupClearsTheRecordAndRepairs(t *testing.T) {
	c := newVerifyCase(activeRow, "acctayse postern-managed\n", nil)
	c.run(t)

	if len(c.audited) != 1 || !strings.Contains(c.audited[0], "postern-dba") {
		t.Fatalf("defter eksik grubu adıyla söylemiyor: %v", c.audited)
	}
	if strings.Contains(c.audited[0], "postern-managed") {
		t.Errorf("makinede DURAN grup eksik gibi yazıldı: %q", c.audited[0])
	}
	if len(c.saved) != 1 {
		t.Fatalf("%d satır yazıldı, bir tane bekleniyordu", len(c.saved))
	}
	if c.saved[0].AppliedFP != "" {
		t.Errorf("parmak izi düşürülmedi (%q): sıcak yol yine hızlı şeride girerdi",
			c.saved[0].AppliedFP)
	}
	if c.repairs != 1 {
		t.Errorf("onarım %d kez koştu, bir kez bekleniyordu", c.repairs)
	}
}

/*
 * ⚠️ CEVAPSIZLIK SÜRÜKLENME DEĞİL. Kapanmış bir kanal, süresi dolmuş bir
 * komut ya da okunamayan bir çıktı "grubu yok" demek değil; sürüklenme
 * saymak, sessiz bir kanalı filodaki her makinede root komutu çalıştıran
 * bir tetiğe çevirirdi. Deneme yine deftere yazılıyor.
 */
func TestAnUnansweredCheckChangesNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer string
		err    error
	}{
		{"komut düştü", "", errors.New("session closed")},
		{"boş cevap", "   \n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newVerifyCase(activeRow, tc.answer, tc.err)
			c.run(t)

			if len(c.saved) > 0 || c.repairs > 0 {
				t.Errorf("cevapsız ölçüm iş üretti: %d yazma, %d onarım",
					len(c.saved), c.repairs)
			}
			if len(c.audited) != 1 {
				t.Fatalf("deneme deftere yazılmadı: %v", c.audited)
			}
			if !strings.Contains(c.audited[0], groupsCommand) {
				t.Errorf("satır komutu söylemiyor: %q", c.audited[0])
			}
		})
	}
}

/*
 * ⚠️ KAYDI OLMAYAN HESABA SORU SORULMUYOR — ve ölçü defter değil, HEDEFE
 * GİDEN KOMUT. postern o makinede o hesabın kaynağı değilse (satır yok,
 * ya da hesap artık açık değil) başka bir aracın açtığı bir hesabın
 * gruplarını kendi kaydına göre yargılamak olurdu.
 */
func TestAnAccountPosternDoesNotOwnIsNeverAsked(t *testing.T) {
	for _, tc := range []struct {
		name string
		row  store.HostAccount
		err  error
	}{
		{"satır yok", store.HostAccount{}, store.ErrNotFound},
		{"hesap kilitli", store.HostAccount{
			TargetName: "db01", Username: "ayse", OSUser: "acctayse",
			Origin: store.OriginCreated, State: store.HostAccountLocked,
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newVerifyCase(tc.row, "acctayse\n", nil)
			c.deps.Row = func(context.Context, string, string) (store.HostAccount, error) {
				return tc.row, tc.err
			}
			c.run(t)

			if len(c.peek.seen) > 0 {
				t.Errorf("kişinin bağlantısında komut koştu: %v", c.peek.seen)
			}
			if len(c.audited) > 0 || len(c.saved) > 0 || c.repairs > 0 {
				t.Errorf("hiç koşmaması gereken yol iş üretti")
			}
		})
	}
}

/*
 * ⚠️ KAYIT DÜZELTİLEMEDİYSE ONARIM DA ÇAĞRILMIYOR. Sıcak yol parmak
 * izine bakıyor: eski değer yerinde kalmışsa koşu yine hızlı şeride
 * girer, yani hedefe boşuna bir yönetim bağlantısı açardık.
 */
func TestTheRepairIsNotCalledWhenTheRecordCouldNotBeCleared(t *testing.T) {
	c := newVerifyCase(activeRow, "acctayse postern-managed\n", nil)
	c.saveErr = errors.New("database is down")
	c.run(t)

	if c.repairs > 0 {
		t.Errorf("kayıt yazılamazken onarım koştu (%d)", c.repairs)
	}
}
