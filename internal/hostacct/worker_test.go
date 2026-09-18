package hostacct

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

func owedRow(user string) store.HostAccount {
	return store.HostAccount{
		TargetName: "db01", Username: user, OSUser: user,
		Origin: store.OriginCreated, State: store.HostAccountActive,
	}
}

func workerDeps(saved *[]store.HostAccount, dialed *int) WorkerDeps {
	return WorkerDeps{
		Owed:   func(context.Context, time.Time) ([]store.HostAccount, error) { return nil, nil },
		Active: func(context.Context) (int, error) { return 100, nil },
		Target: func(_ context.Context, n string) (model.Target, error) {
			return model.Target{Name: n, Host: "10.0.0.1", Port: 22}, nil
		},
		Save: func(_ context.Context, a store.HostAccount) error {
			*saved = append(*saved, a)
			return nil
		},
		Connect: func(context.Context, model.Target, string) (Runner, error) {
			*dialed++
			return &fakeRunner{answers: map[string]string{
				"getent passwd ayse": "ayse:x:1001:1001::/home/ayse:/bin/bash",
			}}, nil
		},
		Caps: func(context.Context, Runner) (upstream.ManageCapabilities, error) {
			return manageableCaps(), nil
		},
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
}

/*
 * ⚠️ "locked" SATIRA, HEDEF GERÇEKTEN KİLİTLENDİKTEN SONRA YAZILIYOR.
 *
 * Önce yazmak kayda yalan yazmaktır: panel "kapandı" der, makinede hesap
 * durmaya devam eder, ve kimse bir daha oraya bakmaz. Bu test, hedefe
 * ulaşılamadığında satırın active KALDIĞINI ölçüyor.
 */
func TestTheRecordSaysLockedOnlyAfterTheHostIs(t *testing.T) {
	var saved []store.HostAccount
	dialed := 0
	d := workerDeps(&saved, &dialed)
	d.Owed = func(context.Context, time.Time) ([]store.HostAccount, error) {
		return []store.HostAccount{owedRow("ayse")}, nil
	}
	d.Connect = func(context.Context, model.Target, string) (Runner, error) {
		return nil, errors.New("dial tcp: no route to host")
	}

	NewWorker(d, time.Minute).Tick(t.Context())

	if len(saved) != 1 {
		t.Fatalf("satır yazılmadı: %+v", saved)
	}
	if saved[0].State != store.HostAccountActive {
		t.Errorf("hedefe ulaşılamadı ama satır %q yazıldı", saved[0].State)
	}
	if saved[0].LastError == "" || saved[0].NextAttemptAt.IsZero() {
		t.Errorf("sebep ve yeniden deneme zamanı yazılmadı: %+v", saved[0])
	}
}

/*
 * ⚠️ BAŞARIDA awaiting_decision DA YAZILIYOR (K3). Bu yolda insan yoktu;
 * hesabın silinip silinmeyeceğine bir kişi bakacak. Bayrak yazılmazsa
 * kilitli hesap panelde hiçbir listeye düşmez ve orada sonsuza kadar
 * kilitli kalır.
 */
func TestASuccessfulLockWaitsForAHumanDecision(t *testing.T) {
	var saved []store.HostAccount
	dialed := 0
	d := workerDeps(&saved, &dialed)
	d.Owed = func(context.Context, time.Time) ([]store.HostAccount, error) {
		return []store.HostAccount{owedRow("ayse")}, nil
	}
	audited := 0
	d.Audit = func(context.Context, string, string) error { audited++; return nil }

	NewWorker(d, time.Minute).Tick(t.Context())

	if len(saved) != 1 || saved[0].State != store.HostAccountLocked {
		t.Fatalf("kilit yazılmadı: %+v", saved)
	}
	if !saved[0].AwaitingDecision {
		t.Error("karar bekleyen olarak işaretlenmedi — panelde hiçbir listeye düşmez")
	}
	if audited != 1 {
		t.Errorf("deftere yazılmadı: %d satır", audited)
	}
}

/*
 * ⚠️ TAVAN AŞILDIĞINDA HİÇBİR ŞEY YAPILMIYOR.
 *
 * Dizindeki bir hata — yanlış kaldırılan bir grup, boşalan bir OU — bir
 * anda herkesin erişimini bitirebilir. Yarısını uygulamak, hem hasarı
 * verip hem sebebi gizlemek olurdu: operatör "bazıları kapandı" görür ve
 * hangisinin neden kapandığının cevabı hiçbir yerde durmaz.
 */
func TestNothingIsLockedWhenTheBlastRadiusCapIsReached(t *testing.T) {
	var saved []store.HostAccount
	dialed := 0
	d := workerDeps(&saved, &dialed)
	rows := make([]store.HostAccount, 0, 40)
	for i := 0; i < 40; i++ {
		rows = append(rows, owedRow("ayse"))
	}
	d.Owed = func(context.Context, time.Time) ([]store.HostAccount, error) { return rows, nil }
	d.Active = func(context.Context) (int, error) { return 100, nil }

	NewWorker(d, time.Minute).Tick(t.Context())

	if dialed != 0 {
		t.Errorf("tavan aşılmışken %d hedefe bağlanıldı", dialed)
	}
	if len(saved) != 0 {
		t.Errorf("tavan aşılmışken satır yazıldı: %+v", saved)
	}
}

/*
 * ⚠️ TAVAN İKİ EŞİĞİN İKİSİNİ BİRDEN İSTİYOR. Üç hesaplı bir kurulumda
 * bir hesabın kapanması %33'tür ve bu olağan bir gündür; oran tek başına,
 * küçük kurulumlarda özelliği hiç çalışmaz hâle getirirdi.
 */
func TestASmallInstallIsNotBlockedByTheFractionAlone(t *testing.T) {
	var saved []store.HostAccount
	dialed := 0
	d := workerDeps(&saved, &dialed)
	d.Owed = func(context.Context, time.Time) ([]store.HostAccount, error) {
		return []store.HostAccount{owedRow("ayse")}, nil
	}
	d.Active = func(context.Context) (int, error) { return 2, nil }

	NewWorker(d, time.Minute).Tick(t.Context())

	if dialed != 1 {
		t.Errorf("küçük kurulumda iş yapılmadı: %d bağlantı", dialed)
	}
}

// manageableCaps, eksiksiz bir hedef: Manageable() true.
func manageableCaps() upstream.ManageCapabilities {
	return upstream.ManageCapabilities{}
}

/*
 * ⚠️ ADIMLAR HEDEFTE DÜŞERSE DE SATIR "active" KALIYOR.
 *
 * Bağlanabilmek, kapatabilmek demek değil: sudo reddedebilir, dosya
 * yazılamayabilir, hesap kilitlenemeyebilir. Satıra "locked" yazmak için
 * ölçü, bağlantının kurulması değil ADIMLARIN BİTMESİ. Bu boşluk bir
 * mutasyonla ölçüldü: yalnızca connect hatasını sınayan test, apply
 * hatasında kaydın yalan söylemesini yakalamıyordu.
 */
func TestAFailedStepLeavesTheRecordUnlocked(t *testing.T) {
	var saved []store.HostAccount
	dialed := 0
	d := workerDeps(&saved, &dialed)
	d.Owed = func(context.Context, time.Time) ([]store.HostAccount, error) {
		return []store.HostAccount{owedRow("ayse")}, nil
	}
	d.Connect = func(context.Context, model.Target, string) (Runner, error) {
		dialed++
		// Hesap var, ama yazma komutları hedefte reddediliyor.
		return &refusingRunner{answers: map[string]string{
			"getent passwd ayse": "ayse:x:1001:1001::/home/ayse:/bin/bash",
			"id -Gn ayse":        "ayse",
		}}, nil
	}

	NewWorker(d, time.Minute).Tick(t.Context())

	if len(saved) != 1 {
		t.Fatalf("satır yazılmadı: %+v", saved)
	}
	if saved[0].State != store.HostAccountLocked {
		// beklenen yol
	} else {
		t.Errorf("adımlar düştü ama satır kilitli yazıldı: %+v", saved[0])
	}
	if saved[0].LastError == "" {
		t.Error("sebep yazılmadı")
	}
}

// refusingRunner, okumaları cevaplayan ama YAZMAYI reddeden hedef.
type refusingRunner struct{ answers map[string]string }

func (r *refusingRunner) Exec(_ context.Context, cmd, _ string) (string, error) {
	if out, ok := r.answers[cmd]; ok {
		return out, nil
	}

	return "", &upstream.CommandError{Status: 1, Stderr: "sudo: a password is required"}
}
func (r *refusingRunner) Close() error { return nil }
