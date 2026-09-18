package hostacct

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

// fakeRunner, hedefte komut çalıştırıyormuş gibi yapar.
type fakeRunner struct {
	answers map[string]string
	seen    []string
}

func (f *fakeRunner) Exec(_ context.Context, cmd, _ string) (string, error) {
	f.seen = append(f.seen, cmd)
	if out, ok := f.answers[cmd]; ok {
		return out, nil
	}
	/*
	 * Yazma komutları başarılı sayılıyor: taklit hedef, planın ürettiği
	 * adımları kabul eden bir makine. Okuma komutlarının cevabı
	 * answers'ta; orada olmayan bir okuma "yok" demek.
	 */
	if strings.HasPrefix(cmd, "sudo -n ") {
		return "", nil
	}
	/*
	 * ⚠️ HEDEFİN "YOK" CEVABI TİPLİ BİR HATA. provision.absent, komutun
	 * sıfırdan farklı çıkışını upstream.CommandError'a bakarak "yok"
	 * diye okuyor; düz bir error, gerçek bir arıza sayılıyor. Taklit
	 * hedefin bunu taklit etmesi şart, yoksa test gerçekte olmayan bir
	 * arızayı ölçer.
	 */
	return "", &upstream.CommandError{Status: 1}
}
func (f *fakeRunner) Close() error { return nil }

var testUser = model.User{Name: "ayse", OSUser: "ayse", Groups: []model.Group{
	{Name: "dba", Targets: []string{"db01"}},
}}
var testTarget = model.Target{Name: "db01", Host: "10.0.0.1", Port: 22}

func baseDeps(dialed *int, saved *store.HostAccount) Deps {
	return Deps{
		Rules: func(context.Context) (map[string]store.GroupSudo, error) { return nil, nil },
		Row: func(context.Context, string, string) (store.HostAccount, error) {
			return store.HostAccount{}, store.ErrNotFound
		},
		Save: func(_ context.Context, a store.HostAccount) error {
			if saved != nil {
				*saved = a
			}
			return nil
		},
		Connect: func(context.Context, model.Target, string) (Runner, error) {
			*dialed++
			return &fakeRunner{answers: map[string]string{}}, nil
		},
		Caps: func(context.Context, Runner) (upstream.ManageCapabilities, error) {
			return upstream.ManageCapabilities{}, nil
		},
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
}

/*
 * ⚠️ PARMAK İZİ TUTUYORSA HEDEFE HİÇ BAĞLANILMIYOR.
 *
 * Özelliğin yaşayabilmesinin şartı bu: her oturuma bir SSH yönetim
 * bağlantısı eklemek, her bağlantıya saniyeler koyar ve kullanıcı bunu
 * postern'in yavaşlığı olarak görür. Test "doğru sonuç"u değil, HİÇ
 * BAĞLANILMADIĞINI ölçüyor.
 */
func TestAMatchingFingerprintNeverTouchesTheTarget(t *testing.T) {
	want := Compute(testUser, testTarget, nil)
	dialed := 0
	d := baseDeps(&dialed, nil)
	d.Row = func(context.Context, string, string) (store.HostAccount, error) {
		return store.HostAccount{
			TargetName: "db01", Username: "ayse", OSUser: "ayse",
			Origin: store.OriginCreated, State: store.HostAccountActive,
			AppliedFP: want.Fingerprint,
		}, nil
	}

	out := Ensure(t.Context(), d, testUser, testTarget)
	if dialed != 0 {
		t.Errorf("hedefe %d kez bağlanıldı; parmak izi tutarken sıfır olmalı", dialed)
	}
	if !out.Skipped || out.Reason != "" {
		t.Errorf("sonuç: %+v", out)
	}
}

/*
 * ⚠️ KİLİTLİ SATIR HIZLI ŞERİTTEN GEÇMİYOR. Kilidi açmak hedefte yazma
 * gerektiriyor; izler eşit diye atlamak, gruba geri alınan bir kişiyi
 * makinede kilitli bırakırdı — ve postern ona "erişimin var" derdi.
 */
func TestALockedRowIsNotSkipped(t *testing.T) {
	want := Compute(testUser, testTarget, nil)
	dialed := 0
	d := baseDeps(&dialed, nil)
	d.Row = func(context.Context, string, string) (store.HostAccount, error) {
		return store.HostAccount{
			TargetName: "db01", Username: "ayse", OSUser: "ayse",
			Origin: store.OriginCreated, State: store.HostAccountLocked,
			AppliedFP: want.Fingerprint,
		}, nil
	}

	Ensure(t.Context(), d, testUser, testTarget)
	if dialed != 1 {
		t.Errorf("kilitli satır atlandı: %d bağlantı", dialed)
	}
}

/*
 * ⚠️ HAZIRLAMA OTURUMU REDDETMİYOR (K6). postern bugünkünden daha sıkı
 * bir kapı olmamalı: yönetim hesabı kurulmamış bir makineye, hesabı
 * Ansible'dan zaten olan kişi bugün girebiliyor. Hazırlamayı ön koşul
 * yapmak, postern'i tek hata noktasına çevirirdi.
 */
func TestAFailureToProvisionDoesNotRefuseTheSession(t *testing.T) {
	dialed := 0
	var saved store.HostAccount
	d := baseDeps(&dialed, &saved)
	d.Connect = func(context.Context, model.Target, string) (Runner, error) {
		return nil, errors.New("dial tcp 10.0.0.1:22: connect: no route to host")
	}

	out := Ensure(t.Context(), d, testUser, testTarget)
	if out.Reason == "" {
		t.Error("sebep boş — dial düşerse operatör iki ayrı yerde arar")
	}
	if !strings.Contains(out.Reason, "no route to host") {
		t.Errorf("sebep sunucunun söylediğini taşımıyor: %q", out.Reason)
	}
	// Ve sebep KAYDEDİLİYOR, geri çekilme zamanıyla: bozuk bir hedef her
	// bağlantıda yeniden dövülmemeli.
	if saved.LastError == "" || saved.NextAttemptAt.IsZero() {
		t.Errorf("başarısızlık satıra yazılmadı: %+v", saved)
	}
	if saved.Attempts != 1 {
		t.Errorf("deneme sayısı: %d", saved.Attempts)
	}
}

/*
 * ⚠️ VAR OLAN HESAP DEVRALINIYOR, YENİDEN AÇILMIYOR (K7). Bu, var olan
 * bir Ansible filosunun altına kayabilmemizin tek yolu; ve kaynağın
 * kaydedilmesi, silme diyaloğunun "bu hesabı biz açmadık" diyebilmesinin
 * tek yolu.
 */
func TestAnExistingAccountIsAdoptedNotCreated(t *testing.T) {
	dialed := 0
	var saved store.HostAccount
	d := baseDeps(&dialed, &saved)
	d.Connect = func(context.Context, model.Target, string) (Runner, error) {
		dialed++
		return &fakeRunner{answers: map[string]string{
			// Hesap ve grup HEDEFTE ZATEN VAR.
			"id -Gn ayse":              "ayse postern-dba",
			"getent group postern-dba": "postern-dba:x:5001:ayse",
			"getent passwd ayse":       "ayse:x:1001:1001::/home/ayse:/bin/bash",
		}}, nil
	}

	Ensure(t.Context(), d, testUser, testTarget)
	if saved.Origin != store.OriginAdopted {
		t.Errorf("kaynak = %q, devralma bekleniyordu", saved.Origin)
	}
}

/* Hesap yoksa postern açıyor ve bunu kaydediyor. */
func TestAMissingAccountIsRecordedAsCreated(t *testing.T) {
	dialed := 0
	var saved store.HostAccount
	d := baseDeps(&dialed, &saved)

	Ensure(t.Context(), d, testUser, testTarget)
	if saved.Origin != store.OriginCreated {
		t.Errorf("kaynak = %q", saved.Origin)
	}
}
