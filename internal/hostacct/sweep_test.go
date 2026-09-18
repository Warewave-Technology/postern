package hostacct

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

var sweepUsers = map[string]model.User{
	"ayse": {Name: "ayse", OSUser: "acctayse", Groups: []model.Group{
		{Name: "dba", Targets: []string{"db01"}},
	}},
	"veli": {Name: "veli", OSUser: "acctveli", Groups: []model.Group{
		{Name: "dba", Targets: []string{"db01"}},
	}},
}

// sweepDeps, tek hedefli bir süpürme kurar. answers hedefin cevapları.
func sweepDeps(dialed *int, answers map[string]string, saved *[]store.HostAccount) SweepDeps {
	return SweepDeps{
		Rows: func(context.Context) ([]store.HostAccount, error) {
			return []store.HostAccount{
				{TargetName: "db01", Username: "ayse", OSUser: "acctayse",
					Origin: store.OriginCreated, State: store.HostAccountActive},
				{TargetName: "db01", Username: "veli", OSUser: "acctveli",
					Origin: store.OriginCreated, State: store.HostAccountActive},
			}, nil
		},
		User: func(_ context.Context, name string) (model.User, error) {
			return sweepUsers[name], nil
		},
		Target: func(_ context.Context, name string) (model.Target, error) {
			return model.Target{Name: name, Host: "10.0.0.1", Port: 22}, nil
		},
		Rules: func(context.Context) (map[string]store.GroupSudo, error) { return nil, nil },
		Save: func(_ context.Context, a store.HostAccount) error {
			if saved != nil {
				*saved = append(*saved, a)
			}

			return nil
		},
		Connect: func(context.Context, model.Target, string) (Runner, error) {
			*dialed++

			return &fakeRunner{answers: answers}, nil
		},
		Caps: func(context.Context, Runner) (upstream.ManageCapabilities, error) {
			return upstream.ManageCapabilities{DelMember: "/usr/bin/gpasswd"}, nil
		},
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
}

/*
 * ⚠️ HEDEF BAŞINA TEK BAĞLANTI.
 *
 * Kişi başına bağlanmak, elli kişilik bir makinede her turda elli SSH
 * demek olurdu — ve özellik ilk büyük filoda kapatılırdı. Test "doğru
 * sonuç"u değil, KAÇ KEZ BAĞLANILDIĞINI ölçüyor.
 */
func TestASweepConnectsOncePerTargetNotPerPerson(t *testing.T) {
	dialed := 0
	var saved []store.HostAccount
	s := NewSweeper(sweepDeps(&dialed, map[string]string{}, &saved), time.Hour)

	s.Tick(t.Context())

	if dialed != 1 {
		t.Errorf("iki kişi için %d kez bağlanıldı; bir kez olmalı", dialed)
	}
	if len(saved) != 2 {
		t.Errorf("%d satır yazıldı, iki bekleniyordu", len(saved))
	}
}

/*
 * ⚠️ FAZLA ÜYE ÇIKARILIYOR VE SEBEBİ DEFTERE YAZILIYOR.
 *
 * Elle eklenen hesap, postern'in o gruba yazdığı sudo kuralını alıyor.
 * Sessizce çıkarmak da yetmez: bir kişinin yetkisini geri almak, defterde
 * bir satır bırakmadan yapılabilecek bir şey değil.
 */
func TestAnExtraMemberIsTakenOutAndWrittenToTheLedger(t *testing.T) {
	dialed := 0
	answers := map[string]string{
		"getent group postern-dba":     "postern-dba:x:5000:acctayse,acctveli,sizan\n",
		"getent group postern-managed": "postern-managed:x:5001:acctayse,acctveli\n",
	}
	var details []string
	d := sweepDeps(&dialed, answers, nil)
	d.Audit = func(_ context.Context, _, detail string) error {
		details = append(details, detail)

		return nil
	}
	NewSweeper(d, time.Hour).Tick(t.Context())

	found := ""
	for _, s := range details {
		if strings.Contains(s, "sizan") {
			found = s
		}
	}
	if found == "" {
		t.Fatalf("çıkarma deftere yazılmadı: %v", details)
	}
	if !strings.Contains(found, "postern-dba") {
		t.Errorf("satır grubu söylemiyor: %q", found)
	}
	// Meşru üyeler satırda geçmemeli: yalnızca fazlası çıkarılıyor.
	for _, legit := range []string{"acctayse", "acctveli"} {
		if strings.Contains(found, legit) {
			t.Errorf("meşru üye çıkarma satırında: %q", found)
		}
	}
}

/*
 * ⚠️ TAVAN AŞILINCA HİÇBİRİ ÇIKARILMIYOR.
 *
 * postern'in kayıtları bir an için eksik okunursa "beklenen üye yok"
 * çıkar ve zorlama bütün makineyi kendi grubundan atardı. Yarısını
 * uygulamak, hem hasarı verip hem sebebi gizlemek olurdu.
 */
func TestTheCapStopsEveryRemovalNotJustTheOnesPastIt(t *testing.T) {
	dialed := 0
	answers := map[string]string{
		"getent group postern-dba": "postern-dba:x:5000:acctayse,acctveli," +
			"a,b,c,d,e,f,g,h\n",
	}
	seen := &fakeRunner{answers: answers}
	d := sweepDeps(&dialed, answers, nil)
	d.MaxRemovals = 3
	d.Connect = func(context.Context, model.Target, string) (Runner, error) {
		dialed++

		return seen, nil
	}
	var details []string
	d.Audit = func(_ context.Context, _, detail string) error {
		details = append(details, detail)

		return nil
	}
	NewSweeper(d, time.Hour).Tick(t.Context())

	for _, cmd := range seen.seen {
		if strings.Contains(cmd, "gpasswd") {
			t.Fatalf("tavan aşılmışken çıkarma çalıştı: %q", cmd)
		}
	}
	said := false
	for _, s := range details {
		if strings.Contains(s, "nothing was changed") {
			said = true
		}
	}
	if !said {
		t.Errorf("tavan sebebi deftere yazılmadı: %v", details)
	}
}

/*
 * ⚠️ ÖNDEN AÇMA KAPALIYKEN KODU HİÇ KOŞMUYOR. Manifestonun cümlesi
 * varsayılanda kodun ŞEKLİNDE görünsün diye Grants bağlanmıyor; bir
 * bayrağın içinde "hayır" diye durmuyor.
 */
func TestPrecreationDoesNothingWhenItIsNotWiredIn(t *testing.T) {
	dialed := 0
	d := sweepDeps(&dialed, map[string]string{}, nil)
	d.Rows = func(context.Context) ([]store.HostAccount, error) { return nil, nil }
	d.Grants = nil

	NewSweeper(d, time.Hour).Tick(t.Context())

	if dialed != 0 {
		t.Errorf("iş yokken %d kez bağlanıldı", dialed)
	}
}

// Önden açma bağlıysa satırı olmayan çift de süpürmeye giriyor.
func TestPrecreationBringsInPairsWithNoRow(t *testing.T) {
	dialed := 0
	var saved []store.HostAccount
	d := sweepDeps(&dialed, map[string]string{}, &saved)
	d.Rows = func(context.Context) ([]store.HostAccount, error) { return nil, nil }
	d.Grants = func(context.Context, time.Time) ([]store.Grant, error) {
		return []store.Grant{{Username: "ayse", TargetName: "db01"}}, nil
	}

	NewSweeper(d, time.Hour).Tick(t.Context())

	if dialed != 1 {
		t.Fatalf("önden açma için %d kez bağlanıldı", dialed)
	}
	if len(saved) != 1 || saved[0].Username != "ayse" {
		t.Fatalf("satır yazılmadı: %+v", saved)
	}
	if saved[0].Origin != store.OriginCreated {
		t.Errorf("kaynak = %q", saved[0].Origin)
	}
}
