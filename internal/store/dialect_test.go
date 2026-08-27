package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/warewave/postern/internal/model"
)

// newPostgresLikeStore, göçleri COLLATE NOCASE'i SÖKEREK uygular.
//
// Amaç: PostgreSQL'de kuracağımız şemanın aynısını SQLite üzerinde kurmak.
// NOCASE gidince harf duyarsızlığı ARTIK SADECE sorgulardaki lower()'a
// kalıyor — yani bu store üzerinde geçen bir test, sorgunun gerçekten
// lehçe-nötr olduğunu ispatlar. Normal newTestStore ile aynı test,
// lower() hiç yazılmasa da geçerdi.
func newPostgresLikeStore(t *testing.T) *Store {
	t.Helper()

	s := newEmptyStore(t)
	ctx := context.Background()

	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}

	for _, m := range migs {
		// Yorumlar da atılıyor: SQLite CREATE TABLE metnini yorumlarıyla
		// birlikte saklar ve şemadaki açıklamalarda "NOCASE" kelimesi
		// geçiyor — aşağıdaki kontrol yanlış alarm vermesin.
		stripped := strings.ReplaceAll(stripSQLComments(m.up), "COLLATE NOCASE", "")
		if _, err := s.db.ExecContext(ctx, stripped); err != nil {
			t.Fatalf("NOCASE'siz göç %s: %v", m.name, err)
		}
	}

	// Sökme gerçekten oldu mu? Bu kontrol olmazsa, göç dosyalarındaki
	// yazım değişince test sessizce NOCASE'li şemayı sınamaya döner.
	var ddl string
	if err := s.db.QueryRowContext(ctx,
		`SELECT sql FROM sqlite_master WHERE type='table' AND name='targets';`).Scan(&ddl); err != nil {
		t.Fatalf("şema okunamadı: %v", err)
	}
	if strings.Contains(strings.ToUpper(ddl), "NOCASE") {
		t.Fatalf("NOCASE sökülemedi, test bir şey ispat etmiyor:\n%s", ddl)
	}

	return s
}

// stripSQLComments, satır sonu yorumlarını (--) atar.
func stripSQLComments(sqlText string) string {
	var b strings.Builder
	for _, line := range strings.Split(sqlText, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// TestCaseInsensitiveWithoutNOCASE, harf duyarsız sayılan her yolu
// NOCASE'siz şemada koşturur.
func TestCaseInsensitiveWithoutNOCASE(t *testing.T) {
	s := newPostgresLikeStore(t)
	ctx := context.Background()

	if _, err := s.CreateTarget(ctx, model.Target{
		Name: "Web01", Host: "10.0.0.1", Port: 22, HostKey: "ssh-ed25519 AAAA",
	}); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	_, err := s.CreateRole(ctx, "ops")
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if _, err := s.CreateUser(ctx, "ali.veli", "ali@example.com", "ali.veli"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	t.Run("Target farklı yazımla bulunur", func(t *testing.T) {
		for _, name := range []string{"web01", "WEB01", "wEb01"} {
			got, err := s.Target(ctx, name)
			if err != nil {
				t.Errorf("Target(%q): %v", name, err)
				continue
			}
			if got.Name != "Web01" {
				t.Errorf("Target(%q) = %q, istenen %q", name, got.Name, "Web01")
			}
		}
	})

	t.Run("Target adı harf duyarsız benzersiz", func(t *testing.T) {
		_, err := s.CreateTarget(ctx, model.Target{
			Name: "WEB01", Host: "10.0.0.2", Port: 22, HostKey: "ssh-ed25519 BBBB",
		})
		if !errors.Is(err, ErrConflict) {
			t.Errorf("CreateTarget(WEB01) = %v, ErrConflict bekleniyordu", err)
		}
	})

	t.Run("GrantTarget farklı yazımla", func(t *testing.T) {
		if err := s.GrantTarget(ctx, "ops", "WEB01"); err != nil {
			t.Errorf("GrantTarget: %v", err)
		}
	})

	t.Run("StartSession farklı yazımla", func(t *testing.T) {
		err := s.StartSession(ctx, SessionStart{
			ID: "sess-1", Username: "ali.veli", TargetName: "wEB01",
			OSUser: "ali.veli", SrcIP: "10.0.0.5", StartedAt: time.Now(),
			RecordingPath: "/tmp/sess-1.cast",
		})
		if err != nil {
			t.Errorf("StartSession: %v", err)
		}
	})

	t.Run("grup eşlemesi farklı yazımla çözülür", func(t *testing.T) {
		if err := s.AddGroupMapping(ctx, "Domain Admins", "ops", "test"); err != nil {
			t.Fatalf("AddGroupMapping: %v", err)
		}

		roles, unmapped, err := s.RolesForGroups(ctx, []string{"DOMAIN ADMINS"})
		if err != nil {
			t.Fatalf("RolesForGroups: %v", err)
		}
		if len(roles) != 1 || roles[0] != "ops" {
			t.Errorf("roller = %v, [ops] bekleniyordu (eşleme harf duyarlı kalmış)", roles)
		}
		if len(unmapped) != 0 {
			t.Errorf("eşleşmeyen = %v, boş bekleniyordu", unmapped)
		}
	})

	t.Run("eşleme farklı yazımla iki kez kurulamaz", func(t *testing.T) {
		err := s.AddGroupMapping(ctx, "domain admins", "ops", "test")
		if !errors.Is(err, ErrConflict) {
			t.Errorf("AddGroupMapping(tekrar) = %v, ErrConflict bekleniyordu", err)
		}
	})

	t.Run("eşleme farklı yazımla silinir", func(t *testing.T) {
		if err := s.RemoveGroupMapping(ctx, "dOmAiN aDmInS", "ops"); err != nil {
			t.Errorf("RemoveGroupMapping: %v", err)
		}
	})

	t.Run("eşleşmeyen gruplar harf duyarsız birleşir", func(t *testing.T) {
		if err := s.RecordUnmappedGroups(ctx, []string{"Developers", "DEVELOPERS", "developers"}); err != nil {
			t.Fatalf("RecordUnmappedGroups: %v", err)
		}

		groups, err := s.UnmappedGroups(ctx)
		if err != nil {
			t.Fatalf("UnmappedGroups: %v", err)
		}
		if len(groups) != 1 {
			t.Fatalf("%d satır, 1 bekleniyordu: %+v", len(groups), groups)
		}
		if groups[0].SeenCount != 3 {
			t.Errorf("SeenCount = %d, 3 bekleniyordu", groups[0].SeenCount)
		}
		if groups[0].Name != "Developers" {
			t.Errorf("Name = %q, ilk görülen yazım (%q) korunmalıydı", groups[0].Name, "Developers")
		}
	})

	t.Run("DeleteTarget farklı yazımla", func(t *testing.T) {
		if _, err := s.CreateTarget(ctx, model.Target{
			Name: "Db01", Host: "10.0.0.3", Port: 22, HostKey: "ssh-ed25519 CCCC",
		}); err != nil {
			t.Fatalf("CreateTarget: %v", err)
		}
		if err := s.DeleteTarget(ctx, "DB01"); err != nil {
			t.Errorf("DeleteTarget: %v", err)
		}
	})

	t.Run("Targets harf duyarsız sıralı", func(t *testing.T) {
		for _, n := range []string{"alpha", "Beta", "gamma"} {
			if _, err := s.CreateTarget(ctx, model.Target{
				Name: n, Host: "10.0.0.9", Port: 22, HostKey: "ssh-ed25519 DDDD",
			}); err != nil {
				t.Fatalf("CreateTarget(%s): %v", n, err)
			}
		}
		targets, err := s.Targets(ctx)
		if err != nil {
			t.Fatalf("Targets: %v", err)
		}
		var names []string
		for _, tg := range targets {
			names = append(names, tg.Name)
		}
		// Harf duyarlı sıralamada büyük harfler öne düşer: [Beta Web01 alpha gamma]
		want := []string{"alpha", "Beta", "gamma", "Web01"}
		if len(names) != len(want) {
			t.Fatalf("adlar = %v, %v bekleniyordu", names, want)
		}
		for i := range want {
			if names[i] != want[i] {
				t.Errorf("sıra = %v, %v bekleniyordu (ORDER BY harf duyarlı kalmış)", names, want)
			}
		}
	})
}

// TestCIColumnsMatchesSchema, ciColumns listesinin şemayla aynı hizada
// olduğunu doğrular: NOCASE işaretli her sütun listede olmalı.
//
// Bu eşleşme kayarsa hata SQLite'ta görünmez — PostgreSQL'de sessizce
// harf duyarlı olur. Bu yüzden şema tek doğruluk kaynağı sayılıyor.
func TestCIColumnsMatchesSchema(t *testing.T) {
	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}

	found := map[string]bool{}
	var table string
	for _, m := range migs {
		for _, line := range strings.Split(stripSQLComments(m.up), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToUpper(trimmed), "CREATE TABLE") {
				table = strings.TrimSuffix(strings.Fields(trimmed)[2], "(")
			}
			if strings.Contains(trimmed, "COLLATE NOCASE") {
				column := strings.Fields(trimmed)[0]
				found[table+"."+column] = true
			}
		}
	}

	if len(found) == 0 {
		t.Fatal("şemada COLLATE NOCASE bulunamadı — tarayıcı bozulmuş olabilir")
	}
	for col := range found {
		if !ciColumns[col] {
			t.Errorf("%s şemada NOCASE ama ciColumns'ta yok: PostgreSQL'de harf duyarlı olur", col)
		}
	}
	for col := range ciColumns {
		if !found[col] {
			t.Errorf("%s ciColumns'ta ama şemada NOCASE değil: liste eskimiş", col)
		}
	}
}
