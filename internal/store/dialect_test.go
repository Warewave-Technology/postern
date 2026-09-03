package store

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
)

// TestCaseInsensitive, harf duyarsız sayılan her yolu koşturur.
//
// SQLite döneminde bu testin ayrı bir kurulumu vardı: şema COLLATE
// NOCASE taşıdığı için harf duyarsızlık sorgudan bağımsız çalışıyordu ve
// eksik bir lower() görünmüyordu. PostgreSQL'de böyle bir örtü yok —
// duyarsızlık YALNIZCA sorgulardaki lower() ve 009'daki ifade
// indekslerinden geliyor, dolayısıyla düz kurulum yeterli kanıt.
func TestCaseInsensitive(t *testing.T) {
	s := newTestStore(t)
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
// olduğunu doğrular.
//
// Doğruluk kaynağı GÖÇ METNİ DEĞİL, canlı katalog: veritabanına "hangi
// sütunlarda lower() ifade indeksi var" diye soruyor. Metin taramak
// yazım değişikliğinde sessizce kör kalırdı; katalog ise indeksin
// gerçekten kurulduğunu da ispatlıyor.
//
// Eşleşme kayarsa hata çalışırken görünmez — sorgu yine çalışır, yalnız
// harf duyarlı olur. Bu yüzden ayrı bir test olarak duruyor.
func TestCIColumnsMatchesSchema(t *testing.T) {
	s := newTestStore(t)

	rows, err := s.db.QueryContext(context.Background(), `
		SELECT tablename, indexdef
		FROM pg_indexes
		WHERE schemaname = current_schema()
		  AND indexdef LIKE '%lower(%';`)
	if err != nil {
		t.Fatalf("pg_indexes: %v", err)
	}
	defer rows.Close()

	lowerCol := regexp.MustCompile(`lower\(\(?([a-z_]+)`)

	found := map[string]bool{}
	for rows.Next() {
		var table, def string
		if err := rows.Scan(&table, &def); err != nil {
			t.Fatalf("scan: %v", err)
		}
		for _, m := range lowerCol.FindAllStringSubmatch(def, -1) {
			found[table+"."+m[1]] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	if len(found) == 0 {
		t.Fatal("şemada lower() ifade indeksi bulunamadı — 009 uygulanmamış olabilir")
	}

	for col := range found {
		if !ciColumns[col] {
			t.Errorf("%s için lower() indeksi var ama ciColumns'ta yok: "+
				"sorgular harf duyarlı gidiyor demektir", col)
		}
	}
	for col := range ciColumns {
		if !found[col] {
			t.Errorf("%s ciColumns'ta ama lower() indeksi yok: "+
				"sorgular indeks kullanamaz ve kısıt uygulanmaz", col)
		}
	}
}

// dsn, sslmode belirtilmemişse doğrulanmış TLS'e zorlar.
//
// Neden test edilmeye değer: libpq'nun varsayılanı "prefer"dır ve TLS
// kurulamazsa düz metne SESSİZCE düşer. Bu, bir bastion'ın kimlik ve
// denetim trafiği için düşürme saldırısının ta kendisidir. Varsayılanı
// değiştiren satır tek satır; testi olmazsa bir "sadeleştirme" sırasında
// sessizce geri gelebilir.
func TestDSNDefaultsToVerifyFull(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  string
		exact bool
	}{
		{
			name: "sslmode yoksa verify-full eklenir",
			in:   "postgres://u:p@db.local:5432/postern",
			want: "sslmode=verify-full",
		},
		{
			name: "acikca yazilan sslmode korunur",
			in:   "postgres://u:p@db.local:5432/postern?sslmode=disable",
			want: "sslmode=disable",
		},
		{
			// Başka parametreler varken de eklenmeli — ayrıştırma
			// "? var mı" diye bakan bir string işi değil.
			name: "diger parametrelerle birlikte",
			in:   "postgres://u:p@db.local:5432/postern?application_name=postern",
			want: "sslmode=verify-full",
		},
		{
			// Anahtar=değer biçimi URL değil; elle kurcalamak yerine
			// olduğu gibi geçiyoruz — ama sslmode YAZILMIŞ olmalı
			// (bkz. TestKeywordDSNMustStateSSLMode).
			name:  "anahtar=deger bicimi oldugu gibi gecer",
			in:    "host=db.local user=postern dbname=postern sslmode=verify-full",
			want:  "host=db.local user=postern dbname=postern sslmode=verify-full",
			exact: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := dsn(tc.in)
			if err != nil {
				t.Fatalf("dsn(%q): %v", tc.in, err)
			}
			if tc.exact {
				if got != tc.want {
					t.Errorf("dsn(%q) = %q, beklenen %q", tc.in, got, tc.want)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("dsn(%q) = %q, %q içermeliydi", tc.in, got, tc.want)
			}
		})
	}
}

// Boş bağlantı dizesi hata: sürücüye boş dize vermek libpq ortam
// değişkenlerine (PGHOST, PGUSER...) düşmek demektir ve "hangi
// veritabanına bağlandım" sorusunu ortama havale eder. Bir bastion için
// bu belirsizlik kabul edilemez.
func TestDSNRejectsEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", "\t\n"} {
		if _, err := dsn(in); err == nil {
			t.Errorf("dsn(%q) hata vermedi", in)
		}
	}
}

// Bağlantı dizesi hataları PAROLAYI TAŞIMAMALI.
//
// Ölçülmüş bir sızıntının regresyon testi: url.Parse'ın döndürdüğü
// *url.Error, ayrıştıramadığı dizenin TAMAMINI taşıyor ve bu hata
// açılışta stderr'e düşüyor — oradan journald'a, log toplayıcıya, CI
// çıktısına ve destek paketine. Veritabanı parolası postern'in
// yetkilendirme ve denetim verisinin tamamına doğrudan erişim demek:
// onunla users.is_admin yazılabilir, yani panelin CLI-only admin kuralı
// tamamen atlanır.
func TestDSNErrorsDoNotLeakThePassword(t *testing.T) {
	const secret = "s3cret-p4ss"

	bad := map[string]string{
		"bozuk kacis sorguda": "postgres://postern:" + secret + "@db.local:5432/postern?x=%zz",
		"kontrol karakteri":   "postgres://postern:" + secret + "@host\x7f/db",
		"noktali virgul":      "postgres://postern:" + secret + "@db.local/postern?a=1;b=2",
		"bozuk yuzde":         "postgres://postern:" + secret + "@db.local/postern?%",
	}

	for name, conn := range bad {
		t.Run(name, func(t *testing.T) {
			out, err := dsn(conn)
			if err == nil {
				// Reddetmemesi de kabul — ama o zaman ÇIKTI sızdırmamalı.
				if strings.Contains(out, secret) {
					t.Errorf("çıktı parolayı taşıyor: %q", out)
				}
				return
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("PAROLA HATA METNİNDE SIZDI: %v", err)
			}
			// Mesaj yine de işe yaramalı: sebebini söylemeyen bir hata,
			// operatörü yapılandırmayı tahmin etmeye zorlar.
			if len(err.Error()) < 20 {
				t.Errorf("hata mesajı teşhis için fazla kısa: %q", err)
			}
		})
	}
}

// ⚠️ İKİ YAPILANDIRMA BİÇİMİ AYNI GÜVENLİK SEVİYESİNİ VERMELİ.
//
// Kapatılan boşluk: anahtar=değer biçimi ("host=... user=...") olduğu
// gibi geçiriliyordu, yani sslmode yazılmamışsa libpq varsayılanı
// "prefer" uygulanıyordu — TLS kurulamazsa bağlantı SESSİZCE düz metne
// düşer. dsn'in var olma sebebi tam olarak bunu önlemekti ve bu biçimde
// hiç uygulanmıyordu.
func TestKeywordDSNMustStateSSLMode(t *testing.T) {
	refused := []string{
		"host=db.local user=postern dbname=postern",
		"host=db.local user=postern password=xsslmode=hile", // sözcük sınırı
		"  host=db.local  ",
	}
	for _, conn := range refused {
		if out, err := dsn(conn); err == nil {
			t.Errorf("sslmode'suz anahtar=değer kabul edildi: %q -> %q", conn, out)
		}
	}

	accepted := []string{
		"host=db.local user=postern sslmode=verify-full",
		"sslmode=require host=db.local",
		"host=db.local sslmode = disable", // boşluklu yazım da sayılır
	}
	for _, conn := range accepted {
		out, err := dsn(conn)
		if err != nil {
			t.Errorf("sslmode'lu anahtar=değer reddedildi: %q -> %v", conn, err)
			continue
		}
		if out != conn {
			t.Errorf("anahtar=değer biçimi değiştirilmiş: %q -> %q", conn, out)
		}
	}
}
