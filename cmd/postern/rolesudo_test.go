package main

/*
 * `postern role sudo show` — kuralı okumanın panel dışı yolu.
 *
 * ⚠️ BU KOMUT BİR SÜRÜM NOTUNUN İÇİNDE. 1.3.0'ın güvenlik satırı, panelde
 * düzenlenen bir kuralın sessizce root'a çıkmış olabileceğini söylüyor ve
 * kontrol yolu olarak bu komutu veriyor. Komut hesabı yazmıyorsa o satır
 * yalan söylüyor demektir; test tam olarak bunu bekliyor.
 */

import (
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/sudoers"
)

func TestRoleSudoShowNamesTheAccountOfEachCommand(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()

	if _, err := e.db.CreateRole(ctx, "dba"); err != nil {
		t.Fatal(err)
	}
	rule := sudoers.Rule{Commands: []sudoers.Command{
		{Path: "/usr/sbin/nginx", Args: []string{"-t"}},
		{Path: "/usr/bin/pg_ctl", Args: []string{"reload"}, RunAs: "postgres"},
	}}
	if err := e.db.SetRoleSudo(ctx, "dba", rule, "ops"); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newRoleSudoCmd(), "show", "--role", "dba")
	if err != nil {
		t.Fatalf("show: %v — %s", err, out)
	}

	/*
	 * ⚠️ HER KOMUT KENDİ HESABINI TAŞIYOR. Önceki hâl tek bir "runs as:"
	 * satırı basıp komutları altına diziyordu; kural komut başına hesap
	 * taşımaya başlayınca o satır, postgres olarak koşan bir komutu
	 * root'muş gibi okutuyordu — yani yetkinin yarısını gizliyordu.
	 */
	for _, want := range []string{
		"/usr/sbin/nginx -t  (runs as root)",
		"/usr/bin/pg_ctl reload  (runs as postgres)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("çıktıda yok: %q\n%s", want, out)
		}
	}

	// Kural başına tek bir hesap satırı ARTIK YOK: iki farklı hesabı olan
	// bir kuralda o satır yanlış bir özet.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "runs as:") {
			t.Errorf("kural başına hesap satırı duruyor: %q", line)
		}
	}

	// Dosyanın hedefteki yeri de yazılıyor: kuralın nereye indiğini
	// bilmeden "neden bu yetki var" sorusu cevaplanmıyor.
	if !strings.Contains(out, "/etc/sudoers.d/postern-dba") {
		t.Errorf("hedefteki dosya yazılmamış:\n%s", out)
	}
	_ = store.RoleSudo{}
}

/*
 * ⚠️ CLI, PANELDE YAZILMIŞ HESABI SESSİZCE ROOT'A ÇEKMİYOR.
 *
 * `set` kuralın tamamını değiştiriyor ve komut başına hesabı ifade
 * edemiyor. Bu kapı açıkken, panelde "pg_ctl reload postgres olarak"
 * yazılmış bir kuralın üstüne CLI'dan yazmak komutu root'a çıkarıyordu —
 * 1.3.0'ın güvenlik satırındaki hatanın ikinci kapısı. Artık niyet
 * isteniyor: --run-as verilmediyse komut duruyor ve neyin nereye
 * taşınacağını söylüyor.
 */
func TestWritingFromTheCLIDoesNotSilentlyMoveACommandToRoot(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if _, err := e.db.CreateRole(ctx, "dba"); err != nil {
		t.Fatal(err)
	}
	if err := e.db.SetRoleSudo(ctx, "dba", sudoers.Rule{Commands: []sudoers.Command{
		{Path: "/usr/bin/pg_ctl", Args: []string{"reload"}, RunAs: "postgres"},
	}}, "ops"); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newRoleSudoCmd(), "set", "--role", "dba",
		"--command", "/usr/sbin/nginx -t")
	if err == nil {
		t.Fatalf("sessizce yazdı: %s", out)
	}
	msg := err.Error()
	for _, want := range []string{"/usr/bin/pg_ctl reload", "postgres", "--run-as"} {
		if !strings.Contains(msg, want) {
			t.Errorf("ret sebebi %q içermiyor:\n%s", want, msg)
		}
	}

	// Kural DEĞİŞMEMİŞ olmalı: yarım uygulanan bir yazma, hem hasarı verip
	// hem sebebi gizlemek olurdu.
	still, rerr := e.db.RoleSudoRule(ctx, "dba")
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(still.Rule.Commands) != 1 || still.Rule.Commands[0].RunAs != "postgres" {
		t.Errorf("kural reddedilen istekten etkilendi: %+v", still.Rule)
	}

	// Niyet açıkça söylenirse geçiyor: acil çıkış yolu kapanmıyor.
	if _, err := e.run(t, newRoleSudoCmd(), "set", "--role", "dba",
		"--command", "/usr/sbin/nginx -t", "--run-as", "root"); err != nil {
		t.Errorf("--run-as verilmiş istek de reddedildi: %v", err)
	}
}
