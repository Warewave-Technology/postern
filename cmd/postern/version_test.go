package main

import (
	"bytes"
	"strings"
	"testing"
)

// runBare, veritabanı istemeyen komutlar için: testEnv.run her çağrıya
// --config ekliyor ve `version` onu kabul etmiyor.
func runBare(t *testing.T, args ...string) string {
	t.Helper()
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out.String()
}

/*
 * ⚠️ İKİ SORU, İKİ ÇIKTI.
 *
 * `--version` betiklerin ayrıştırdığı tek satır; `postern version`
 * insanın "yamalı mıyım" diye sorduğunda ihtiyaç duyduğu commit ve
 * kirlilik bilgisi. Birincisini ikincisiyle doldurmak, sürümü
 * ayrıştıran her betiği kırardı.
 */
func TestVersionFlagIsOneLine(t *testing.T) {
	out := runBare(t, "--version")
	if n := strings.Count(strings.TrimSpace(out), "\n"); n != 0 {
		t.Errorf("--version %d satır fazla bastı:\n%s", n, out)
	}
	if strings.Contains(out, "platform") {
		t.Errorf("--version ayrıntıya kaçtı:\n%s", out)
	}
}

// `postern version` ayrıntı basmalı: Go sürümü ve platform, bir hata
// raporunda ilk sorulan iki şey.
func TestVersionCommandShowsTheBuild(t *testing.T) {
	out := runBare(t, "version")
	for _, want := range []string{"postern", "go", "platform"} {
		if !strings.Contains(out, want) {
			t.Errorf("çıktıda %q yok:\n%s", want, out)
		}
	}
}
