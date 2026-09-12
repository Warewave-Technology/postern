package sudoers

import (
	"strings"
	"testing"
)

// ok, doğrulamanın temiz geçtiğini söyler.
func ok(t *testing.T, r Rule) {
	t.Helper()
	if f := Validate(r); len(f) != 0 {
		t.Fatalf("temiz kural reddedildi: %s", Describe(f))
	}
}

// refused, kuralın onayla BİLE geçmediğini söyler.
func refused(t *testing.T, r Rule, want string) {
	t.Helper()
	f := Validate(r)
	if len(f) == 0 {
		t.Fatalf("REDDEDİLMEDİ: %v", r.Commands)
	}
	if !strings.Contains(Describe(f), want) {
		t.Errorf("sebep %q geçmiyor: %s", want, Describe(f))
	}
	r.Acknowledged = true
	if !Refuses(Validate(r), true) {
		t.Errorf("ONAYLA GEÇTİ: yapısal sorun onaylanabilir olmamalı — %v", r.Commands)
	}
}

/*
 * ⚠️ BU DOSYANIN TAMAMI TEK BİR ARIZANIN ETRAFINDA: OPERATÖR "DAR
 * YETKİ VERDİM" SANARKEN ROOT VERİYOR.
 *
 * Kural sözdizimi olarak kusursuz, visudo'dan geçiyor, panelde
 * masum görünüyor — ve kabuğa çıkıyor. Görülebilir tek yer burası.
 */
func TestNarrowRulePasses(t *testing.T) {
	ok(t, Rule{Commands: []Command{
		{Path: "/usr/bin/nginx", Args: []string{"-t"}},
		{Path: "/bin/systemctl-reload-nginx"},
	}})
}

func TestALLIsRefused(t *testing.T) {
	refused(t, Rule{Commands: []Command{{Path: "ALL"}}}, "every command")
}

/*
 * ⚠️ JOKER, METNİ SINIRLIYOR, YETKİYİ DEĞİL. `/usr/bin/less
 * /var/log/*.log` kuralı "yalnızca log okusun" diye yazılıyor; less
 * zaten içinden kabuk açıyor, joker onu hiç sınırlamıyor. Ve
 * `/bin/*` doğrudan her şey demek.
 */
func TestWildcardIsRefusedEvenInArguments(t *testing.T) {
	refused(t, Rule{Commands: []Command{
		{Path: "/usr/bin/tail", Args: []string{"/var/log/*.log"}},
	}}, "wildcard")

	refused(t, Rule{Commands: []Command{{Path: "/bin/*"}}}, "wildcard")
}

/*
 * ⚠️ ÇIPLAK AD, KOMUTU PATH'E BIRAKIYOR. PATH'i etkileyebilen biri
 * hangi ikilinin koşacağını seçer; kural "systemctl" der, koşan şey
 * başka bir şey olur.
 */
func TestRelativePathIsRefused(t *testing.T) {
	refused(t, Rule{Commands: []Command{{Path: "nginx"}}}, "absolute path")
}

/*
 * ⚠️ SATIR SONU, GÖZDEN GEÇİRİLMEMİŞ İKİNCİ BİR KURAL YAZAR. Komut
 * alanına kaçan bir "\n", sudoers dosyasına kimsenin bakmadığı bir
 * satır ekler — ve o satır "ALL" olabilir.
 */
func TestLineBreakIsRefused(t *testing.T) {
	refused(t, Rule{Commands: []Command{
		{Path: "/usr/bin/id\nyigit ALL=(ALL) NOPASSWD: ALL"},
	}}, "line break")
}

// ⚠️ Olumsuzlama bir sınır değil: yasaklanan komuta başka bir yoldan
// ulaşılıyor. Yasak listesi, izin listesinin yerini tutmuyor.
func TestNegationIsRefused(t *testing.T) {
	refused(t, Rule{Commands: []Command{{Path: "!/bin/sh"}}}, "negation")
}

// ⚠️ SETENV, LD_PRELOAD ile her komutu root kabuğuna çeviriyor.
func TestSudoersTagIsRefused(t *testing.T) {
	refused(t, Rule{Commands: []Command{
		{Path: "/usr/bin/id", Args: []string{"SETENV:"}},
	}}, "tag")
}

func TestEmptyRuleIsRefused(t *testing.T) {
	refused(t, Rule{}, "allows nothing")
}

/*
 * ⚠️ KAÇIŞ İKİLİLERİ: ONAYSIZ REDDEDİLİYOR, ONAYLA GEÇİYOR.
 *
 * Yapısal sorunlardan farklılar: operatör gerçekten "bu kişi vim ile
 * root olabilir, biliyorum" diyebilir. Sessizce yazmak ile bilerek
 * yazmak arasındaki farkı kaydediyoruz.
 */
func TestEscapeBinariesNeedAnExplicitAcknowledgement(t *testing.T) {
	for _, tc := range []struct{ path, why string }{
		{"/usr/bin/vim", "shell"},
		{"/bin/less", "shell"},
		{"/usr/bin/find", "-exec"},
		{"/usr/bin/systemctl", "systemctl edit"},
		{"/usr/bin/awk", "runs commands"},
		{"/bin/tar", "checkpoint-action"},
		{"/usr/bin/docker", "host filesystem"},
	} {
		r := Rule{Commands: []Command{{Path: tc.path}}}

		f := Validate(r)
		if len(f) == 0 {
			t.Errorf("%s KAÇIŞ OLARAK GÖRÜLMEDİ — 'dar' sanılan kural root veriyor", tc.path)
			continue
		}
		if !strings.Contains(Describe(f), tc.why) {
			t.Errorf("%s için sebep %q geçmiyor: %s", tc.path, tc.why, Describe(f))
		}
		if !Refuses(f, false) {
			t.Errorf("%s onaysız geçti", tc.path)
		}
		if Refuses(f, true) {
			t.Errorf("%s onaylandığı hâlde geçmedi", tc.path)
		}
	}
}

// ⚠️ Taban ad karşılaştırılıyor: /usr/bin/vim ile /bin/vim aynı tehlike.
func TestEscapeIsFoundWhateverTheDirectory(t *testing.T) {
	for _, p := range []string{"/bin/vim", "/usr/bin/vim", "/opt/tools/bin/vim"} {
		if len(Validate(Rule{Commands: []Command{{Path: p}}})) == 0 {
			t.Errorf("%s kaçış olarak görülmedi", p)
		}
	}
}

/*
 * ⚠️ RENDER, DOĞRULAMADAN GEÇMEDEN YAZMIYOR. Ayrı bir adım olsaydı
 * çağıranın unutması mümkün olurdu ve o unutma, dosyanın hedefe
 * gitmesiyle sonuçlanırdı.
 */
func TestRenderRefusesWhatValidateRefuses(t *testing.T) {
	if _, err := Render("yigit", Rule{Commands: []Command{{Path: "ALL"}}}, ""); err == nil {
		t.Fatal("REDDEDİLEN KURAL YAZILDI")
	}
}

func TestRenderWritesAMarkedFile(t *testing.T) {
	out, err := Render("p_yigit", Rule{
		Commands: []Command{{Path: "/usr/bin/nginx", Args: []string{"-t"}}},
	}, "grant 7f3a")
	if err != nil {
		t.Fatal(err)
	}

	// ⚠️ İşaret satırı şart: postern'in yazmadığı bir dosyaya asla
	// dokunmamasının tek yolu, kendi yazdığını tanıyabilmesi.
	if !strings.HasPrefix(out, "# postern") {
		t.Errorf("işaret satırı yok:\n%s", out)
	}
	if !strings.Contains(out, "grant 7f3a") {
		t.Errorf("başlık taşınmadı:\n%s", out)
	}
	if !strings.Contains(out, "p_yigit ALL=(root) NOPASSWD: /usr/bin/nginx -t") {
		t.Errorf("kural beklenen biçimde değil:\n%s", out)
	}
}

/*
 * ⚠️ KULLANICI ADI DA SUDOERS SÖZDİZİMİ. Adında boşluk ya da virgül
 * olan bir değer, kuralı başka bir şeye çevirir.
 */
func TestRenderRefusesAUserNameThatIsSyntax(t *testing.T) {
	for _, name := range []string{"", "ALL", "a b", "a,b", "a!b"} {
		if _, err := Render(name, Rule{
			Commands: []Command{{Path: "/usr/bin/id"}},
		}, ""); err == nil {
			t.Errorf("%q kullanıcı adı kabul edildi", name)
		}
	}
}
