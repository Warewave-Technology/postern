package provision

import (
	"strings"
	"testing"
)

// userAddCommand, plandaki hesap açma adımının komutunu döner.
func userAddCommand(t *testing.T, steps []Step) string {
	t.Helper()
	for _, s := range steps {
		if s.Kind == StepUserAdd {
			return s.Command
		}
	}
	t.Fatalf("planda hesap açma adımı yok: %v", kinds(steps))

	return ""
}

// Numara boşsa hesap onunla açılıyor — filo boyunca aynı numara.
func TestAFreeNumberIsGivenToTheNewAccount(t *testing.T) {
	o := empty()
	steps, err := Plan(able(), Desired{Users: []User{{Name: "ayse", UID: 60001}}}, o)
	if err != nil {
		t.Fatal(err)
	}
	if got := userAddCommand(t, steps); !strings.Contains(got, " -u 60001 ") {
		t.Fatalf("komutta numara yok: %q", got)
	}
}

/*
 * ⚠️ DOLU BİR NUMARA ZORLANMIYOR.
 *
 * `useradd -u` dolu bir numarayı kabul ettiğinde (--non-unique ile) ya da
 * hedefin bir varyantı buna izin verdiğinde, o numaraya ait bütün
 * dosyaların sahipliği yeni hesaba geçer: eski sahibin evi, log'ları,
 * anahtarları. Numaranın filo boyunca aynı olması bu riske değmiyor —
 * hesap hedefin kendi numarasıyla açılıyor.
 */
func TestATakenNumberIsNotForcedOntoTheNewAccount(t *testing.T) {
	o := empty()
	o.UIDOwner = map[int]string{60001: "backup"}

	steps, err := Plan(able(), Desired{Users: []User{{Name: "ayse", UID: 60001}}}, o)
	if err != nil {
		t.Fatal(err)
	}
	got := userAddCommand(t, steps)
	if strings.Contains(got, "-u ") {
		t.Fatalf("dolu numara zorlandı: %q", got)
	}
	if !strings.HasSuffix(got, " ayse") {
		t.Fatalf("hesap yine de açılmalıydı: %q", got)
	}
}

// Numara istenmemişse komut eskisi gibi kalıyor.
func TestNoNumberMeansTheTargetChooses(t *testing.T) {
	steps, err := Plan(able(), Desired{Users: []User{{Name: "ayse"}}}, empty())
	if err != nil {
		t.Fatal(err)
	}
	if got := userAddCommand(t, steps); strings.Contains(got, "-u ") {
		t.Fatalf("istenmediği hâlde numara verildi: %q", got)
	}
}

// Observe, açılacak hesabın numarasını kimin tuttuğunu okuyor.
func TestObserveReadsWhoHoldsTheWantedNumber(t *testing.T) {
	r := runnerFor(t, hostAnswers(map[string]string{
		"getent passwd 60001": "backup:x:60001:60001::/var/backups:/bin/sh\n",
	}))
	o, err := Observe(t.Context(), r, Desired{Users: []User{{Name: "ayse", UID: 60001}}})
	if err != nil {
		t.Fatal(err)
	}
	if o.UIDOwner[60001] != "backup" {
		t.Fatalf("sahip = %q, \"backup\" bekleniyordu", o.UIDOwner[60001])
	}
}

// Numara boşsa haritada hiç görünmüyor.
func TestAFreeNumberLeavesNoOwner(t *testing.T) {
	r := runnerFor(t, hostAnswers(map[string]string{}))
	o, err := Observe(t.Context(), r, Desired{Users: []User{{Name: "ayse", UID: 60001}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(o.UIDOwner) != 0 {
		t.Fatalf("boş numaraya sahip yazıldı: %v", o.UIDOwner)
	}
}

/*
 * ⚠️ CEVAPSIZLIK "BOŞ" DEĞİL, HATA.
 *
 * Ulaşılamayan bir getent boş görünseydi plan dolu bir numarayı zorlar ve
 * başkasının dosyalarını devrederdi — yani bağlantı titremesi, veri
 * sahipliğini değiştiren bir karara dönüşürdü.
 */
func TestSilenceAboutANumberIsNotTreatedAsFree(t *testing.T) {
	r := runnerFor(t, func(cmd, in string) (string, string, int, bool) {
		if cmd == "getent passwd 60001" {
			return answerSilence(cmd, in)
		}

		return "", cmd + ": not found\n", 127, true
	})
	if _, err := Observe(t.Context(), r, Desired{Users: []User{{Name: "ayse", UID: 60001}}}); err == nil {
		t.Fatal("cevapsız getent hata vermeliydi")
	}
}

/*
 * ⚠️ OKUNABİLİR ÇIKTI, BAŞARILI OKUMA DEĞİL.
 *
 * Ölçüldü: kanal çıkış kodu göndermeden kapanırken stdout'a düşen satır
 * mükemmel ayrıştırılıyor. Yalnızca çıktıya bakan bir kod bunu "numarayı
 * backup tutuyor" diye okur — oysa hiçbir şey ölçülmedi. Yanlış yöne
 * düşmesi (numarayı boş sanmak) dosya sahipliğini devrederdi; bu yöne
 * düşmesi ise deftere YANLIŞ BİR SAHİP adı yazdırır ve "neden numaram
 * farklı" sorusunun cevabını bozar.
 */
func TestAParsableLineFromAFailedReadIsStillAFailure(t *testing.T) {
	r := runnerFor(t, func(cmd, _ string) (string, string, int, bool) {
		if cmd == "getent passwd 60001" {
			// Satır tam, ama çıkış kodu hiç gelmiyor.
			return "backup:x:60001:60001::/var/backups:/bin/sh\n", "", 0, false
		}

		return "", cmd + ": not found\n", 127, true
	})
	o, err := Observe(t.Context(), r, Desired{Users: []User{{Name: "ayse", UID: 60001}}})
	if err == nil {
		t.Fatalf("ölçülmemiş okuma kabul edildi: %v", o.UIDOwner)
	}
}

// Var olan bir hesabın numarası hiç sorulmuyor — sıcak yolda bedava komut yok.
func TestAnExistingAccountsNumberIsNotQueried(t *testing.T) {
	asked := false
	r := runnerFor(t, func(cmd, _ string) (string, string, int, bool) {
		switch cmd {
		case "id -Gn ayse":
			return "ayse\n", "", 0, true
		case "getent passwd 60001":
			asked = true

			return "", "", 0, true
		}

		return "", cmd + ": not found\n", 127, true
	})
	if _, err := Observe(t.Context(), r, Desired{Users: []User{{Name: "ayse", UID: 60001}}}); err != nil {
		t.Fatal(err)
	}
	if asked {
		t.Fatal("var olan hesap için numara sorgulandı")
	}
}
