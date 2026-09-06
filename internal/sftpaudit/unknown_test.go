package sftpaudit

import (
	"strings"
	"testing"
)

/*
 * ⚠️ TANIMADIĞIMIZ TÜR ÖNCEDEN ONAYLANMIŞ OLMAMALI.
 *
 * ÖLÇÜLEN AÇIK: onRequest'in son dalı, tanımadığı HER türü "salt okuma
 * üstverisi" sayıp sessizce geçiriyordu. Sürüm anlaşmasını izlemediğimiz
 * için (fxpInit'e bakılmıyor) hedef v6 konuşuyorsa SSH_FXP_LINK (21) —
 * dosyaya İKİNCİ BİR AD veren, silinen bir dosyanın içeriğini yaşatan
 * işlem — tam olarak o kovaya düşüyordu.
 *
 * Aynı gerekçe eklentiler için zaten yazılıydı (onExtended); temel tür
 * uzayında uygulanmamıştı.
 */
func TestUnknownRequestTypeIsRecorded(t *testing.T) {
	const fxpLink = 21 // v6: sabit/sembolik bağ yaratır

	s, got := collect(t)

	// v6 LINK: id, yeni-yol, mevcut-yol, symlink-mi.
	feedClient(t, s, newPkt(fxpLink).u32(9).
		str("/tmp/kopya").str("/srv/gizli.db").bytes())
	feedTarget(t, s, statusOK(9))

	if len(*got) != 1 {
		t.Fatalf("BİLİNMEYEN TÜR DEFTERE HİÇ GİRMEDİ; olaylar: %+v", *got)
	}
	e := (*got)[0]
	if e.Op != OpUnknown {
		t.Errorf("Op = %q, %q bekleniyordu", e.Op, OpUnknown)
	}
	if !strings.Contains(e.Detail, "21") {
		t.Errorf("detail = %q; tür numarasını taşımalı ki operatör neye baktığını bilsin", e.Detail)
	}
	if !e.OK {
		t.Error("hedef kabul etti ama satır başarısız yazılmış")
	}
}

// Tanıdığımız salt-okuma türleri satır ÜRETMEMEYE devam etmeli: değişiklik
// yalnızca BİLİNMEYENİ görünür kılmalı, defteri stat gürültüsüyle
// doldurmamalı.
func TestKnownReadOnlyRequestsStayQuiet(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  byte
	}{
		{"stat", fxpStat},
		{"lstat", fxpLstat},
		{"realpath", fxpRealpath},
		{"readlink", fxpReadlink},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, got := collect(t)

			feedClient(t, s, newPkt(tc.typ).u32(4).str("/etc/passwd").bytes())
			feedTarget(t, s, statusOK(4))

			if len(*got) != 0 {
				t.Fatalf("%s satır üretti: %+v", tc.name, *got)
			}
		})
	}
}

/*
 * Bilinmeyen bir tür TANITICI döndürürse onu dosya olarak kaydetmiyoruz.
 *
 * ⚠️ NEDEN: yolu bilmiyoruz, dolayısıyla kaydedersek yol BOŞ olur ve
 * sonraki READ/WRITE baytları boş yola atfedilirdi. Defterde, olmayan bir
 * dosyaya yapılmış gerçek bir transfer görünürdü — yanlış satır, eksik
 * satırdan kötü.
 */
func TestUnknownTypeReturningAHandleIsNotRecordedAsAFile(t *testing.T) {
	const fxpWeird = 99

	s, got := collect(t)

	feedClient(t, s, newPkt(fxpWeird).u32(2).str("/srv/gizli.db").bytes())
	feedTarget(t, s, newPkt(fxpHandle).u32(2).str("h1").bytes())

	if len(*got) != 1 || (*got)[0].Op != OpUnknown {
		t.Fatalf("bilinmeyen tür tanıtıcı döndürdü, satır beklenen gibi değil: %+v", *got)
	}
	if p := (*got)[0].Path; p != "" {
		t.Errorf("yol = %q; bilmediğimiz bir yolu uydurmuş oluyoruz", p)
	}

	// Tanıtıcı KAYDEDİLMEMELİ: üzerinden okunan baytlar boş yola
	// yazılmamalı.
	feedClient(t, s, newPkt(fxpRead).u32(3).str("h1").u64(0).u32(64).bytes())
	feedTarget(t, s, newPkt(fxpData).u32(3).str(strings.Repeat("x", 64)).bytes())
	feedClient(t, s, newPkt(fxpClose).u32(4).str("h1").bytes())
	feedTarget(t, s, statusOK(4))

	for _, e := range *got {
		if e.Op == OpTransfer {
			t.Fatalf("boş yola transfer satırı yazıldı: %+v", e)
		}
	}
}
