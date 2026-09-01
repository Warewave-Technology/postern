package ldap

import (
	"errors"
	"testing"
)

/*
 * ⚠️ AD'NİN 49 NUMARALI HATASI BEŞ AYRI ŞEY DEMEK OLABİLİR.
 *
 * Hepsini "yanlış parola" saymak, doğru parolasını bilen kullanıcıyı
 * onu defalarca denemeye ve sonra yanlış yerde — postern'de — arıza
 * aramaya gönderiyordu. Yapılacak iş belli ve postern'de değil.
 */
func TestADSubCode(t *testing.T) {
	// AD'nin gerçek mesaj biçimi.
	expired := errors.New("LDAP Result Code 49 \"Invalid Credentials\": " +
		"80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, " +
		"data 532, v3839")
	mustChange := errors.New("... data 773, v3839")
	locked := errors.New("... data 775, v3839")

	if !adSubCode(expired, "532") {
		t.Error("532 bulunamadı")
	}
	if !adSubCode(mustChange, "773") {
		t.Error("773 bulunamadı")
	}
	if !adSubCode(locked, "775") {
		t.Error("775 bulunamadı")
	}

	// ⚠️ BAŞKA BİR SAYININ İÇİNDE GEÇEN KOD EŞLEŞMEMELİ. Ayraç
	// aramamızın sebebi bu: çıplak "532", "1532" içinde de geçerdi.
	if adSubCode(errors.New("... data 1532, v3839"), "532") {
		t.Error("1532 içindeki 532 eşleşti")
	}
	if adSubCode(errors.New("... data 5320, v3839"), "532") {
		t.Error("5320 içindeki 532 eşleşti")
	}

	// Eşleşme yoksa hiçbir bayrak konmuyor: yanlış pozitif üretmiyor,
	// yalnızca daha iyi bir cümle kurma fırsatını kaçırıyor.
	if adSubCode(errors.New("invalid credentials"), "532") {
		t.Error("kodsuz mesaj eşleşti")
	}
	if adSubCode(nil, "532") {
		t.Error("nil eşleşti")
	}
}

/*
 * ⚠️ REFERRAL "YOK" DEĞİL "BURADA DEĞİL" DEMEK.
 *
 * Boş sonuç PresenceAbsent'a çevriliyor ve o da "kullanıcı silinmiş"
 * demek — groupsync onu görüp rol iptaline gidiyor. Ama AD, aranan şey
 * başka bir alan adındaysa SIFIR giriş ve BİR REFERRAL döndürüyor:
 * kişi duruyor, yalnızca bu sunucuda değil.
 *
 * Bu testin ölçtüğü şey mesajın kendisi: hata kurulmuş bir arama
 * gerektirmeden, çıktının operatöre NE YAPACAĞINI söylediğini
 * doğruluyor. Asıl davranış (Unknown'a düşmek) presence.go'nun
 * hatayı Unknown'a çevirmesinden geliyor ve o zaten testli.
 */
func TestReferralMessageTellsTheOperatorWhatToDo(t *testing.T) {
	// findUser'ın kurduğu metnin aynısı.
	msg := "ldap: user yigit: the directory returned a referral instead of an answer " +
		"(ldap://sub.example.com/DC=sub,DC=example,DC=com) — this base DN does not " +
		"hold that user; point user_base at the domain that does, or use a global catalog"

	for _, want := range []string{"referral", "user_base", "global catalog"} {
		if !containsFold(msg, want) {
			t.Errorf("mesaj %q içermiyor: %s", want, msg)
		}
	}
	// ⚠️ "not found" ya da "deleted" DEMEMELİ: operatörü kullanıcıyı
	// aramaya değil, taban DN'i düzeltmeye göndermeli.
	for _, bad := range []string{"not found", "deleted", "no such user"} {
		if containsFold(msg, bad) {
			t.Errorf("mesaj %q diyor — yanlış yere gönderiyor", bad)
		}
	}
}

func containsFold(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if equalFold(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 32
		}
		if 'A' <= y && y <= 'Z' {
			y += 32
		}
		if x != y {
			return false
		}
	}
	return true
}
