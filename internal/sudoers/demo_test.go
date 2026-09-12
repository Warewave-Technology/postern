package sudoers

import "testing"

/*
 * ⚠️ BU TEST BİR İDDİAYI ÖLÇÜYOR, BİR DAVRANIŞI DEĞİL.
 *
 * Aşağıdaki kural gerçek bir Debian 13 makinesinde denendi: visudo
 * "parsed OK" dedi ve o kuralı taşıyan kullanıcı
 *
 *   sudo -n find /var/log -maxdepth 0 -exec id \;
 *
 * ile uid=0(root) aldı. Yani sözdizimi kusursuz, panelde masum, ve
 * tam yetki. Doğrulayıcının var olma sebebi tam olarak bu kural.
 */
func TestTheRuleThatLookedNarrowOnARealMachine(t *testing.T) {
	r := Rule{Commands: []Command{
		{Path: "/usr/bin/find", Args: []string{"/var/log", "*"}},
	}}

	f := Validate(r)
	if len(f) == 0 {
		t.Fatal("GERÇEK MAKİNEDE ROOT VEREN KURAL TEMİZ GÖRÜLDÜ")
	}
	if !Refuses(f, false) {
		t.Error("onaysız geçti")
	}
	// Joker yapısal bir sorun: onayla da geçmiyor.
	if !Refuses(f, true) {
		t.Error("ONAYLA GEÇTİ: joker onaylanabilir bir risk değil, sınırsızlık")
	}
}
