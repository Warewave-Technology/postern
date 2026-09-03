//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * ⚠️ ADI SERBEST BIRAKMAK, O ADA BAĞLI OTURUMLARI DA BIRAKMALI.
 *
 * `purge` satırı silmiyor, adı serbest bırakıyor: username
 * 'purged:<id>' oluyor ki denetim kayıtlarındaki metin okunabilir
 * kalsın. Amacın tamamı adın yeniden kullanılabilmesi.
 *
 * Panel oturumları ise BELLEKTE ve KULLANICI ADININ METNİYLE
 * anahtarlanıyor. Purge onları düşürmezse, ad yeniden yaratıldığında
 * eski oturum YENİ kişiye çözülüyor: her istekte koşan
 * accountStillOpen RefuseIfDeleted'e bakıyor, o da artık yeni satırı
 * bulup nil dönüyor — kontrol geçiliyor.
 *
 * Sonucu kayıtlardan ayırt edilemeyen bir kimlik karışması: ayrılan
 * kişinin uyuyan sekmesi, aynı adı alan yeni kişinin rolleriyle onun
 * hedeflerinde çalışır ve denetim satırlarını onun adına yazar.
 *
 * ⚠️ DURUM DOĞRUDAN VERİTABANINDAN 'deleted' YAPILIYOR, panel ucundan
 * DEĞİL. O uç da oturumları düşürüyor (savunma amaçlı) ve testi oradan
 * geçirseydik purge'ün kendi düzeltmesi ölçülmeden geçerdi.
 */
func TestPurgingAUsernameDropsItsPanelSessions(t *testing.T) {
	_, apiURL, _, db := oobBastion(t, 0)
	ctx := context.Background()

	// Yönetici IdP'den giriyor: yönetici hesabı YEREL PAROLA TUTAMIYOR
	// (göç 026), o yüzden iki kimlik iki ayrı kapıdan geliyor.
	if err := db.SetUserAdmin(ctx, "yigit", true); err != nil {
		t.Fatal(err)
	}
	if err := db.AllowIdentityBind(ctx, "yigit", time.Now()); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, admin, apiURL)

	// Ayşe yerel parolayla giriyor. Kaynak ayarı ONUN girişi için
	// gerekiyor; yöneticinin oturumu zaten kurulmuş durumda.
	if err := db.SetSetting(ctx, auth.KeyLoginSource, "local", false, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	secret, verifier, err := auth.NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReplaceLocalCredential(ctx, "ayse", verifier, "yigit"); err != nil {
		t.Fatal(err)
	}
	jar2, _ := cookiejar.New(nil)
	ayse := &http.Client{Jar: jar2, Timeout: 30 * time.Second}
	if code, msg := localSignIn(t, ayse, apiURL, "ayse", secret); code != http.StatusOK {
		t.Fatalf("ayşe girişi %d: %s", code, msg)
	}

	/*
	 * ⚠️ PAROLA HEMEN DEĞİŞTİRİLİYOR VE BU, TESTİN GEÇERLİLİĞİ İÇİN.
	 *
	 * Verilen değerle giren oturum KISITLI ve o kısıt yerel kimlik
	 * bilgisi satırına bağlı; purge ise o satırı da siliyor
	 * (accountstate.go: DELETE FROM local_credentials). Kısıtlı
	 * oturumla ölçseydik istek zaten 401 dönerdi ve test, purge'ün
	 * oturumu düşürüp düşürmediğini HİÇ ölçmeden geçerdi — ölçüldü,
	 * düzeltme kaldırıldığında da geçiyordu.
	 *
	 * Tam oturum, yalnızca kullanıcı adına bağlı olan tek şey; yani
	 * ölçmek istediğimiz şeyin ta kendisi.
	 */
	if code, msg := postJSON(t, ayse, apiURL+"/api/me/password", map[string]string{
		"current": secret, "new": "mor-otobus-42-lale",
	}); code != http.StatusOK {
		t.Fatalf("ayşe parolasını değiştiremedi (%d): %s", code, msg)
	}

	// ⚠️ ÖNCE ÇALIŞTIĞINI GÖSTER: bu satır olmadan test, oturum en
	// baştan geçersizken de geçerdi.
	me, status := fetchMe(t, ayse, apiURL)
	if status != http.StatusOK {
		t.Fatalf("ayşe'nin oturumu daha başta çalışmıyor: /api/me = %d", status)
	}
	if me.MustChangePassword {
		t.Fatal("oturum hâlâ kısıtlı — test yerel kimlik bilgisine bağlı kalır")
	}

	// Ayrılıyor. (Panel ucu değil, doğrudan durum — yukarıdaki nota bakın.)
	if err := db.SetAccountState(ctx, "ayse", store.StateDeleted); err != nil {
		t.Fatal(err)
	}
	if code, msg := adminReq(t, admin, http.MethodPost,
		apiURL+"/api/admin/users/ayse/purge", ""); code != http.StatusOK {
		t.Fatalf("purge %d: %s", code, msg)
	}

	// Aynı adla YENİ biri işe giriyor.
	if _, err := db.CreateUser(ctx, "ayse", "ayse.yeni@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}

	/*
	 * ⚠️ ASIL ÖLÇÜM DEFTERDEN OKUNUYOR, /api/me'DEN DEĞİL — ve sebebi
	 * testin kendi sınırı, ölçüm kolaylığı değil.
	 *
	 * Ayşe'nin oturumu YEREL kapıdan çıkma (viaLocal) ve o kapı,
	 * yerel kimlik bilgisi satırının varlığına bağlı; purge onu da
	 * siliyor. Yani bu oturum, düzeltme OLMASA DA 401 alıyor — ölçüldü,
	 * `dropped := 0` mutasyonuyla test yine geçiyordu.
	 *
	 * Tehlikeli olan nüfus IdP'den girenler: onların oturumu hiçbir
	 * satıra bağlı değil, yalnızca ada. Bu koşum takımında ikinci bir
	 * IdP kimliği yok (Keycloak tek kullanıcı veriyor ve yönetici
	 * hesabı yerel parola TUTAMIYOR — göç 026), yani o oturumu burada
	 * kuramıyoruz.
	 *
	 * Ölçülebilen ve düzeltmeyi ayırt eden şey kablolamanın kendisi:
	 * purge, ada bağlı canlı oturumu BULDU ve DÜŞÜRDÜ. Defter satırı
	 * bunu sayıyla söylüyor; düşürülmezse sayı sıfır olur.
	 */
	status, body := adminReq(t, admin, http.MethodGet, apiURL+"/api/admin/log", "")
	if status != http.StatusOK {
		t.Fatalf("defter okunamadı: %d %s", status, body)
	}
	var entries []struct {
		Action, Entity, Details string
	}
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		t.Fatalf("defter JSON: %v — %s", err, body)
	}
	var purge string
	for _, e := range entries {
		if e.Action == "user.purge" && e.Entity == "ayse" {
			purge = e.Details
		}
	}
	if purge == "" {
		t.Fatalf("defterde user.purge izi yok: %s", body)
	}
	if !strings.Contains(purge, "1 panel session(s) removed") {
		t.Errorf("purge, ada bağlı açık panel oturumunu düşürmedi; defter: %q\n"+
			"Ad serbest bırakıldığı için o oturum, aynı adı alan yeni kişiye "+
			"çözülür ve denetim satırlarını onun adına yazar", purge)
	}

	// Bu oturumun artık geçmemesi de doğru olan, ama tek başına
	// düzeltmeyi ayırt etmiyor (yukarıdaki nota bakın).
	if _, s := fetchMe(t, ayse, apiURL); s != http.StatusUnauthorized {
		t.Errorf("purge edilmiş adın eski oturumu hâlâ geçerli: /api/me = %d", s)
	}
}
