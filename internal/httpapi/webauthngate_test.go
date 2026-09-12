package httpapi

// Girişte güvenlik anahtarının ikinci faktör olarak istenmesi (göç 039).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/store"
)

// keyed, anahtarı olan bir hesap kurar ve sunucuyu döner.
func keyed(t *testing.T, only bool) (*Server, *store.Store) {
	t.Helper()
	s, db := dbServer(t)
	s.SetExternalURL("https://postern.example.com")

	ctx := t.Context()
	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddWebAuthnCredential(ctx, "ayse", store.WebAuthnCredential{
		ID:        "a2V5",
		PublicKey: []byte("cose"),
		Name:      "iş dizüstü",
	}); err != nil {
		t.Fatal(err)
	}
	if only {
		if err := db.SetWebAuthnOnly(ctx, "ayse", true); err != nil {
			t.Fatal(err)
		}
	}

	return s, db
}

// factor, ikinci faktör kapısını çağırır ve yanıtı döner.
func factor(t *testing.T, s *Server, assertion, code string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()

	r := httptest.NewRequest(http.MethodPost, "/auth/local", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	w := httptest.NewRecorder()

	var raw json.RawMessage
	if assertion != "" {
		raw = json.RawMessage(assertion)
	}
	s.secondFactor(w, r, "ayse", raw, code)

	body := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)

	return w, body
}

/*
 * ⚠️ ANAHTARI OLAN HESAPTAN İMZA İSTENİYOR — VE İSTEK BİR HATA DEĞİL.
 *
 * Panelin anahtar istemini çizebilmesi için "parola yanlış" ile "ikinci
 * faktör bekleniyor"u ayırt etmesi gerekiyor; bu yüzden 401 ile birlikte
 * makine okunur bir işaret dönüyor. Bilgi sızmıyor: buraya gelen taraf
 * parolayı zaten kanıtladı.
 */
func TestAccountWithAKeyIsAskedForIt(t *testing.T) {
	s, _ := keyed(t, false)

	w, body := factor(t, s, "", "")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("durum = %d, 401 bekleniyordu", w.Code)
	}
	if body["webauthn_required"] != true {
		t.Errorf("ANAHTAR İSTENMEDİ: gövde %v", body)
	}
	if body["options"] == nil {
		t.Error("meydan okuma gönderilmedi: tarayıcı imza isteyemez")
	}
}

/*
 * ⚠️ BU DOSYANIN EN ÖNEMLİ TESTİ: "YALNIZCA ANAHTAR" AÇIKKEN KOD
 * KABUL EDİLMİYOR.
 *
 * Kabul edilseydi kilidin hiçbir anlamı kalmazdı: kullanıcı kimlik
 * avına dayanıklı bir faktör seçtiğini sanarken, saldırgan anahtarı hiç
 * sormadan kodu ister ve hesap eskisi kadar kırılgan kalırdı. Sessiz
 * bir zayıflama, olmayan bir korumadan kötüdür — çünkü kullanıcı
 * korunduğunu sanıyor.
 */
func TestCodeIsRefusedWhenTheAccountRequiresAKey(t *testing.T) {
	s, _ := keyed(t, true)

	w, body := factor(t, s, "", "123456")

	if w.Code == http.StatusOK {
		t.Fatal("KOD KABUL EDİLDİ: 'yalnızca anahtar' kilidi baypas edildi")
	}
	if body["webauthn_required"] != true {
		t.Errorf("kod gönderildiğinde anahtar istenmedi: %v", body)
	}
	if body["code_allowed"] != false {
		t.Errorf("KİLİTLİ HESAPTA KOD YOLU AÇIK GÖSTERİLDİ: %v", body)
	}
}

/*
 * ⚠️ KİLİT KAPALIYKEN KOD YOLU AÇIK KALIYOR. Kullanıcı anahtarını
 * yanına almadıysa kendi hesabından kilitlenmemeli; geri düşme
 * bilinçli bir seçim.
 */
func TestCodeStillWorksWhenTheAccountAllowsIt(t *testing.T) {
	s, _ := keyed(t, false)

	w, _ := factor(t, s, "", "123456")

	if w.Code != http.StatusOK {
		t.Fatalf("KOD YOLU KAPANDI: durum = %d, geçmesi bekleniyordu", w.Code)
	}
}

/*
 * ⚠️ ANAHTARI OLMAYAN HESAP ESKİ YOLDAN GEÇİYOR. Bu özelliğin var
 * olması, hiç anahtar kaydetmemiş kullanıcıların girişini
 * değiştirmemeli.
 */
func TestAccountWithoutKeysIsUntouched(t *testing.T) {
	s, db := dbServer(t)
	s.SetExternalURL("https://postern.example.com")
	if _, err := db.CreateUser(t.Context(), "veli", "veli@warewave.io", "veli"); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/auth/local", nil)
	w := httptest.NewRecorder()
	if !s.secondFactor(w, r, "veli", nil, "") {
		t.Fatalf("anahtarsız hesap durduruldu: durum = %d, gövde %s",
			w.Code, w.Body.String())
	}
}

/*
 * ⚠️ YAPILANDIRMA BOZULUNCA KİLİTLİ HESAP SESSİZCE ZAYIFLAMIYOR.
 *
 * external_url'i bozan bir değişiklik, "yalnızca anahtar" diyen bir
 * hesabı sessizce koda düşürebilseydi, kullanıcı kimlik avına
 * dayanıklı bir faktör seçtiğini sanarken koruma ortadan kalkardı ve
 * bunu kimse görmezdi. Doğru davranış gürültülü biçimde durmak.
 *
 * ⚠️ İLK YAZDIĞIM TEST BUNU FAZLA GENİŞ İDDİA EDİYORDU ve düştü:
 * kilidi AÇIK OLMAYAN bir hesap zaten kodu kabul ediyor, dolayısıyla
 * orada bozuk yapılandırma hiçbir şeyi zayıflatmıyor. Zayıflama
 * yalnızca kilitli hesapta anlamlı; iddia oraya taşındı.
 */
func TestBrokenExternalURLDoesNotQuietlyUnlockALockedAccount(t *testing.T) {
	s, _ := keyed(t, true)
	// IP: şartname RP ID olarak kabul etmiyor.
	s.SetExternalURL("http://127.0.0.1:8088")

	w, _ := factor(t, s, "", "123456")

	if w.Code == http.StatusOK {
		t.Fatal("KOD SESSİZCE KABUL EDİLDİ: anahtar koruması yapılandırma " +
			"hatasıyla birlikte kayboldu")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("durum = %d, 503 bekleniyordu (sebebi söyleyen bir hata)", w.Code)
	}
}

/*
 * ⚠️ KARŞI KANIT: kilidi açık olmayan hesapta kod yolu, yapılandırma
 * bozuk olsa bile çalışıyor. Burada kapatılacak bir koruma yok —
 * hesap zaten kodu kabul ediyor — ve kullanıcıyı dışarıda bırakmak,
 * kazanılmış hiçbir güvenlik olmadan bir arıza üretirdi.
 */
func TestBrokenExternalURLStillLetsAnUnlockedAccountUseItsCode(t *testing.T) {
	s, _ := keyed(t, false)
	s.SetExternalURL("http://127.0.0.1:8088")

	if w, _ := factor(t, s, "", "123456"); w.Code != http.StatusOK {
		t.Errorf("kod yolu kapandı: durum = %d", w.Code)
	}
}

/*
 * ⚠️ TÖREN TEK KULLANIMLIK. Aynı meydan okumayla ikinci bir imza
 * denemesi, tekrar saldırılarına kapı açardı; WebAuthn'ın bu saldırıya
 * karşı koyduğu şey meydan okumanın bir kez geçerli olması.
 */
func TestLoginCeremonyIsSpentOnce(t *testing.T) {
	s, _ := keyed(t, false)

	// İlk çağrı töreni açıyor.
	factor(t, s, "", "")

	if _, ok := s.webauthnLogin.take("ayse"); !ok {
		t.Fatal("tören hiç açılmadı")
	}
	if _, ok := s.webauthnLogin.take("ayse"); ok {
		t.Error("TÖREN İKİNCİ KEZ HARCANABİLDİ: meydan okuma tek " +
			"kullanımlık değil")
	}
}

/*
 * ⚠️ IP ADRESİ İÇİN VERİLEN HATA, OPERATÖRE NE YAPACAĞINI SÖYLEMELİ.
 *
 * Kütüphane bu yapılandırmayı zaten reddediyor — ölçüldü: kontrolü
 * kaldırdığımda davranış değişmiyor. Değişen tek şey CÜMLE, ve bu
 * kontrolün var olma sebebi o: "invalid configuration" diyen bir hata,
 * external_url'i düzeltmesi gereken kişiye hiçbir şey söylemiyor.
 * "localhost kabul edilir, 127.0.0.1 edilmez" ise doğrudan düzeltmenin
 * kendisi.
 */
func TestIPAddressErrorNamesTheFix(t *testing.T) {
	_, err := webauthnFor("http://127.0.0.1:8088")
	if err == nil {
		t.Fatal("IP adresi kabul edildi")
	}

	msg := err.Error()
	if !strings.Contains(msg, "localhost") {
		t.Errorf("HATA DÜZELTMEYİ SÖYLEMİYOR: %q — operatör external_url'i "+
			"nasıl düzelteceğini buradan öğrenemez", msg)
	}
	if !strings.Contains(msg, "external_url") {
		t.Errorf("hata hangi ayarın bozuk olduğunu söylemiyor: %q", msg)
	}
}
