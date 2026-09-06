package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

/*
 * Yol kuralı ucunun doğrulaması, depoya HİÇ gitmeden ölçülüyor.
 *
 * ⚠️ NİYE BURADA: şemada da CHECK var ve "constraint violation" dönen
 * bir cevap teknik olarak doğru, pratikte işe yaramaz — yöneticiye ne
 * yazması gerektiğini söylemiyor. Bu testler, reddin SEBEBİYLE
 * geldiğini çiviliyor.
 */

func postRule(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()

	s := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/roles/ops/paths",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("name", "ops")
	s.adminSetRolePath(rec, req)

	return rec
}

func TestRelativePrefixIsRefusedWithTheReason(t *testing.T) {
	rec := postRule(t, `{"prefix":"var/log","allow":true}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("durum %d, 400 bekleniyordu", rec.Code)
	}
	/*
	 * ⚠️ SEBEP ARANIYOR, DURUM KODU DEĞİL. "400" tek başına, kuralı
	 * yazan kişiye yolun neden reddedildiğini söylemiyor; o kişi de
	 * genelde önekin göreli olduğunun farkında değil.
	 */
	if !strings.Contains(rec.Body.String(), "absolute") {
		t.Errorf("sebep önekin mutlak olması gerektiğini söylemiyor: %s", rec.Body.String())
	}
}

/*
 * ⚠️ RET + YAZMA ÇELİŞKİSİ KAYDEDİLMEDEN DURDURULUYOR.
 *
 * Kaydedilseydi liste "denied, read-write" diye okunacak bir satır
 * gösterirdi ve yöneticiye o rolün yazabildiğini düşündürürdü. Politika
 * o satırı zaten ret sayar; yani ekranla gerçek ayrışırdı.
 */
func TestDenialWithWriteIsRefused(t *testing.T) {
	rec := postRule(t, `{"prefix":"/var/log","allow":false,"can_write":true}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("durum %d, 400 bekleniyordu", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "grants nothing") {
		t.Errorf("sebep çelişkiyi anlatmıyor: %s", rec.Body.String())
	}
}

func TestEmptyPrefixIsRefused(t *testing.T) {
	if rec := postRule(t, `{"prefix":"   ","allow":true}`); rec.Code != http.StatusBadRequest {
		t.Errorf("yalnızca boşluktan oluşan önek kabul edildi: %d", rec.Code)
	}
}

// Denetim satırı, kuralın NE OLDUĞUNU okunur biçimde taşımalı: "set
// /var/log" satırı, izin mi ret mi olduğunu söylemiyor.
func TestAuditPhraseSaysWhatTheRuleIs(t *testing.T) {
	cases := []struct {
		allow, write bool
		want         string
	}{
		{true, false, "allow /var/log (read-only)"},
		{true, true, "allow /var/log (read-write)"},
		{false, false, "deny /var/log"},
	}
	for _, c := range cases {
		if got := rulePhrase("/var/log", c.allow, c.write); got != c.want {
			t.Errorf("rulePhrase(%v,%v) = %q, %q bekleniyordu", c.allow, c.write, got, c.want)
		}
	}
}
