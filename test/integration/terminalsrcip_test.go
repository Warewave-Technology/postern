//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// trustedProxies, koşum takımının kuracağı güvenilen vekil listesi.
// Boşken (varsayılan) hiçbir şey değişmiyor.
var trustedProxies []string

/*
 * ⚠️ DENETİM SATIRINA KULLANICININ ADRESİ YAZILMALI, VEKİLİNKİ DEĞİL.
 *
 * Panel terminali, oturumu açarken kaynak adresi doğrudan
 * r.RemoteAddr'dan alıyordu. TLS'i sonlandıran bir ters vekilin
 * arkasında bu, sessions.src_ip'ye VEKİLİN adresini yazıyor demek —
 * üstelik trusted_proxies doğru yapılandırılmışken, yani postern
 * gerçek adresi biliyor ve atıyordu.
 *
 * Aynı sütuna SSH kapısı doğrudan bağlantının adresini yazıyor. Yani
 * tek sütun iki ayrı anlam taşıyordu: "bu kabuk nereden açıldı"
 * sorusu, panelden açılan her oturum için aynı cevabı veriyordu ve
 * iki kullanıcı ayırt edilemiyordu.
 *
 * Değer buradan pek çok yere yayılıyor: denetim ekranındaki Src
 * sütunu, canlı oturum satırı, hedef sayfası, SFTP dosya olayları ve
 * kesme işleminin admin_log açıklaması.
 */
func TestWebTerminalRecordsTheUsersAddressNotTheProxys(t *testing.T) {
	trustedProxies = []string{"127.0.0.1/32", "::1/128"}
	t.Cleanup(func() { trustedProxies = nil })

	_, apiURL, _, db := oobBastionWithTerminal(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	// ⚠️ Vekil davranışı: istek 127.0.0.1'den geliyor (güvenilen), ve
	// gerçek istemciyi başlıkta bildiriyor.
	const real = "203.0.113.7"
	wsURL := strings.Replace(apiURL, "http://", "ws://", 1) + "/api/terminal/web01"
	header := http.Header{}
	header.Set("Origin", apiURL)
	header.Set("X-Forwarded-For", real)

	conn, _, err := websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{
		HTTPClient: client,
		HTTPHeader: header,
	})
	if err != nil {
		t.Fatalf("terminal WS açılamadı: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	id := waitForOpenSession(t, db)
	s, err := db.Session(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}

	if s.SrcIP != real {
		t.Errorf("src_ip = %q, %q bekleniyordu — denetim satırına vekilin "+
			"adresi yazılmış; vekil arkasındaki iki kullanıcı ayırt edilemez",
			s.SrcIP, real)
	}
}

/*
 * ⚠️ VE GÜVENİLMEYEN BİR KAYNAK BAŞLIĞI UYDURAMAMALI.
 *
 * Varsayılan (boş liste) davranışın değişmediğini de ölçüyor: bu
 * olmadan, başlığı koşulsuz okuyan bir düzeltme de yukarıdaki testi
 * geçerdi — ve o düzeltme, herkesin denetim satırına istediği adresi
 * yazabilmesi demek olurdu.
 */
func TestForgedForwardedHeaderIsIgnoredWithoutTrustedProxies(t *testing.T) {
	_, apiURL, _, db := oobBastionWithTerminal(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	wsURL := strings.Replace(apiURL, "http://", "ws://", 1) + "/api/terminal/web01"
	header := http.Header{}
	header.Set("Origin", apiURL)
	header.Set("X-Forwarded-For", "198.51.100.9")

	conn, _, err := websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{
		HTTPClient: client,
		HTTPHeader: header,
	})
	if err != nil {
		t.Fatalf("terminal WS açılamadı: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	id := waitForOpenSession(t, db)
	s, err := db.Session(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}

	if s.SrcIP == "198.51.100.9" {
		t.Error("uydurma X-Forwarded-For denetim satırına yazıldı — " +
			"güvenilen vekil listesi boşken başlık okunmamalı")
	}
}
