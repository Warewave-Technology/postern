package httpapi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/proxy"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

/*
 * ⚠️ "EL SIKIŞAMADIM" İLE "REDDEDİLDİM" AYNI CÜMLE OLAMAZ.
 *
 * Bu ikisi operatörü bambaşka yerlere gönderiyor: biri hedefteki
 * TrustedUserCAKeys'e, diğeri ağa ya da sshd'nin algoritma
 * yapılandırmasına. Sınıflandırıcı düzeltilmeden önce ikisi de tek bir
 * cümleye düşüyordu ve o cümle çoğu zaman yanlış olanıydı.
 */
func TestTerminalRefusalSeparatesHandshakeFromRefusal(t *testing.T) {
	_, refused := terminalRefusal(fmt.Errorf("x: %w", upstream.ErrRefused))
	_, handshake := terminalRefusal(fmt.Errorf("x: %w", upstream.ErrHandshake))
	_, fallback := terminalRefusal(fmt.Errorf("bilinmeyen"))

	if refused == handshake {
		t.Error("iki sınıf aynı cümleyi veriyor — ayırmanın anlamı kalmıyor")
	}
	if handshake == fallback {
		t.Error("el sıkışma arızası genel cümleye düşüyor — sınıf boşa geçmiş")
	}

	// ⚠️ SERTİFİKADAN BAHSETMEMELİ: sorunun sertifikayla ilgisi yok ve
	// operatörü oraya göndermek, düzeltilen arızanın ta kendisi.
	low := strings.ToLower(handshake)
	for _, bad := range []string{"certificate", " ca"} {
		if strings.Contains(low, bad) {
			t.Errorf("el sıkışma cümlesi %q içeriyor: %q", bad, handshake)
		}
	}
}

/*
 * ⚠️ CÜMLELER WEBSOCKET KAPANIŞ ÇERÇEVESİNE SIĞMALI.
 *
 * RFC 6455 sebep alanını 123 BAYTLA sınırlıyor ve aşan bir çerçeve
 * gönderilemiyor: kullanıcı sebebi görmek yerine sebepsiz kopuyor —
 * yani cümleyi yazmanın bütün amacı kayboluyor. Bayt sayılıyor, rune
 * değil: uzun tire üç bayt.
 */
func TestTerminalRefusalReasonsFitTheCloseFrame(t *testing.T) {
	for _, err := range []error{
		proxy.ErrAccessDenied, proxy.ErrRecordingFailed,
		upstream.ErrRefused, upstream.ErrHandshake,
		upstream.ErrUnreachable, upstream.ErrHostKeyMismatch,
		fmt.Errorf("bilinmeyen"),
	} {
		_, reason := terminalRefusal(fmt.Errorf("x: %w", err))
		if n := len(reason); n > 123 {
			t.Errorf("%v için sebep %d bayt (>123): %q — çerçeve hiç "+
				"gönderilemez ve kullanıcı sebepsiz kopar", err, n, reason)
		}
	}
}
