package httpapi

import (
	"testing"
	"time"
)

// promptServer, yalnızca istem penceresini ölçmek için kurulmuş sunucu.
func promptServer(window time.Duration) *Server {
	return &Server{totpWindow: window, prompts: map[string]time.Time{}}
}

/*
 * ⚠️ KAYDI OLMAYAN İSTEK "SÜRESİ GEÇMİŞ" DEĞİL.
 *
 * Panel iki adım kullanıyor ama akış bunu ŞART KOŞMUYOR: istemci parolayı
 * ve kodu tek istekte gönderebiliyor. Kaydı olmayan bir isteği reddetmek,
 * hiçbir zaman kod istemi görmemiş bir istemciyi kalıcı olarak dışarıda
 * bırakırdı.
 */
func TestAnUnseenPromptIsNotExpired(t *testing.T) {
	s := promptServer(time.Minute)

	if s.promptExpired("ayse") {
		t.Fatal("hiç istem görülmemiş hesap süresi geçmiş sayıldı")
	}
}

func TestPromptExpiresAfterTheWindow(t *testing.T) {
	s := promptServer(50 * time.Millisecond)
	s.notePrompt("ayse")

	if s.promptExpired("ayse") {
		t.Fatal("istem daha yeni açıldı ama süresi geçmiş sayıldı")
	}

	time.Sleep(80 * time.Millisecond)

	if !s.promptExpired("ayse") {
		t.Fatal("pencere doldu ama istem hâlâ geçerli sayılıyor")
	}
}

/*
 * ⚠️ SIFIR PENCERE "KAPALI" DEMEK, "HEMEN GEÇTİ" DEĞİL.
 *
 * Sıfırı "anında zamanaşımı" saymak, yapılandırmayı boş bırakan bir
 * operatörün her girişini kırardı — ve kırılma yeri kullanıcıya
 * "kodunuz zaman aşımına uğradı" diyen bir mesaj olurdu, yani sebebi
 * hiçbir yerde görünmezdi.
 */
func TestAZeroWindowMeansNoWindow(t *testing.T) {
	s := promptServer(0)
	s.notePrompt("ayse")

	time.Sleep(20 * time.Millisecond)

	if s.promptExpired("ayse") {
		t.Fatal("pencere kapalıyken istem zaman aşımına uğradı")
	}
	if len(s.prompts) != 0 {
		t.Errorf("pencere kapalıyken kayıt tutuldu: %v", s.prompts)
	}

	/*
	 * ⚠️ KAYIT VARKEN PENCERE KAPATILIRSA DA GEÇERLİ KALMALI.
	 *
	 * Bu testin ilk hâli yalnızca yukarıdaki durumu ölçüyordu ve
	 * mutasyon testinde yakalandı: pencere sıfırken notePrompt zaten
	 * kayıt tutmuyor, dolayısıyla promptExpired'daki korumayı sökmek
	 * gözlenebilir bir fark yaratmıyordu. Korumanın işe yaradığı
	 * gerçek durum bu: kayıt açıldıktan SONRA pencere kapatılıyor.
	 */
	s2 := promptServer(time.Millisecond)
	s2.notePrompt("ayse")
	time.Sleep(10 * time.Millisecond)
	if !s2.promptExpired("ayse") {
		t.Fatal("ölçüm kurulamadı: kayıt süresi geçmiş olmalıydı")
	}

	s2.totpWindow = 0
	if s2.promptExpired("ayse") {
		t.Fatal("pencere kapatıldı ama eski kayıt hâlâ zaman aşımı ürettiriyor")
	}
}

// Başarılı giriş kaydı bırakıyor: aynı hesabın bir sonraki girişi taze bir
// pencereyle başlamalı.
func TestClearPromptForgetsTheAccount(t *testing.T) {
	s := promptServer(time.Minute)
	s.notePrompt("ayse")
	s.clearPrompt("ayse")

	if _, ok := s.prompts["ayse"]; ok {
		t.Fatal("kayıt bırakılmadı")
	}
}

/*
 * Harita sınırsız büyümüyor.
 *
 * ⚠️ Kayıt ancak PAROLA DOĞRULANDIKTAN sonra açılıyor, yani satır başına
 * geçerli bir parola gerekiyor — bu bir saldırı yüzeyi değil. Yine de
 * terk edilmiş istemler birikiyor ve onları tutmanın bir faydası yok.
 */
func TestOldPromptsArePruned(t *testing.T) {
	s := promptServer(10 * time.Millisecond)

	for i := range 200 {
		s.prompts[string(rune('a'+i%26))+string(rune('a'+i/26))] = time.Now().Add(-time.Hour)
	}
	s.notePrompt("taze")

	if len(s.prompts) > 64 {
		t.Fatalf("eski kayıtlar temizlenmedi: %d kayıt", len(s.prompts))
	}
	if _, ok := s.prompts["taze"]; !ok {
		t.Error("taze kayıt temizlikte gitti")
	}
}
