package httpapi

// TOTP kod isteminin süresi.

import "time"

/*
 * Kod istemi, açık kalabileceği süreyle sınırlı.
 *
 * ⚠️ BU BİR GÜVENLİK SINIRI DEĞİL VE ÖYLE ANLATILMAMALI. Akış parolayı
 * kodla BİRLİKTE yeniden gönderiyor (araya belirteç koymamak bilinçli:
 * o belirteç, ikinci faktörünü henüz kanıtlamamış birinin elinde duran
 * bir şey olurdu). Dolayısıyla pencereyi tazelemek, parolayı yeniden
 * göndermek kadar kolay ve bir saldırganı yavaşlatmıyor.
 *
 * Yaptığı iki iş gerçek: açık kalmış bir istemin ömrünü sınırlıyor, ve
 * GEÇ GELEN kodu bir başarısızlık olarak saydırıyor — yani istemi
 * süresiz açık tutmak bedelsiz olmuyor.
 *
 * ⚠️ TERK EDİLEN İSTEM SAYILMIYOR ve sayılamaz: kullanıcı hiçbir şey
 * göndermezse ölçecek bir olay yok. Saydığımızı iddia etmek, ölçmediğimiz
 * bir şeyi ölçüyormuş gibi göstermek olurdu.
 */

// notePrompt, bu hesap için kod isteminin başladığını kaydeder.
func (s *Server) notePrompt(name string) {
	if s.totpWindow <= 0 {
		return
	}

	s.promptMu.Lock()
	defer s.promptMu.Unlock()

	if s.prompts == nil {
		s.prompts = map[string]time.Time{}
	}
	s.pruneLocked()
	s.prompts[name] = time.Now()
}

/*
 * promptExpired, bu hesabın kod isteminin süresinin geçip geçmediği.
 *
 * ⚠️ İSTEM YOKSA "GEÇMİŞ" DEĞİL. İstemci parolayı ve kodu tek istekte
 * göndermiş olabilir — panel iki adım kullanıyor ama akış bunu şart
 * koşmuyor. Kaydı olmayan bir isteği reddetmek, hiçbir zaman kod istemi
 * görmemiş bir istemciyi kalıcı olarak dışarıda bırakırdı.
 */
func (s *Server) promptExpired(name string) bool {
	if s.totpWindow <= 0 {
		return false
	}

	s.promptMu.Lock()
	defer s.promptMu.Unlock()

	at, ok := s.prompts[name]
	if !ok {
		return false
	}

	return time.Since(at) > s.totpWindow
}

// clearPrompt, başarılı girişten sonra kaydı bırakır.
func (s *Server) clearPrompt(name string) {
	s.promptMu.Lock()
	defer s.promptMu.Unlock()

	delete(s.prompts, name)
}

/*
 * pruneLocked, süresi çoktan geçmiş kayıtları atar. promptMu tutulmalı.
 *
 * ⚠️ TEMİZLİK OLMADAN BU HARİTA SINIRSIZ BÜYÜR: kimliği doğrulanmamış
 * biri her seferinde başka bir kullanıcı adıyla parola denerse... hayır,
 * kayıt ancak PAROLA DOĞRULANDIKTAN sonra açılıyor, yani satır başına
 * bir geçerli parola gerekiyor. Yine de terk edilen istemler birikir ve
 * onları tutmanın bir faydası yok.
 */
func (s *Server) pruneLocked() {
	if len(s.prompts) < 64 {
		return
	}

	cut := time.Now().Add(-2 * s.totpWindow)
	for k, v := range s.prompts {
		if v.Before(cut) {
			delete(s.prompts, k)
		}
	}
}
