package model

import "testing"

/*
 * ⚠️ BOŞ LİSTE `unknown`'a DÜŞER, DOLU LİSTE DEĞİŞMEZ.
 *
 * Var olma sebebi: grup claim'i göndermeyen bir IdP'de hiçbir grup
 * hiçbir role eşleşmiyor, ProvisionUser hesabı açmıyor ve kullanıcı
 * kapıda kalıyor. Bu grup yöneticiye bir tutamak veriyor.
 *
 * ⚠️ Dolu listeye dokunmaması da aynı derecede önemli: `unknown`'ı
 * herkesin listesine eklemek, ona eşlenmiş bir rolü HERKESE dağıtırdı.
 */
func TestResolvedGroups(t *testing.T) {
	if got := ResolvedGroups(nil); len(got) != 1 || got[0] != UnknownGroup {
		t.Fatalf("ResolvedGroups(nil) = %v, [%s] bekleniyordu", got, UnknownGroup)
	}
	if got := ResolvedGroups([]string{}); len(got) != 1 || got[0] != UnknownGroup {
		t.Fatalf("ResolvedGroups([]) = %v, [%s] bekleniyordu", got, UnknownGroup)
	}

	in := []string{"sysadmins", "hr"}
	got := ResolvedGroups(in)
	if len(got) != 2 || got[0] != "sysadmins" || got[1] != "hr" {
		t.Fatalf("ResolvedGroups(%v) = %v — dokunulmamalıydı", in, got)
	}
}
