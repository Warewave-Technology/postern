package sshalg

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// ⚠️ SHA-1 HİÇBİR LİSTEDE OLMAMALI.
//
// x/crypto'nun varsayılanları uyumluluk için seçilmiş ve SHA-1 taşıyor —
// ölçüldü: KeyExchanges'te diffie-hellman-group14-sha1, MACs'te
// hmac-sha1 ve hmac-sha1-96. Bir bastion'ın taşıma katmanı geride
// kalmış istemcilere uyum sağlamak için değil, arkasındaki her makineye
// giden trafiği korumak için ayarlanır.
func TestNoSHA1Anywhere(t *testing.T) {
	for name, list := range map[string][]string{
		"KeyExchanges": KeyExchanges,
		"Ciphers":      Ciphers,
		"MACs":         MACs,
	} {
		for _, a := range list {
			if strings.Contains(strings.ToLower(a), "sha1") {
				t.Errorf("%s içinde SHA-1: %q", name, a)
			}
		}
	}
}

// Listelerin tamamı x/crypto tarafından DESTEKLENİYOR olmalı: yazım
// hatası yapılan bir algoritma sessizce yok sayılır ve liste
// daraldığını fark etmeden zayıflar.
func TestEveryAlgorithmIsSupported(t *testing.T) {
	sup := ssh.SupportedAlgorithms()
	ins := ssh.InsecureAlgorithms()

	// x/crypto bazı adları yalnız "insecure" listesinde tutuyor; bizim
	// hiçbirimiz orada OLMAMALI ama destek kontrolü ikisini de saymalı.
	known := func(a string, groups ...[]string) bool {
		for _, g := range groups {
			if slices.Contains(g, a) {
				return true
			}
		}
		return false
	}

	// x/crypto bazı algoritmaları ESKİ ADIYLA da kabul ediyor ama
	// SupportedAlgorithms()'te yalnızca kanonik adı listeliyor.
	// Takma ad varsayılan listede VAR (ölçüldü) ve yalnız o adı sunan
	// eski istemcilerin bağlanmasını sağlıyor — dropping it would be a
	// compatibility loss with no security gain.
	aliases := map[string]string{
		"curve25519-sha256@libssh.org": "curve25519-sha256",
	}

	for _, a := range KeyExchanges {
		name := a
		if canon, ok := aliases[a]; ok {
			name = canon
		}
		if !known(name, sup.KeyExchanges) {
			t.Errorf("KeyExchanges: %q x/crypto tarafından desteklenmiyor", a)
		}
		if known(a, ins.KeyExchanges) {
			t.Errorf("KeyExchanges: %q güvensiz listesinde", a)
		}
	}
	for _, a := range Ciphers {
		if !known(a, sup.Ciphers) {
			t.Errorf("Ciphers: %q desteklenmiyor", a)
		}
	}
	for _, a := range MACs {
		if !known(a, sup.MACs) {
			t.Errorf("MACs: %q desteklenmiyor", a)
		}
	}
}

// Listeler BOŞ olmamalı: boş bir liste x/crypto'da "varsayılanı kullan"
// demek, yani sessizce SHA-1'e geri dönmek.
func TestListsAreNotEmpty(t *testing.T) {
	if len(KeyExchanges) == 0 || len(Ciphers) == 0 || len(MACs) == 0 {
		t.Fatal("boş liste varsayılana düşer — SHA-1 geri gelir")
	}
}

/*
 * ⚠️ PİNLENEN ANAHTARLA EL SIKIŞILABİLMELİ.
 *
 * Bu, iki listeyi birbirine bağlayan dikiş: tarama bir türü sunuyorsa,
 * o türden pinlenmiş bir hedefle bağlantı da kurulabilmeli. Dikiş
 * kopunca ortaya çıkan arıza sessiz ve tam: RSA host key'i pinlenmiş
 * her hedef, pin'in tel formatı doğrudan müzakere listesi sanıldığı
 * için OpenSSH 8.8+ üzerinde ERİŞİLEMEZ oluyordu.
 */
func TestPinnedAlgorithmsMatchTheScanList(t *testing.T) {
	formats := []string{
		ssh.KeyAlgoED25519, ssh.KeyAlgoRSA,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	}
	covered := map[string]bool{}

	for _, f := range formats {
		got := HostKeyAlgorithmsFor(f)
		if len(got) == 0 {
			// ⚠️ Süs değil: x/crypto boş listeyi "varsayılanı kullan"
			// diye okuyor ve o varsayılan ssh-rsa ile ssh-dss taşıyor.
			// Boş dönmek sessizce AÇARDI.
			t.Errorf("HostKeyAlgorithmsFor(%q) boş — x/crypto varsayılanına düşer", f)
			continue
		}
		for _, a := range got {
			if !slices.Contains(HostKeyAlgorithms, a) {
				t.Errorf("HostKeyAlgorithmsFor(%q) = %v: %q tarama listesinde YOK "+
					"— pinlenen hedefle el sıkışılamaz", f, got, a)
			}
			covered[a] = true
		}
	}

	for _, a := range HostKeyAlgorithms {
		if !covered[a] {
			t.Errorf("tarama %q sunuyor ama hiçbir pin türünden türemiyor", a)
		}
	}
}

/*
 * ⚠️ TAM LİSTE SINANIYOR, "İÇERİYOR MU" DEĞİL.
 *
 * Ölçüldü: listeye ssh-rsa'yı EKLEMEK ("eski hedefler de çalışsın")
 * uçtan uca testi geçiyor — x/crypto ortak algoritmayı istemcinin
 * listesini dıştan tarayarak buluyor ve rsa-sha2-512 yine kazanıyor.
 * Yani politikayı ayakta tutan şey bu eşitlik iddiası.
 */
func TestHostKeyAlgorithmsForRSA(t *testing.T) {
	got := HostKeyAlgorithmsFor(ssh.KeyAlgoRSA)
	want := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	if !slices.Equal(got, want) {
		t.Fatalf("HostKeyAlgorithmsFor(ssh-rsa) = %v, beklenen %v — "+
			"SHA-1 geri gelirse taşımadan çıkarılmış olmasının anlamı kalmaz",
			got, want)
	}
}
