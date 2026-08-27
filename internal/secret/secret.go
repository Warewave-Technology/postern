// Package secret seals configuration secrets at rest.
//
// NE YAPAR: veritabanına yazılacak sırları (LDAP servis hesabı parolası
// gibi) AES-256-GCM ile mühürler. Anahtar AYRI bir dosyada durur.
//
// NE YAPMAZ — ve bunu net söylemek önemli: sunucuyu ele geçiren birine
// karşı koruma sağlamaz. O kişi hem veritabanını hem anahtar dosyasını
// okuyabilir. Bu paketin koruduğu senaryo veritabanı KOPYASININ
// sızmasıdır: yedek, hata ayıklama için alınan döküm, yanlışlıkla
// paylaşılan dosya. Anahtar o kopyalarda olmadığı için sır da açılmaz.
//
// "Anahtarı nerede saklayacağız" sorusu sonsuza kadar geriye gider (ana
// anahtarı şifreleyen anahtar...). Zincir bir yerde dosya sistemi
// izinlerine dayanmak zorunda; biz orada duruyoruz ve iddiayı da o kadar
// tutuyoruz.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ErrNotSealed: mühürlü olmayan ya da bozulmuş bir değer açılmaya çalışıldı.
var ErrNotSealed = errors.New("secret: value is not sealed or is corrupt")

// keySize, AES-256 için 32 bayt.
const keySize = 32

// Box, mühürleme/çözme işlemlerini yapan anahtar sahibi.
type Box struct {
	aead cipher.AEAD
}

// Init, yeni bir ana anahtar üretip path'e yazar ve Box döner.
//
// Dosya O_EXCL ile açılır: var olan anahtarın ÜSTÜNE YAZMAK, o anahtarla
// mühürlenmiş bütün sırları kalıcı olarak okunamaz yapardı — ca.Init'te
// verdiğimiz kararın aynısı, aynı sebeple.
func Init(path string) (*Box, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("secret.Init: %w", err)
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("secret.Init: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("secret.Init: %w", err)
	}
	defer f.Close()

	if _, err := f.Write([]byte(base64.StdEncoding.EncodeToString(key))); err != nil {
		return nil, fmt.Errorf("secret.Init: %w", err)
	}

	return newBox(key)
}

// Load, var olan ana anahtarı okur.
//
// İzin kontrolü ca.Load'daki ile aynı: grup ya da diğerleri okuyabiliyorsa
// anahtar zaten sır değildir. Sessizce düzeltmek yerine REDDEDİYORUZ —
// operatör neyin yanlış olduğunu bilsin.
func Load(path string) (*Box, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("secret.Load: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("secret.Load: %s is group/world readable (%04o); chmod 600 it", path, perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secret.Load: %w", err)
	}

	key, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("secret.Load: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("secret.Load: key is %d bytes, want %d", len(key), keySize)
	}

	return newBox(key)
}

func newBox(key []byte) (*Box, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	return &Box{aead: aead}, nil
}

// Seal, düz metni mühürler. Çıktı base64(nonce || ciphertext+tag).
//
// Nonce her çağrıda TAZE: GCM'de aynı anahtar+nonce çiftini iki kez
// kullanmak şifrelemeyi çökertir. Çıktının başına yazılıyor çünkü açarken
// gerekiyor ve gizli değil.
func (b *Box) Seal(plaintext string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("secret.Seal: %w", err)
	}

	sealed := b.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Unseal, mühürlü değeri açar.
//
// GCM kimlik doğrulamalı: değiştirilmiş bir şifreli metin sessizce yanlış
// düz metin ÜRETMEZ, hata verir. Yani bu fonksiyonun başarısı aynı
// zamanda "bu değer bozulmamış" kanıtıdır.
func (b *Box) Unseal(sealed string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("secret.Unseal: %w", ErrNotSealed)
	}

	nonceSize := b.aead.NonceSize()
	if len(raw) < nonceSize {
		return "", fmt.Errorf("secret.Unseal: %w", ErrNotSealed)
	}

	plaintext, err := b.aead.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
	if err != nil {
		// Sebebi AYIRT ETMİYORUZ: yanlış anahtar mı, bozuk veri mi,
		// kurcalanmış mı — üçü de "bu değeri açamıyorum" demek ve farkı
		// söylemek saldırgana bilgi verir.
		return "", fmt.Errorf("secret.Unseal: %w", ErrNotSealed)
	}
	return string(plaintext), nil
}
