package httpapi

/*
 * Uçtan uca WebAuthn töreni: yazılım doğrulayıcısıyla kayıt ve giriş.
 *
 * ⚠️ BU DOSYA OLMADIĞI İÇİN GİRİŞ TAMAMEN KIRIK YAYINLANDI.
 *
 * Bu paketteki öbür WebAuthn testleri kapının ÖNÜNÜ sınıyor: anahtar var
 * mı, kod kabul ediliyor mu, meydan okuma dönüyor mu. Hiçbiri imza
 * ATMIYOR — çünkü imza atmak için özel anahtar gerekiyordu ve biz o işi
 * "tarayıcı yapar" diye bıraktık. Sonuç: doğrulanmış bir imzanın
 * geçtiği yol hiç koşulmadı ve kayıtta bildirilen bayrakları
 * saklamadığımız ortaya ancak gerçek bir Touch ID denemesinde çıktı —
 * BE=1 bildiren her doğrulayıcı "bu güvenlik anahtarı kabul edilmedi"
 * alıyordu, yani anahtarını bağlayan herkes kendi hesabından kilitlendi.
 *
 * Buradaki doğrulayıcı bir sahtekârlık değil: gerçek bir anahtarın
 * ürettiği baytların aynısını üretiyor (authData + clientDataJSON
 * özetinin ES256 imzası). Kütüphane onu gerçek bir anahtardan ayırt
 * edemiyor, dolayısıyla geçmesi gereken yol gerçekten koşuyor.
 */

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Warewave-Technology/postern/internal/store"
)

const (
	testRPID   = "postern.example.com"
	testOrigin = "https://postern.example.com"

	// Touch ID ve senkron passkey'lerin bildirdiği bayraklar: kullanıcı
	// orada, doğrulandı, anahtar yedeklenebilir ve yedeklenmiş.
	flagsSyncedPasskey = protocol.FlagUserPresent | protocol.FlagUserVerified |
		protocol.FlagBackupEligible | protocol.FlagBackupState

	// Yedeklenemeyen bir donanım anahtarı (USB): yalnızca UP ve UV.
	flagsHardwareKey = protocol.FlagUserPresent | protocol.FlagUserVerified
)

// softKey, testlerde gerçek bir doğrulayıcının yerine geçen ES256 anahtarı.
type softKey struct {
	priv    *ecdsa.PrivateKey
	id      []byte
	aaguid  []byte
	flags   protocol.AuthenticatorFlags
	counter uint32
}

func newSoftKey(t *testing.T, flags protocol.AuthenticatorFlags) *softKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("anahtar üretilemedi: %v", err)
	}

	return &softKey{
		priv:    priv,
		id:      []byte("postern-test-credential"),
		aaguid:  make([]byte, 16),
		flags:   flags,
		counter: 1,
	}
}

// cose, açık anahtarın doğrulayıcının gönderdiği COSE gösterimi.
func (k *softKey) cose(t *testing.T) []byte {
	t.Helper()

	pub := k.priv.PublicKey
	key := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: pub.X.FillBytes(make([]byte, 32)),
		YCoord: pub.Y.FillBytes(make([]byte, 32)),
	}

	b, err := webauthncbor.Marshal(key)
	if err != nil {
		t.Fatalf("COSE anahtarı yazılamadı: %v", err)
	}

	return b
}

/*
 * authData, doğrulayıcının imzaladığı veri.
 *
 * Biçim şartnamede sabit: rpIdHash(32) || flags(1) || counter(4) ve
 * kayıtta ayrıca aaguid(16) || kimlik uzunluğu(2) || kimlik || COSE
 * anahtarı. Bayrakların TAM OLARAK burada taşındığına dikkat — girişte
 * gelen bu sekizli, kayıtta sakladığımızla karşılaştırılıyor.
 */
func (k *softKey) authData(t *testing.T, withCredential bool) []byte {
	t.Helper()

	sum := sha256.Sum256([]byte(testRPID))
	out := make([]byte, 0, 128)
	out = append(out, sum[:]...)

	flags := k.flags
	if withCredential {
		flags |= protocol.FlagAttestedCredentialData
	}
	out = append(out, byte(flags))

	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, k.counter)
	out = append(out, counter...)

	if withCredential {
		out = append(out, k.aaguid...)
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, uint16(len(k.id)))
		out = append(out, length...)
		out = append(out, k.id...)
		out = append(out, k.cose(t)...)
	}

	return out
}

// clientData, tarayıcının ürettiği bağlam: tören türü, meydan okuma, köken.
func clientData(t *testing.T, kind, challenge string) []byte {
	t.Helper()

	b, err := json.Marshal(map[string]any{
		"type":        kind,
		"challenge":   challenge,
		"origin":      testOrigin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("clientData yazılamadı: %v", err)
	}

	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("JSON yazılamadı: %v", err)
	}

	return b
}

// register, kayıt töreninin doğrulayıcı tarafını oynar.
func (k *softKey) register(t *testing.T, challenge string) json.RawMessage {
	t.Helper()

	attestation, err := webauthncbor.Marshal(map[string]any{
		// ⚠️ "none" GERÇEK BİR BİÇİM, KAÇAMAK DEĞİL: platform anahtarları
		// varsayılan olarak kanıt göndermiyor ve postern kanıt istemiyor.
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": k.authData(t, true),
	})
	if err != nil {
		t.Fatalf("attestation yazılamadı: %v", err)
	}

	return mustJSON(t, map[string]any{
		"id":    b64(k.id),
		"rawId": b64(k.id),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData(t, "webauthn.create", challenge)),
			"attestationObject": b64(attestation),
		},
	})
}

// assert, giriş töreninin doğrulayıcı tarafını oynar: imzayı burası atıyor.
func (k *softKey) assert(t *testing.T, challenge string) json.RawMessage {
	t.Helper()

	// ⚠️ SAYAÇ HER İMZADA ARTIYOR — klon sezgisinin dayandığı davranış.
	k.counter++

	data := k.authData(t, false)
	client := clientData(t, "webauthn.get", challenge)
	clientHash := sha256.Sum256(client)

	signed := append(append([]byte{}, data...), clientHash[:]...)
	digest := sha256.Sum256(signed)

	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatalf("imza atılamadı: %v", err)
	}

	return mustJSON(t, map[string]any{
		"id":    b64(k.id),
		"rawId": b64(k.id),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(client),
			"authenticatorData": b64(data),
			"signature":         b64(sig),
		},
	})
}

// enrolled, hesabı açıp verilen doğrulayıcıyı GERÇEK uçlardan kaydeder.
func enrolled(t *testing.T, key *softKey) (*Server, *store.Store, string) {
	t.Helper()

	s, db, dsn := dbServerDSN(t)
	s.SetExternalURL(testOrigin)

	if _, err := db.CreateUser(t.Context(), "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}

	// Kayıt başlat: meydan okumayı sunucu üretiyor.
	w := httptest.NewRecorder()
	s.handleWebAuthnBegin(w, fresh(t, s, "{}"))
	if w.Code != http.StatusOK {
		t.Fatalf("kayıt başlatılamadı: %d %s", w.Code, w.Body.String())
	}

	var options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &options); err != nil {
		t.Fatal(err)
	}
	if options.PublicKey.Challenge == "" {
		t.Fatalf("meydan okuma boş: %s", w.Body.String())
	}

	body := mustJSON(t, map[string]any{
		"name":       "iş dizüstü",
		"credential": key.register(t, options.PublicKey.Challenge),
	})

	w = httptest.NewRecorder()
	s.handleWebAuthnFinish(w, fresh(t, s, string(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("KAYIT REDDEDİLDİ: %d %s", w.Code, w.Body.String())
	}

	return s, db, dsn
}

// forgetFlags, satırı göç 040 öncesi duruma döndürür: bayraklar bilinmiyor.
func forgetFlags(t *testing.T, dsn string) {
	t.Helper()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	res, err := db.Exec(`UPDATE webauthn_credentials SET flags = NULL;`)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		t.Fatal("bayrağı silinecek satır yok: test ölçmek istediğini ölçmüyor")
	}
}

// fresh, oturumu taze sayılan bir istek kurar: kayıt uçları bunu istiyor.
func fresh(t *testing.T, s *Server, body string) *http.Request {
	t.Helper()

	token, err := s.webSessions.CreateLocal("ayse", "ayse")
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/api/me/webauthn", strings.NewReader(body))
	r.RemoteAddr = "203.0.113.9:5555"
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})

	return r.WithContext(context.WithValue(r.Context(), ctxUser, "ayse"))
}

// signIn, ikinci faktör kapısını bir imzayla geçmeyi dener.
func signIn(t *testing.T, s *Server, key *softKey) (bool, *httptest.ResponseRecorder) {
	t.Helper()

	// İlk istek imzasız: sunucu meydan okumayı burada veriyor.
	w, body := factor(t, s, "", "")
	options, ok := body["options"].(map[string]any)
	if !ok {
		t.Fatalf("meydan okuma dönmedi: %d %s", w.Code, w.Body.String())
	}
	pk, _ := options["publicKey"].(map[string]any)
	challenge, _ := pk["challenge"].(string)
	if challenge == "" {
		t.Fatalf("meydan okuma boş: %s", w.Body.String())
	}

	r := httptest.NewRequest(http.MethodPost, "/auth/local", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	w = httptest.NewRecorder()

	return s.secondFactor(w, r, "ayse", key.assert(t, challenge), ""), w
}

/*
 * ⚠️ YEDEKLENEBİLİR BİR ANAHTAR GİRİŞ YAPABİLMELİ.
 *
 * Bu testin sınadığı şey tek cümle: kayıtta bildirilen bayraklar
 * saklanıyor mu. Saklanmadığı sürümde kütüphane, imzadaki BE=1 ile
 * kayıttaki sıfır değeri karşılaştırıp "Backup Eligible flag
 * inconsistency" diyor ve giriş HER SEFERİNDE düşüyor — hesabı yalnızca
 * anahtara bağlamış bir kişi için bu, paneline bir daha girememek
 * demek. Gerçek bir Touch ID ile ölçüldü.
 */
func TestASyncedPasskeySignsIn(t *testing.T) {
	key := newSoftKey(t, flagsSyncedPasskey)
	s, db, _ := enrolled(t, key)

	ok, w := signIn(t, s, key)
	if !ok {
		t.Fatalf("YEDEKLENEBİLİR ANAHTAR GİREMEDİ: %d %s", w.Code, w.Body.String())
	}

	// Sayaç ve bayraklar başarılı imzadan sonra kayda yazılıyor.
	creds, err := db.WebAuthnCredentials(t.Context(), "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if !creds[0].FlagsKnown {
		t.Error("giriş sonrası bayraklar 'bilinmiyor' kaldı")
	}
	if creds[0].SignCount != key.counter {
		t.Errorf("sayaç = %d, %d bekleniyordu", creds[0].SignCount, key.counter)
	}
	if creds[0].LastUsedAt.IsZero() {
		t.Error("son kullanım yazılmadı")
	}
}

/*
 * ⚠️ YEDEKLENEMEYEN BİR ANAHTAR DA GİREBİLMELİ.
 *
 * Bayrakları saklamanın kolay ve YANLIŞ yolu, "hepsini açık say"
 * demekti: yedeklenebilir passkey'ler düzelir, USB anahtarlar bu kez
 * ters yönde kırılırdı. İki doğrulayıcı türü ayrı ayrı koşuyor, çünkü
 * tek yönlü bir düzeltme ikisinden birini sessizce dışarıda bırakır.
 */
func TestAHardwareKeyThatCannotBeBackedUpSignsIn(t *testing.T) {
	key := newSoftKey(t, flagsHardwareKey)
	s, _, _ := enrolled(t, key)

	if ok, w := signIn(t, s, key); !ok {
		t.Fatalf("DONANIM ANAHTARI GİREMEDİ: %d %s", w.Code, w.Body.String())
	}
}

/*
 * ⚠️ BAYRAKLARI SAKLANMAMIŞ ESKİ SATIR DA GİREBİLMELİ.
 *
 * Göç 040'tan önce kaydolmuş anahtarların satırında bayrak yok.
 * "Bilinmiyor"u sıfır saymak, tam olarak düzelttiğimiz hatayı o kişiler
 * için sürdürürdü: yükseltmeden sonra girişleri reddedilir ve çıkış
 * yolu yalnızca `postern admin reset-webauthn` olurdu. İlk başarılı
 * imzada değer kabul ediliyor ve SATIRA YAZILIYOR; sonraki girişlerde
 * artık karşılaştırılıyor.
 */
func TestAKeyEnrolledBeforeFlagsWereStoredStillSignsIn(t *testing.T) {
	key := newSoftKey(t, flagsSyncedPasskey)
	s, db, dsn := enrolled(t, key)

	forgetFlags(t, dsn)

	if ok, w := signIn(t, s, key); !ok {
		t.Fatalf("ESKİ SATIR GİREMEDİ: %d %s", w.Code, w.Body.String())
	}

	creds, err := db.WebAuthnCredentials(t.Context(), "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if !creds[0].FlagsKnown {
		t.Error("BAYRAKLAR YAZILMADI: eski satır bir sonraki girişte de karşılaştırılamayacak")
	}
}

/*
 * ⚠️ HAM SEKİZLİ BOŞSA BAYRAKLAR YİNE DE YAZILMALI.
 *
 * Kütüphanenin CredentialFlags'ında ham değer yalnızca kayıt kendi
 * yapıcısından geçtiğinde doluyor. Elle kurulmuş (ya da ileride başka
 * bir yoldan gelen) bir kayıtta sıfır kalır ve biz "hiçbir bayrak yok"
 * yazardık — yani tam olarak düzelttiğimiz hatayı, bu kez sessizce geri
 * getirirdik. Bu yol gerçek bir törenden geçmiyor, o yüzden ayrıca
 * sınanıyor.
 */
func TestFlagsAreWrittenEvenWhenTheRawOctetIsMissing(t *testing.T) {
	got := flagsByte(webauthn.CredentialFlags{
		UserPresent:    true,
		UserVerified:   true,
		BackupEligible: true,
		BackupState:    true,
	})

	want := byte(flagsSyncedPasskey)
	if got != want {
		t.Errorf("bayraklar = %#02x, %#02x bekleniyordu", got, want)
	}
}

/*
 * ⚠️ BAŞKA BİR ANAHTARIN İMZASI GEÇMEMELİ.
 *
 * Yukarıdaki testler "geçmesi gereken geçiyor mu" diye soruyor;
 * doğrulamayı tamamen kaldırsak onlar da geçerdi. Bu test öbür yönü
 * tutuyor: aynı kimlikle ama BAŞKA özel anahtarla atılmış bir imza
 * reddedilmeli.
 */
func TestASignatureFromADifferentKeyIsRejected(t *testing.T) {
	key := newSoftKey(t, flagsSyncedPasskey)
	s, _, _ := enrolled(t, key)

	impostor := newSoftKey(t, flagsSyncedPasskey)
	impostor.id = key.id

	ok, w := signIn(t, s, impostor)
	if ok {
		t.Fatal("BAŞKA ANAHTARIN İMZASI KABUL EDİLDİ")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("durum = %d, 401 bekleniyordu", w.Code)
	}
}
