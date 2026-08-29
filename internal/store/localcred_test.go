package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestLocalCredentialRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLocalCredential(ctx, "ops", "argon2id$deneme", "yigit"); err != nil {
		t.Fatal(err)
	}

	v, err := s.LocalCredential(ctx, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if v != "argon2id$deneme" {
		t.Fatalf("doğrulayıcı = %q", v)
	}

	holders, err := s.LocalCredentialHolders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(holders) != 1 || holders[0].Username != "ops" || holders[0].CreatedBy != "yigit" {
		t.Fatalf("sahipler = %+v", holders)
	}
	if !holders[0].LastUsedAt.IsZero() {
		t.Error("hiç kullanılmamış kimlik bilgisi için son kullanım damgası var")
	}

	when := time.Now()
	if err := s.TouchLocalCredential(ctx, "ops", when); err != nil {
		t.Fatal(err)
	}
	holders, err = s.LocalCredentialHolders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if holders[0].LastUsedAt.IsZero() {
		t.Error("kullanımdan sonra damga yazılmamış")
	}
}

/*
 * ⚠️ İKİNCİ KEZ ÇALIŞTIRMAK MEVCUT SIRRI GEÇERSİZ KILMAMALI.
 *
 * Üstüne yazan bir uygulama, komutu tekrar çalıştıran operatörün
 * ELİNDEKİ sırrı sessizce çöpe atardı — üstelik o an ekranda yeni bir
 * sır gördüğü için fark etmeden. Daha kötüsü, veritabanına yazabilen
 * herkes kurulumun tek yöneticisinin kimlik bilgisini böylece
 * döndürebilirdi.
 */
func TestAddLocalCredentialRefusesToOverwrite(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLocalCredential(ctx, "ops", "birinci", "yigit"); err != nil {
		t.Fatal(err)
	}

	err := s.AddLocalCredential(ctx, "ops", "ikinci", "saldirgan")
	if !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("hata = %v, ErrCredentialExists bekleniyordu", err)
	}

	v, err := s.LocalCredential(ctx, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if v != "birinci" {
		t.Fatalf("doğrulayıcı ezilmiş: %q", v)
	}
}

func TestLocalCredentialRemoval(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveLocalCredential(ctx, "ops"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("olmayan kimlik bilgisi silinince: %v", err)
	}
	if err := s.AddLocalCredential(ctx, "ops", "v", "yigit"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveLocalCredential(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LocalCredential(ctx, "ops"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("silindikten sonra: %v", err)
	}
	// Hesabın kendisi durmalı: kimlik bilgisi gitti, denetim izi değil.
	if _, err := s.User(ctx, "ops"); err != nil {
		t.Fatalf("kimlik bilgisiyle birlikte hesap da silinmiş: %v", err)
	}
}

// testPubKeyBlob, teste özgü bir açık anahtar üretir.
func testPubKeyBlob(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub.Marshal()
}

/*
 * ⚠️ SİL-VE-EKLE KURALI ATLATAMAMALI.
 *
 * Kural "ilk anahtar serbest, sonrakiler yeniden kimlik doğrulama
 * ister" diye konuldu. Saf gerçekleştirme "şu an anahtarın var mı" diye
 * sorardı; o hâlde panel oturumunu ele geçiren biri mevcut anahtarı
 * siler, sayaç sıfıra döner ve kendi anahtarını bedavaya ekler — kural
 * tamamen delinir. Kapı bu yüzden SAYIYA değil, bir kez konan DAMGAYA
 * bakıyor. Test tam olarak o saldırı sırasını yürütüyor.
 */
func TestFirstKeyStampSurvivesRemoval(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "yigit@warewave.io", "yigit"); err != nil {
		t.Fatal(err)
	}
	if stamped, err := s.FirstKeyAdded(ctx, "yigit"); err != nil {
		t.Fatal(err)
	} else if stamped {
		t.Fatal("yeni hesap damgalı geldi: ilk anahtar serbest olmalıydı")
	}

	blob := testPubKeyBlob(t)
	if err := s.AddPublicKey(ctx, "yigit", blob, "ilk"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkFirstKeyAdded(ctx, "yigit", time.Now()); err != nil {
		t.Fatal(err)
	}

	// Saldırı sırası: sil, sayaç sıfırlansın, yeniden ekle.
	if err := s.RemovePublicKey(ctx, "yigit", blob); err != nil {
		t.Fatal(err)
	}
	keys, err := s.PublicKeys(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("anahtar silinmemiş: %d", len(keys))
	}

	stamped, err := s.FirstKeyAdded(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if !stamped {
		t.Fatal("silme damgayı kaldırdı — sil-ve-ekle kuralı atlatır")
	}
}

// Damga bir kez konuyor: sonraki çağrılar ilk anın üstüne yazmamalı.
func TestFirstKeyStampIsNotMoved(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := s.MarkFirstKeyAdded(ctx, "ayse", old); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkFirstKeyAdded(ctx, "ayse", time.Now()); err != nil {
		t.Fatal(err)
	}

	var at sql.NullInt64
	if err := s.db.QueryRowContext(ctx,
		`SELECT first_key_added_at FROM users WHERE username = 'ayse';`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if !at.Valid || at.Int64 != old.Unix() {
		t.Fatalf("damga kaymış: %v (beklenen %d)", at, old.Unix())
	}
}
