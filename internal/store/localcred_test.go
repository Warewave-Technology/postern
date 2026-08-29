package store

import (
	"context"
	"errors"
	"testing"
	"time"
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
