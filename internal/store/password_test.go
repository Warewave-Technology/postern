package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

/*
 * ⚠️ POSTERN'İN EN KESKİN İDDİASININ TESTİ.
 *
 * Kural: bir YÖNETİCİ hesabı asla kullanıcı parolası tutamaz. Sebebi
 * kolaylık değil — acil durum kapısı tahmin edilebilir bir değere
 * bağlanamaz. "Her şey bozulduğunda içeri girilir" iddiası tamamen buna
 * dayanıyor.
 *
 * Kuralı VERİTABANI tutuyor (göç 026), uygulama katmanındaki bir if
 * değil. Bu test onu HER KAPIDAN deniyor, çünkü bir sonraki çağrı yolu
 * yazıldığında koruma orada da duruyor olmalı.
 */
func TestAdminAccountCanNeverHoldAPassword(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAdmin(ctx, "ops", true); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLocalCredential(ctx, "ops", "argon2id$sir", "cli"); err != nil {
		t.Fatal(err)
	}

	// KAPI 1: yöneticinin kendisi parola koymaya çalışıyor.
	err := s.SetChosenPassword(ctx, "ops", "argon2id$parola", time.Now())
	if !errors.Is(err, ErrAdminPasswordRefused) {
		t.Fatalf("yönetici parola koyabildi (ya da hata yanlış): %v", err)
	}

	// KAPI 2: panelden kimlik bilgisi verilmeye çalışılıyor.
	if _, err := s.ReplaceLocalCredential(ctx, "ops", "argon2id$panelden", "yigit"); err == nil {
		t.Fatal("panelden yönetici hesabına kimlik bilgisi verilebildi")
	}

	// Sır DURUYOR: reddedilen bir işlem, çalışan acil durum kapısını
	// bozmamalı.
	c, err := s.LocalCredential(ctx, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if c.Verifier != "argon2id$sir" {
		t.Fatalf("acil durum sırrı değişmiş: %q", c.Verifier)
	}
	if c.Chosen {
		t.Fatal("yöneticinin kimlik bilgisi parola olarak işaretlenmiş")
	}
	if c.MustChange {
		t.Fatal("yönetici 'değiştirmek zorunda' işaretini almış — " +
			"değiştiremediği için hesabı kalıcı kilitlenirdi")
	}
}

/*
 * ⚠️ TERS YÖN: PAROLA TUTAN BİRİ YÖNETİCİ YAPILIRSA.
 *
 * Kural burada REDDETMEK değil PAROLAYI DÜŞÜRMEK. Reddetmek, dizin
 * grubundan gelen toplu eşitlemede tek bir kişinin parolası yüzünden
 * TÜM kurulumun yönetici eşitlemesini durdururdu.
 */
func TestPromotingAPasswordHolderDropsThePassword(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLocalCredential(ctx, "ayse", "argon2id$verildi", "yigit"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetChosenPassword(ctx, "ayse", "argon2id$parola", time.Now()); err != nil {
		t.Fatal(err)
	}

	// Yükseltme DÜŞMÜYOR.
	if err := s.SetUserAdmin(ctx, "ayse", true); err != nil {
		t.Fatalf("parola tutan hesabın yükseltilmesi düştü: %v", err)
	}

	u, err := s.User(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if !u.Admin {
		t.Fatal("yükseltme yapılmamış")
	}
	// Parola gitmiş olmalı: yönetici artık acil durum sırrıyla girecek.
	if _, err := s.LocalCredential(ctx, "ayse"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("parola yönetici olduktan sonra da duruyor: %v", err)
	}
}

// Grup üzerinden yükseltmede de aynı davranış — ve toplu yol, tek bir
// kişi yüzünden TAMAMEN durmamalı.
func TestGroupPromotionDropsPasswordsWithoutStoppingTheSync(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, n := range []string{"ayse", "deniz", "kerem"} {
		if _, err := s.CreateUser(ctx, n, n+"@warewave.io", n); err != nil {
			t.Fatal(err)
		}
	}
	// Ortadaki kişinin parolası var.
	if err := s.AddLocalCredential(ctx, "deniz", "argon2id$verildi", "yigit"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetChosenPassword(ctx, "deniz", "argon2id$parola", time.Now()); err != nil {
		t.Fatal(err)
	}

	granted, _, err := s.ApplyAdminGroup(ctx, []string{"ayse", "deniz", "kerem"})
	if err != nil {
		t.Fatalf("toplu eşitleme düştü — bir kişinin parolası tüm kurulumu durdurdu: %v", err)
	}
	if len(granted) != 3 {
		t.Fatalf("yükseltilen = %v, üçü de bekleniyordu", granted)
	}
	if _, err := s.LocalCredential(ctx, "deniz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("grup yükseltmesi parolayı düşürmedi: %v", err)
	}
}

/*
 * ⚠️ VERİLEN KİMLİK BİLGİSİ "DEĞİŞTİRİLMEK ZORUNDA" DOĞUYOR.
 *
 * Kapattığı somut açık: değeri üreten yönetici onu BİLİYOR. Kişi
 * değiştirene kadar hesap iki kişinin elinde. Yönetici hesaplarında bu
 * bayrak KONMUYOR, çünkü onlar parolaya hiç geçemiyor ve konsaydı hesap
 * "değiştir" ile "değiştiremezsin" arasında kilitlenirdi.
 */
func TestIssuedCredentialsDemandAChangeExceptForAdmins(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ayse", "a@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "ops", "o@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAdmin(ctx, "ops", true); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ayse", "ops"} {
		if err := s.AddLocalCredential(ctx, n, "argon2id$x", "cli"); err != nil {
			t.Fatal(err)
		}
	}

	ayse, err := s.LocalCredential(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if !ayse.MustChange {
		t.Error("sıradan kullanıcının kimlik bilgisi 'değiştir' istemiyor — " +
			"veren kişi değeri bilmeye devam ediyor")
	}
	ops, err := s.LocalCredential(ctx, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if ops.MustChange {
		t.Error("yönetici 'değiştir' istiyor ama değiştiremez — kilitlenir")
	}
}

/*
 * Panelden verme: var olanın ÜSTÜNE yazıyor.
 *
 * ⚠️ AddLocalCredential'ın üstüne yazmama kuralı burada geçerli DEĞİL
 * ve olmamalı: "kullanıcı parolasını unuttu" panelden çözülemezse,
 * özelliğin var olma sebebi ilk gerçek olayda çöker. Yöneticiye
 * dokunulamaması o korumanın devamı.
 */
func TestPanelIssueReplacesAndResetsToAnUnchosenValue(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ayse", "a@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}

	replaced, err := s.ReplaceLocalCredential(ctx, "ayse", "argon2id$bir", "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if replaced {
		t.Error("ilk verişte 'üstüne yazıldı' denmiş")
	}

	// Kullanıcı parolasını koydu.
	if err := s.SetChosenPassword(ctx, "ayse", "argon2id$parola", time.Now()); err != nil {
		t.Fatal(err)
	}

	// Unuttu: yönetici panelden yeniden veriyor.
	replaced, err = s.ReplaceLocalCredential(ctx, "ayse", "argon2id$iki", "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if !replaced {
		t.Error("üstüne yazıldığı bildirilmedi — denetim kaydı yanlış olay yazar")
	}

	c, err := s.LocalCredential(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if c.Verifier != "argon2id$iki" {
		t.Fatalf("doğrulayıcı güncellenmemiş: %q", c.Verifier)
	}
	if c.Chosen {
		t.Error("yeni değer 'kullanıcı seçti' sayılıyor — " +
			"makine üretimi bir değer biçim kontrolüne uğramadan kabul edilirdi")
	}
	if !c.MustChange {
		t.Error("yeniden verilen değer 'değiştir' istemiyor")
	}
}

// Silinen hesabın parola özeti de gidiyor: hesabı bittikten sonra
// saklanan bir kişisel veri kalmamalı.
func TestPurgeRemovesTheCredential(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ayse", "a@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLocalCredential(ctx, "ayse", "argon2id$x", "cli"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetChosenPassword(ctx, "ayse", "argon2id$parola", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountState(ctx, "ayse", StateDeleted); err != nil {
		t.Fatal(err)
	}
	// Kullanıcı ID'si purge'den ÖNCE alınıyor: purge adı serbest
	// bırakıyor, yani sonrasında adla arama zaten bulamaz.
	var id string
	if err := s.db.QueryRowContext(ctx,
		`SELECT id FROM users WHERE username = $1;`, "ayse").Scan(&id); err != nil {
		t.Fatal(err)
	}

	if _, err := s.PurgeAccount(ctx, "ayse", time.Now()); err != nil {
		t.Fatal(err)
	}

	/*
	 * ⚠️ SATIRA ID İLE BAKIYORUZ, ADLA DEĞİL.
	 *
	 * Adla bakan ilk hâli MUTASYON TESTİNİ GEÇTİ ve bu doğruydu:
	 * purge kullanıcı adını serbest bırakıyor, dolayısıyla adla yapılan
	 * arama kimlik bilgisi silinmese de ErrNotFound döner. Test, silmeyi
	 * değil ad değişimini ölçüyordu.
	 */
	var left int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM local_credentials WHERE user_id = $1;`, id).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatal("purge sonrası parola özeti duruyor — " +
			"hesabı bitmiş bir kişinin parolası saklanmaya devam ediyor")
	}
}

/*
 * ⚠️ PANELDEN VERİLEN DEĞER, YÖNETİCİ OLUNCA DA KALMAMALI.
 *
 * Bu testin kapattığı saldırı tamamen PANELDEN yürüyor ve host'a hiç
 * dokunmuyor:
 *
 *   1. Yönetici, sıradan bir hesaba panelden giriş bilgisi verir.
 *      Değer makine üretimi — yani "parola" değil — ama VEREN KİŞİ onu
 *      biliyor.
 *   2. Aynı yönetici, panelden dizin yönetici grubunu o kişiyi
 *      kapsayacak şekilde değiştirir (017'den beri mümkün).
 *   3. Kişi yönetici olur ve kimlik bilgisi hâlâ ilk yöneticinin
 *      bildiği değerdir.
 *
 * Yani paneli ele geçiren biri, sırrını bildiği bir yönetici üretir ve
 * acil durum kapısının tüm anlamı gider. Ölçüt değerin TÜRÜ değil
 * KAYNAĞI: yöneticinin kimlik bilgisi HOST'TAN çıkmış olmak zorunda.
 */
func TestPromotionDropsPanelIssuedSecretsToo(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ayse", "a@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	// Panelden verildi: created_by = yöneticinin adı, 'cli' DEĞİL.
	// Kullanıcı henüz değiştirmedi, yani hâlâ makine üretimi bir sır.
	if _, err := s.ReplaceLocalCredential(ctx, "ayse", "argon2id$panelden", "yigit"); err != nil {
		t.Fatal(err)
	}

	if err := s.SetUserAdmin(ctx, "ayse", true); err != nil {
		t.Fatalf("yükseltme düştü: %v", err)
	}

	if _, err := s.LocalCredential(ctx, "ayse"); !errors.Is(err, ErrNotFound) {
		t.Fatal("panelden verilen sır, hesap yönetici olduktan sonra da duruyor — " +
			"paneli ele geçiren kişi sırrını bildiği bir yönetici üretebilir")
	}
}

// Host'tan çıkmış sır yükseltmede KALIYOR: acil durum kapısının olması
// gereken hâli bu, ve yanlışlıkla silmek yöneticiyi dışarıda bırakırdı.
func TestPromotionKeepsTheHostIssuedSecret(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ops", "o@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLocalCredential(ctx, "ops", "argon2id$hosttan", "cli"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAdmin(ctx, "ops", true); err != nil {
		t.Fatal(err)
	}

	c, err := s.LocalCredential(ctx, "ops")
	if err != nil {
		t.Fatalf("host'tan verilen sır yükseltmede silinmiş: %v", err)
	}
	if c.Verifier != "argon2id$hosttan" {
		t.Fatalf("doğrulayıcı değişmiş: %q", c.Verifier)
	}
}
