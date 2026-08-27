// Package groupsync decides what a directory synchronisation should do.
//
// Bu paketin varlık sebebi tek bir soru: dizinden gelen bilgiye bakarak
// KİMİN yetkisi iptal edilmeli? Cevabı yanlış vermek, bir LDAP
// kesintisinde şirketin tamamını dışarıda bırakmak demek.
//
// Karar mantığı BİLEREK saf: I/O yok, saat yok, veritabanı yok. Böylece
// "dizin çöktüğünde kimsenin yetkisi iptal edilmez" özelliği bir tablo
// testiyle milisaniyelerde ispatlanabiliyor — tartışılmak yerine.
package groupsync

import (
	"fmt"
	"time"

	"github.com/warewave/postern/internal/ldap"
)

// Observation, tek bir kullanıcı hakkında dizinden öğrenilenler.
type Observation struct {
	Username string

	// Presence, dizinin bu kullanıcı hakkında söylediği (üç değerli).
	Presence ldap.Presence

	// MappedRoles, dizindeki gruplarının karşılığı olan roller.
	// Presence != PresencePresent iken anlamsızdır.
	MappedRoles []string

	// MissingSince, bu kullanıcının İLK kez dizinde bulunamadığı an.
	// Sıfır ise şu ana kadar hep bulunmuş.
	MissingSince time.Time

	// ManualRoles, elle verilmiş rol sayısı. Senkronizasyon bunlara
	// DOKUNMAZ (bkz. göç 005) — ama rapor bunu ayrıca söylemeli, yoksa
	// operatör "iptal edildi" okuyup erişimin tamamen bittiğini sanar.
	ManualRoles int
}

// Limits, patlama yarıçapı tavanları.
type Limits struct {
	// Grace, kullanıcı dizinde bulunamadıktan sonra iptal için beklenen
	// süre. Kısa bir çoğaltma gecikmesi ya da bakım penceresi yetkileri
	// silmesin diye.
	Grace time.Duration

	// MaxZeroFraction / MinZeroFloor, "kaç kişi sıfır SSO rolüne
	// düşerse bu bir kesintidir" eşiği. İkisi BİRLİKTE aşılmalı: küçük
	// kurumlarda oran tek kişiyle aşılır, büyüklerinde taban tek başına
	// anlamsız kalır.
	MaxZeroFraction float64
	MinZeroFloor    int

	// MaxUnknownFraction, dizinin cevaplayamadığı kullanıcı oranı için
	// tavan. Aşılırsa dizin sağlıklı değildir ve hiçbir karar verilmez.
	MaxUnknownFraction float64

	// MaxRevokePerRun, tek koşuda iptal edilebilecek kullanıcı sayısı.
	MaxRevokePerRun int
}

// DefaultLimits, makul ve MUHAFAZAKÂR başlangıç değerleri.
func DefaultLimits() Limits {
	return Limits{
		Grace:              time.Hour,
		MaxZeroFraction:    0.10,
		MinZeroFloor:       3,
		MaxUnknownFraction: 0.25,
		MaxRevokePerRun:    25,
	}
}

// UserRoles, bir kullanıcıya uygulanacak yeni SSO rol kümesi.
type UserRoles struct {
	Username string
	Roles    []string

	// Revoking, bu uygulamanın kullanıcıyı SIFIR SSO rolüne düşürdüğünü
	// söyler — rapor ve denetim için.
	Revoking bool

	// ManualRoles, iptalden SONRA elinde kalan elle verilmiş rol sayısı.
	ManualRoles int
}

// Plan, bir senkronizasyon koşusunda ne yapılacağı.
type Plan struct {
	// Apply, uygulanacak rol kümeleri.
	Apply []UserRoles

	// Hold, dizinde bulunamayan ama Grace süresi dolmamış kullanıcılar.
	Hold []string

	// Unknown, dizinin cevaplayamadığı kullanıcılar. Bunlara DOKUNULMAZ.
	Unknown []string

	// Abort boş değilse HİÇBİR ŞEY uygulanmaz ve sebebi budur.
	Abort string
}

// BuildPlan, gözlemlerden bir koşu planı çıkarır.
//
// ⚠️ EN ÖNEMLİ TASARIM KARARI: "dizinde yok" ile "dizinde var ama artık
// hiçbir gruba üye değil" AYNI sayaçta toplanıyor.
//
// Sebebi somut: yarım geri yüklenmiş ya da eksik çoğaltılmış bir dizin
// kullanıcı aramasını düzgün cevaplar, grup aramasını BOŞ cevaplar. Kişi
// bazında bakan bir mantık bunu meşru bir iptal olarak okur ve herkesi
// siler. Yalnızca toplam sayaç bunu görebilir.
func BuildPlan(now time.Time, obs []Observation, limits Limits) Plan {
	var plan Plan

	total := len(obs)
	if total == 0 {
		return plan
	}

	unknown := 0
	zeroing := 0 // iptal EDİLECEK ya da sıfıra düşecek olanlar

	for _, o := range obs {
		switch o.Presence {
		case ldap.PresenceUnknown:
			unknown++
		case ldap.PresenceAbsent:
			zeroing++
		case ldap.PresencePresent:
			if len(o.MappedRoles) == 0 {
				zeroing++
			}
		}
	}

	// 1) Dizin sağlıklı mı? Değilse hiçbir karar verilmez.
	if frac := float64(unknown) / float64(total); frac > limits.MaxUnknownFraction {
		return Plan{Abort: fmt.Sprintf(
			"directory could not answer for %d of %d users (%.0f%%, ceiling %.0f%%)",
			unknown, total, frac*100, limits.MaxUnknownFraction*100)}
	}

	// 2) Toplu iptal görünümü var mı?
	if zeroing >= limits.MinZeroFloor {
		if frac := float64(zeroing) / float64(total); frac > limits.MaxZeroFraction {
			return Plan{Abort: fmt.Sprintf(
				"%d of %d users would lose all SSO roles (%.0f%%, ceiling %.0f%%); "+
					"this looks like a directory problem, not %d departures",
				zeroing, total, frac*100, limits.MaxZeroFraction*100, zeroing)}
		}
	}

	// 3) Kullanıcı bazında planla.
	revoking := 0
	for _, o := range obs {
		switch o.Presence {
		case ldap.PresenceUnknown:
			plan.Unknown = append(plan.Unknown, o.Username)

		case ldap.PresenceAbsent:
			// Grace penceresi: kısa bir çoğaltma gecikmesi yetkileri
			// silmesin. MissingSince sıfırsa bu, kullanıcının ilk kez
			// bulunamadığı koşu demektir — henüz bekleme başlamadı.
			if o.MissingSince.IsZero() || now.Sub(o.MissingSince) < limits.Grace {
				plan.Hold = append(plan.Hold, o.Username)
				continue
			}
			revoking++
			plan.Apply = append(plan.Apply, UserRoles{
				Username: o.Username, Roles: nil,
				Revoking: true, ManualRoles: o.ManualRoles,
			})

		case ldap.PresencePresent:
			ur := UserRoles{Username: o.Username, Roles: o.MappedRoles, ManualRoles: o.ManualRoles}
			if len(o.MappedRoles) == 0 {
				ur.Revoking = true
				revoking++
			}
			plan.Apply = append(plan.Apply, ur)
		}
	}

	// 4) Tek koşuda çok fazla iptal?
	if limits.MaxRevokePerRun > 0 && revoking > limits.MaxRevokePerRun {
		return Plan{Abort: fmt.Sprintf(
			"%d revocations exceeds max_revoke_per_run (%d)", revoking, limits.MaxRevokePerRun)}
	}

	return plan
}
