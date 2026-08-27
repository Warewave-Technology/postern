package main

import (
	"context"
	"fmt"

	"github.com/warewave/postern/internal/store"
)

// CLI değişikliklerinin denetim kaydı.
//
// ⚠️ NEDEN VAR: CLI'dan yapılan HİÇBİR değişiklik admin_log'a
// düşmüyordu — `user modify --admin` dahil. Yani tasarımın bilerek
// yalnızca CLI'ya emanet ettiği tek yetki devri, sistemde iz
// bırakmayan tek işlemdi. Panelden yapılan her değişiklik
// denetlenirken, en ayrıcalıklı olanı denetlenmiyordu.
//
// Aktör, süreci çalıştıran işletim sistemi kullanıcısı: yetki modeli
// zaten dosya erişimine dayanıyor (S3 sözleşmesi).

// auditCLI, bir CLI değişikliğini denetim kaydına yazar.
//
// Hata YUTULMUYOR: izlenemeyen bir değişiklik, yapılmamış bir
// değişiklikten daha kötü — operatör yaptığını sanır, kayıt onu
// göstermez. Çağıranlar hatayı yukarı taşıyor.
func auditCLI(ctx context.Context, db *store.Store, action, entity, details string) error {
	err := db.LogAdmin(ctx, store.AdminLogEntry{
		Actor:   cliActor(),
		Via:     "cli",
		Action:  action,
		Entity:  entity,
		Details: details,
	})
	if err != nil {
		return fmt.Errorf("audit write failed for %s %s: %w", action, entity, err)
	}
	return nil
}
