import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";

/*
 * VAR OLMAYAN CSS SINIFI — KÖK SEBEBİ KAPATAN KONTROL.
 *
 * ⚠️ NEDEN VAR: bu panelde `className="stop"` ve `className="tight"`
 * yazıldı; ikisi de site belgelerinin sınıflarıydı ve panel stilinde
 * HİÇ YOKTU. Blok stilsiz çizildi, hiçbir test bozulmadı, ve kusur
 * ancak ekrana bakan bir insan tarafından görüldü. Birim testleri
 * yapıyı ölçüyor, stilin var olup olmadığını değil.
 *
 * ⚠️ YALNIZCA SABİT DİZGELER TARANIYOR. `className={...}` ifadeleri,
 * şablon dizgileri ve koşullu birleştirmeler atlanıyor: onları
 * çözmeye çalışmak, yanlış alarm üreten ve bu yüzden kapatılan bir
 * kontrol olurdu. Sabit dizgeler kusurların yaşadığı yer.
 */
describe("panel sınıfları", () => {
  it("her sabit className stil dosyasında karşılığını buluyor", () => {
    const root = process.cwd();
    const css = fs.readFileSync(path.join(root, "src/styles.css"), "utf8");

    /*
     * ⚠️ TARAYICININ VE KÜTÜPHANELERİN KENDİ SINIFLARI MUAF. Bunlar
     * stil dosyasında değil, başka yerde tanımlı; listede olmaları
     * "bilinmiyor" değil "başka yerde" demek.
     */
    const external = new Set(["xterm", "xterm-viewport", "sr-only"]);

    /*
     * ⚠️ DONDURULMUŞ BORÇ — SİLİNECEK, GENİŞLEMEYECEK.
     *
     * Bu liste kontrol yazıldığında zaten tanımsız olan dört sınıfı
     * taşıyordu (btn-ghost, btn-sm, data, pathrules). 2026-09-13'te
     * hepsi ödendi: btn-ghost kullanımları panelin kendi btn-quiet'ine
     * çevrildi, btn-sm tanımlandı, data ve pathrules sökülüp yerlerine
     * gerçek sarmalayıcı (.table-wrap) geldi — ve her biri ekrana
     * bakılarak doğrulandı. Küme BOŞ kalıyor; kontrolün işi yeni bir
     * tanesinin eklenmesini engellemek. Listeye ekleme yapmak, borcu
     * yeniden açmak demek.
     */
    const known = new Set<string>([]);

    const missing: string[] = [];
    const walk = (dir: string) => {
      for (const entry of fs.readdirSync(dir)) {
        const p = path.join(dir, entry);
        if (fs.statSync(p).isDirectory()) {
          walk(p);
          continue;
        }
        if (!/\.tsx$/.test(p) || /\.test\.tsx$/.test(p)) continue;

        const src = fs.readFileSync(p, "utf8");
        for (const m of src.matchAll(/className="([^"{}]+)"/g)) {
          for (const cls of m[1].split(/\s+/).filter(Boolean)) {
            if (external.has(cls) || known.has(cls)) continue;
            // Sınıfın stil dosyasında bir seçici olarak geçmesi yeter.
            if (new RegExp(`\\.${cls}[\\s,{:.>~+\\[]`).test(css)) continue;
            missing.push(`${path.relative(root, p)}: .${cls}`);
          }
        }
      }
    };
    walk(path.join(root, "src"));

    expect(missing, "panel stilinde karşılığı olmayan sınıflar").toEqual([]);
  });
});
