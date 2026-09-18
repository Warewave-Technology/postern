import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";

/*
 * ⚠️ YARIM KALAN BİR YENİDEN ADLANDIRMA, HİÇ YAPILMAMIŞTAN KÖTÜDÜR.
 *
 * Ekranın yarısı "role" yarısı "group" derse, okuyan kişi ikisinin farklı
 * şeyler olduğunu sanar — oysa aynı nesne. Derleyici kimlikleri
 * yakalıyor; ekranda görünen METNİ ve yorumu yakalamıyor. Bu test onları
 * yakalıyor.
 *
 * ⚠️ ARIA `role` MUAF, ÇÜNKÜ HTML'İN KENDİ KELİMESİ. role="menu",
 * getByRole ve arkadaşları değişmiyor. Muafiyet listesine satır eklemek
 * kolay ve testi işe yaramaz hâle getirmenin de en kolay yolu: yeni bir
 * muafiyet eklerken NEDEN muaf olduğunu buraya yaz.
 */
const EXEMPT = [
  /role="[^"]*"/, // ARIA özniteliği
  /(?:get|query|find)(?:All)?By(?:Role)/, // testing-library sorguları
  /columnheader|menuitem|listbox|combobox/, // ARIA rol ADLARI
  /labels:\s*\{[^}]*role:/, // hedef ETİKETİ: müşterinin kendi verisi
  /role:\s*"database"/, // aynı: örnek etiket değeri
];

/*
 * ⚠️ withFileTypes DEĞİL, statSync. Bu dizinin ayrı tsconfig'i var ve
 * orada `readdirSync(dir, { withFileTypes: true })` aşırı yükü string[]
 * olarak çözülüyor: vitest tip bakmadığı için test koşuyor, `make web`
 * içindeki tsc ise CI'da düşüyordu.
 */
function walk(dir: string, out: string[] = []): string[] {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    if (fs.statSync(p).isDirectory()) walk(p, out);
    else if (/\.(tsx?|css)$/.test(name)) out.push(p);
  }

  return out;
}

describe("sözlük", () => {
  it("panelde postern nesnesi için 'role' kelimesi kalmadı", () => {
    const hits: string[] = [];
    for (const f of [...walk("src"), ...walk("test-node")]) {
      if (f.endsWith("vocabulary.test.ts")) continue;
      fs.readFileSync(f, "utf8")
        .split("\n")
        .forEach((line, i) => {
          if (!/\brole\b/i.test(line)) return;
          if (EXEMPT.some((re) => re.test(line))) return;
          hits.push(`${f}:${i + 1}: ${line.trim().slice(0, 90)}`);
        });
    }

    expect(hits).toEqual([]);
  });
});
