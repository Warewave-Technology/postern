import { describe, expect, it } from "vitest";
import raw from "./styles.css?raw";

/**
 * Paletin iki koyu bloğunun AYRIŞMADIĞINI doğrular.
 *
 * NEDEN BÖYLE BİR TEST: koyu tokenlar iki kez yazılı — biri
 * `@media (prefers-color-scheme: dark)` içinde (sistem koyu), diğeri
 * `:root[data-theme="dark"]` altında (kullanıcı elle seçti). CSS bunları
 * tek kurala birleştiremiyor.
 *
 * Ayrışırlarsa ortaya çıkan kusur SİNSİ: sistem koyu temadayken her şey
 * doğru görünür, kullanıcı anahtarı elle "koyu"ya çektiği anda paletin
 * yarısı eski değerlerde kalır. Yani hatayı yalnızca o yoldan giden
 * görür ve geliştirici muhtemelen o yoldan gitmez.
 */
// ⚠️ Dosya `?raw` ile GÖMÜLÜYOR, fs ile okunmuyor. İlk deneme
// import.meta.url + fileURLToPath idi; jsdom ortamında import.meta.url
// bir http adresi oluyor ve test sessizce hiç koşmuyordu. fs'e geçmek
// ise yalnızca bu test için @types/node bağımlılığı demekti.
// ⚠️ YORUMLAR ÖNCE SİLİNİYOR. İlk hâlde düz indexOf kullanılıyordu ve
// seçiciyi kendi açıklama yorumunun içinde buluyordu: test, aydınlık
// bloğu "koyu" sanıp karşılaştırıyordu. Testin kendisi yanlış yeri
// ölçüyorsa, ölçtüğü şey hakkında hiçbir şey söylemez.
const css = raw.replace(/\/\*[\s\S]*?\*\//g, "");

/** Bir seçicinin gövdesindeki --token: value çiftlerini çıkarır. */
function tokensAfter(marker: string): Record<string, string> {
  const at = css.indexOf(marker);
  if (at === -1) throw new Error(`seçici bulunamadı: ${marker}`);

  // Gövde: marker'dan sonraki ilk '{' ile onu kapatan '}' arası.
  const open = css.indexOf("{", at + marker.length);
  let depth = 0;
  let i = open;
  for (; i < css.length; i++) {
    if (css[i] === "{") depth++;
    else if (css[i] === "}") {
      depth--;
      if (depth === 0) break;
    }
  }
  const body = css.slice(open + 1, i);

  const out: Record<string, string> = {};
  for (const m of body.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) {
    out[m[1]] = m[2].trim().replace(/\s+/g, " ");
  }
  return out;
}

describe("gruvbox paleti", () => {
  it("iki koyu blok birebir ayni tokenlari tasir", () => {
    const media = tokensAfter(':root:not([data-theme="light"])');
    const attr = tokensAfter(':root[data-theme="dark"]');

    expect(Object.keys(attr).sort()).toEqual(Object.keys(media).sort());
    expect(attr).toEqual(media);
  });

  // Aydınlık blokta tanımlı her token'ın koyu karşılığı OLMALI: eksik
  // kalan bir token koyu temada aydınlık değerini taşır ve genelde
  // görünmez bir metin üretir.
  it("aydinlik blokta tanimli her token koyuda da tanimli", () => {
    const light = tokensAfter(":root {");
    const dark = tokensAfter(':root[data-theme="dark"]');

    // Ölçü/yazı tipi belirteçleri temaya göre değişmiyor; yalnızca
    // renk ve gölge belirteçleri karşılaştırılıyor.
    const themed = Object.keys(light).filter(
      (k) => !/^--(radius|font|mono)/.test(k),
    );
    const missing = themed.filter((k) => !(k in dark));
    expect(missing).toEqual([]);
  });
});
