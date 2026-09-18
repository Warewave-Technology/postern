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

/**
 * Başlık dolgusunun YÖNÜ çivileniyor.
 *
 * ⚠️ NEDEN BÖYLE BİR TEST: bu kural bir kez ters yazıldı ve altı dosyada
 * yirmiden fazla başlık sessizce dolgusuz kaldı — başlık metni, altındaki
 * değerlerle hizalanmıyordu. Kusur "biraz sola kaymış yazı" gibi göründüğü
 * için gözle bakan kimse yakalamadı; UserDetail'de aynı tablonun bir
 * başlığı dolguluyken ikisi değildi ve o da fark edilmemişti.
 *
 * Ölçülen şey: düz bir <th> dolgu ALIR, ve sıfırlama yalnızca dolgusunu
 * kendisi taşıyan bir çocuk barındıran hücreye uygulanır. Ters çevrilirse
 * bu test düşer.
 */
describe("tablo başlığı dolgusu", () => {
  /*
   * ⚠️ AÇILIŞ PARANTEZİ SEÇİCİNİN İÇİNDE ARANIYOR, SONRASINDA DEĞİL.
   *
   * İlk hâli `at + selector.length`'ten sonra '{' arıyordu; seçici zaten
   * '{' içerdiği için bu, BİR SONRAKİ kuralın gövdesini okuyordu. Sonuç
   * iki yanlış: düz th testi başka bir kuralın `padding: 0`'ını görüp
   * düştü, :has testi ise `padding: 0.62rem`'i "padding:0" alt dizgisi
   * sanıp YANLIŞ SEBEPTEN geçti. İkincisi daha kötü olanı.
   */
  function bodyOf(selector: string): string {
    const at = css.indexOf(selector);
    if (at === -1) throw new Error(`seçici bulunamadı: ${selector}`);
    const open = css.indexOf("{", at);
    const close = css.indexOf("}", open);
    return css.slice(open + 1, close);
  }

  it("düz th dolgu alıyor", () => {
    const body = bodyOf("\nth {");
    const padding = /padding:\s*([^;]+);/.exec(body)?.[1]?.trim();
    expect(padding).toBeTruthy();
    expect(padding).not.toBe("0");
  });

  it("sıfırlama yalnızca tam-alan çocuk taşıyan hücrede", () => {
    // Kural varsa dolgusunu çocuk taşıyor demektir; yoksa sıralanabilir
    // başlıkta çift dolgu olurdu.
    expect(css).toContain("th:has(> .th-pad)");
    expect(css).toContain("th:has(> button.sort)");
    // Tam eşleşme: "padding: 0.62rem" de "padding:0" ALT DİZGİSİNİ taşıyor.
    const zeroed = bodyOf("th:has(> button.sort) {");
    expect(/padding:\s*0\s*;/.test(zeroed)).toBe(true);
  });
});

/*
 * ⚠️ TANIMSIZ BİR DEĞİŞKENE YAPILAN ATIF, SESSİZCE HİÇBİR ŞEY YAPAR.
 *
 * CSS'te `color: var(--bg)` gibi bir satır, --bg tanımlı değilse
 * GEÇERSİZ olur: özellik hiç uygulanmaz ve öğe rengi miras alır. Ekran
 * çizilir, hata vermez, testler geçer — yalnızca renk yanlıştır.
 *
 * İki tanesi ölçüldü ve ikisi de görünürlük kaybıydı: çan rozeti
 * `color: var(--bg)` yüzünden yazısını `.bell`'in soluk renginden miras
 * alıyordu (adaçayı üstünde adaçayı, sayı okunmuyordu), ve verilen
 * parolanın kutusu `background: var(--bg)` yüzünden ŞEFFAF çiziliyordu.
 * İkincisinin komşu satırında aynı sınıftan bir hata (--border) bir kez
 * fark edilip düzeltilmiş, bu bırakılmıştı — yani göz bu hatayı
 * yakalamıyor.
 */
describe("değişken atıfları", () => {
  it("var(--x) yazılan her jeton tanımlı", () => {
    const defined = new Set<string>();
    for (const m of css.matchAll(/(--[a-z0-9-]+)\s*:/g)) defined.add(m[1]);

    const missing = new Set<string>();
    // Yedekli kullanım — var(--x, 10px) — kasıtlı: yedeği olan atıf
    // tanımsızken de doğru davranır, o yüzden aranmıyor.
    for (const m of css.matchAll(/var\(\s*(--[a-z0-9-]+)\s*\)/g)) {
      if (!defined.has(m[1])) missing.add(m[1]);
    }

    expect([...missing].sort()).toEqual([]);
  });
});

/*
 * Bekleyen iş rozetinin okunurluğu ÖLÇÜLÜYOR, göze bırakılmıyor.
 *
 * ⚠️ Rozetin işi bir sayı göstermek; okunmayan bir sayı, olmayan bir
 * rozetten daha kötü, çünkü yer kaplayıp işi yapılmış gösteriyor. Eşik
 * WCAG AA'nın küçük metin için istediği 4.5:1 — rozet 11px ve kalın.
 */
describe("rozet okunurluğu", () => {
  const lum = (hex: string) => {
    const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
    const [r, g, b] = c.map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));

    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const ratio = (a: string, b: string) => {
    const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);

    return (hi + 0.05) / (lo + 0.05);
  };

  it("iki temada da 4.5:1 üstünde", () => {
    for (const marker of [":root", ':root[data-theme="dark"]']) {
      const t = tokensAfter(marker);
      expect(ratio(t["--attention"], t["--attention-fg"])).toBeGreaterThan(4.5);
    }
  });
});

/*
 * ⚠️ AÇILIR BAŞLIĞIN ÜÇGENİ ÇİZİLMEK ZORUNDA.
 *
 * Bu kontrolün önceki hâli metnin içine gömülü bir düğmeydi ve tıklanır
 * olduğu anlaşılmıyordu (kullanıcı söyledi). <summary> bunu kendisi
 * çözüyor — ama yalnızca işareti çizildiğinde: Safari'de varsayılan
 * `display: block` ve pek çok reset `list-style: none` veriyor; ikisinde
 * de üçgen kaybolur ve elimizde yine tıklanır olduğu anlaşılmayan bir
 * satır kalır.
 *
 * Eski test burada `.notify-panel button`ın nowrap muafiyetini
 * koruyordu; o kural, bildirim satırları düğmeden <li> içine taşınınca
 * kalktı — cümleler artık bir düğme etiketi değil, paragraf.
 */
describe("açılır durum süzgeci", () => {
  it("üçgeni çizen display kuralını taşıyor", () => {
    const rule = css.slice(css.indexOf(".state-filter > summary {"));
    const body = rule.slice(0, rule.indexOf("}"));
    expect(body).toMatch(/display:\s*list-item/);
    expect(body).toMatch(/cursor:\s*pointer/);
  });
});

/*
 * ⚠️ BÖLÜM ETİKETİ OKUNUR KALMAK ZORUNDA. Bu başlıklar (ACCESS, AUDIT,
 * ACCOUNT) kenar menüsünün iskeleti; okunmazlarsa gruplama da okunmuyor.
 * Önceki renk (--faint) aydınlık temada 4.29:1 veriyordu — AA'nın altı —
 * ve bu yüzden değiştirilmişti. Yeni renk aynı sınavdan geçiyor: küçük
 * ve kalın metin için eşik 4.5:1, ölçüsü kendi zemininde.
 */
describe("bölüm etiketi okunurluğu", () => {
  const lum = (hex: string) => {
    const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
    const [r, g, b] = c.map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));

    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const ratio = (a: string, b: string) => {
    const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);

    return (hi + 0.05) / (lo + 0.05);
  };

  it("iki temada da kendi zemininde 4.5:1 üstünde", () => {
    for (const marker of [":root", ':root[data-theme="dark"]']) {
      const t = tokensAfter(marker);
      // Kenar menüsü ve menü panelleri --surface/--raised üstünde duruyor.
      expect(ratio(t["--label"], t["--surface"])).toBeGreaterThan(4.5);
      expect(ratio(t["--label"], t["--raised"])).toBeGreaterThan(4.5);
    }
  });
});
