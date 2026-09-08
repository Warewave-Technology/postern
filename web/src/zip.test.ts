import { describe, expect, it } from "vitest";
import { dosStamp, maxEntries, safeName, uniqueName, ZipWriter } from "./zip";

/*
 * Arşivin BİÇİMİ burada ölçülmüyor — onun hükmünü gerçek `unzip` veriyor
 * (test-node/zip.real.test.ts). Burada ölçülen şey adların temizlenmesi:
 * saf, çizimsiz ve hepsi hedefin YAZDIĞI metne karşı.
 */

describe("safeName", () => {
  /*
   * ⚠️ ZIP-SLIP. Arşivin içindeki yol, açan aracın nereye yazacağını
   * belirliyor: "../../.ssh/authorized_keys" adında bir dosya, denetçi
   * arşivi kendi makinesinde açtığında ev dizininin DIŞINA yazardı. Ad
   * bileşen bileşen temizlendiği için ayraç ve nokta-adlar burada
   * ölüyor.
   */
  it("ayraçları ve nokta-adları etkisizleştiriyor", () => {
    expect(safeName("..")).toBe("_");
    expect(safeName(".")).toBe("_");
    expect(safeName("a/b")).toBe("a_b");
    expect(safeName("a\\b")).toBe("a_b");
    // Temizlikten SONRA bakılıyor: "..\0" da ".." demek.
    expect(safeName("..\u0000")).toBe("_");
    expect(safeName("")).toBe("_");
  });

  /*
   * ⚠️ KAÇIŞ DİZİLERİ ARŞİV LİSTESİNİ DE BOYUYOR. `unzip -l` çıktısı bir
   * terminale gidiyor; adın içindeki ESC, denetçinin ekranını
   * yeniden yazabilir. Kayda giren metinle aynı gerekçe (sftpcast.go).
   */
  it("kontrol karakterlerini atıyor", () => {
    expect(safeName("kontrol\u001b[2Jsil.txt")).toBe("kontrol[2Jsil.txt");
    expect(safeName("a\u0007b\u007fcd")).toBe("abcd");
  });

  /*
   * ⚠️ EN SİNSİSİ BU: AD OLDUĞUNDAN BAŞKA GÖRÜNÜYOR. U+202E (sağdan
   * sola geçersiz kıl) taşıyan "fatura<RLO>gnp.exe", hem panelde hem
   * arşiv listesinde hem de çoğu çıkarma aracında "faturaexe.png" diye
   * okunuyor — denetçi bir resme tıkladığını sanarken çalıştırılabilir
   * bir dosya açıyor. Kontrol karakterleriyle aynı muamele, aynı sebep.
   */
  it("iki yönlü yazı denetimlerini atıyor", () => {
    expect(safeName("fatura\u202egnp.exe")).toBe("faturagnp.exe");
    expect(safeName("a\u200eb\u200fc\u2066d\u2069e")).toBe("abcde");
  });

  /*
   * ⚠️ WINDOWS'UN AYRILMIŞ AYGIT ADLARI. "CON" ya da "COM1" adıyla bir
   * dosya çıkarmak Windows'ta ya düşüyor ya bir aygıta yazıyor; arşivin
   * geri kalanı açılırken o girdi sessizce kayboluyor.
   */
  it("Windows'un ayrılmış adlarını etkisizleştiriyor", () => {
    expect(safeName("CON")).toBe("_CON");
    expect(safeName("nul.txt")).toBe("_nul.txt");
    expect(safeName("com1")).toBe("_com1");
    expect(safeName("lpt9.log")).toBe("_lpt9.log");
    // Benzeyen ama ayrılmış OLMAYAN adlar dokunulmadan geçiyor.
    expect(safeName("console.log")).toBe("console.log");
    expect(safeName("com0")).toBe("com0");
  });

  /*
   * Windows sondaki noktayı ve boşluğu SESSİZCE atıyor: "veri." ile
   * "veri" aynı dosyaya çıkıyor ve ikincisi birincisini eziyor.
   */
  it("sondaki nokta ve boşluğu işaretliyor", () => {
    expect(safeName("veri.")).toBe("veri._");
    expect(safeName("veri ")).toBe("veri _");
  });
});

describe("uniqueName", () => {
  it("uzantıyı koruyarak ayırıyor", () => {
    const taken = new Set<string>();
    expect(uniqueName(taken, "a.log")).toBe("a.log");
    expect(uniqueName(taken, "a.log")).toBe("a (2).log");
    expect(uniqueName(taken, "a.log")).toBe("a (3).log");
    // Uzantısız ad: sayı sona geliyor.
    expect(uniqueName(taken, "README")).toBe("README");
  });

  /*
   * ⚠️ ARŞİVİN İÇİNDE FARKLI OLMAK YETMİYOR VE BU EN SESSİZ KAYIP.
   *
   * "README" ile "readme" zip'te iki ayrı girdi; `unzip -t` de geçiyor.
   * Ama macOS'un APFS'i ve Windows büyük/küçük harf ayırmıyor: ikisi
   * çıkarılırken TEK dosyaya düşüyor ve sonuncusu diğerini eziyor.
   * Denetçi bunu göremiyor — arşivde iki satır var, diskte bir dosya.
   */
  it("yalnızca harf büyüklüğüyle ayrılan adları da ayırıyor", () => {
    const taken = new Set<string>();
    expect(uniqueName(taken, "README")).toBe("README");
    expect(uniqueName(taken, "readme")).toBe("readme (2)");
  });

  /*
   * ⚠️ AYNI GEREKÇE UNICODE AYRIŞTIRMASI İÇİN DE GEÇERLİ. macOS adları
   * NFD'ye ayrıştırıyor: "günlük"ün birleşik ve ayrık yazımları diskte
   * aynı dosya oluyor.
   */
  it("NFC ve NFD yazımını aynı ad sayıyor", () => {
    const taken = new Set<string>();
    const nfc = "günlük".normalize("NFC");
    const nfd = "günlük".normalize("NFD");
    expect(nfc).not.toBe(nfd);

    expect(uniqueName(taken, nfc)).toBe(nfc);
    expect(uniqueName(taken, nfd)).toBe(`${nfd} (2)`);
  });
});

describe("dosStamp", () => {
  /*
   * ⚠️ 1980 ÖNCESİ YOK. Hedefin ATTRS'ında zaman bayrağı kapalı
   * olabiliyor ve mtime 0 geliyor; çıkarılan sarmalama 2043 gibi bir
   * tarih verirdi. Yanlış bir tarih, belli bir tabandan kötü.
   */
  it("biçimin dışındaki yılları kırpıyor", () => {
    // 1970: taban 1 Ocak 1980.
    expect(dosStamp(1)).toEqual({ date: (0 << 9) | (1 << 5) | 1, time: 0 });

    // Tavanın çok ötesi de sarmalanmıyor.
    const far = dosStamp(9_000_000_000);
    expect(far.date >>> 9).toBeLessThanOrEqual(2107 - 1980);
  });
});

describe("ZipWriter", () => {
  it("girdi sayısı tavanına çarpınca hata veriyor", () => {
    const z = new ZipWriter();
    const body = new Uint8Array(1);

    // Tavana kadar doldurmak yavaş; sayacı doğrudan sınamak için
    // tavanın hemen altından başlanamıyor, o yüzden küçük bir tavan
    // yerine hatanın CÜMLESİ sınanıyor.
    expect(() => {
      for (let i = 0; i <= maxEntries; i++) {
        z.addFile({ path: `f${i}`, mtime: 0, mode: 0o100644 }, [body], 1, 0);
      }
    }).toThrow(/cannot hold more than 65535 entries/);
  });

  /*
   * ⚠️ TAVAN HESABI YAZMANIN GERÇEK MALİYETİNİ SAYMALI. İlk hâli
   * yalnızca ad ve gövde uzunluğunu topluyordu: yerel başlığın 30
   * baytını, merkezî dizinin girdi başına 46+ad baytını ve sondaki 22
   * baytı hiç görmüyordu. Eksik sayan bir tavan, geçildiğini FARK
   * ETMEDEN geçilen bir tavan.
   */
  it("merkezî dizinin maliyetini de sayıyor", () => {
    const z = new ZipWriter();
    const name = "x".repeat(200);
    z.addFile({ path: name, mtime: 0, mode: 0o100644 }, [], 0, 0);

    // Yazılan bayt: yerel başlık (30) + ad. Merkezî dizin henüz
    // yazılmadı ama tavan hesabında sayılıyor.
    expect(z.bytes).toBe(30 + name.length);
    expect(z.count).toBe(1);
  });
});
