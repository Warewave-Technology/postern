// @vitest-environment node

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ZipWriter, crc32, safeName, uniqueName } from "../src/zip";

/*
 * ⚠️ BU DOSYANIN VAR OLMA SEBEBİ, zip.ts'in KENDİ KENDİNİ DOĞRULAMASI.
 *
 * Biçimi biz yazıyoruz. Onu yine kendi yazdığımız bir çözümleyiciyle
 * sınamak, iki tarafın AYNI yanlış varsayımla yazılıp birlikte yeşil
 * kalması demek — bu depo o tuzağın adını zaten koydu
 * (test-node/sftp.real.test.ts, ve Go tarafında test/integration).
 *
 * Burada hükmü Info-ZIP'in `unzip`'i veriyor: `unzip -t` arşivdeki HER
 * girdinin CRC'sini yeniden hesaplıyor. Yani bir bayt kaydıysa, bir
 * boyut alanı yanlışsa ya da merkezî dizinin konumu tutmuyorsa test
 * düşüyor — bizim ne düşündüğümüzden bağımsız olarak.
 */

function findUnzip(): string {
  for (const p of ["/usr/bin/unzip", "/bin/unzip", "/usr/local/bin/unzip"]) {
    if (existsSync(p)) return p;
  }
  /*
   * ⚠️ ATLAMIYOR, DÜŞÜYOR. Sessizce atlanan bir test hiç olmayan bir
   * testtir; yeşil bir CI'da kimse fark etmez (sftp.real.test.ts'teki
   * aynı gerekçe).
   */
  throw new Error("unzip bulunamadı — arşiv biçimi doğrulanamaz");
}

let dir = "";
const unzip = findUnzip();

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "postern-zip-"));
});

afterAll(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

/** write, arşivi diske koyar ve yolunu döner. */
async function write(name: string, blob: Blob): Promise<string> {
  const path = join(dir, name);
  writeFileSync(path, new Uint8Array(await blob.arrayBuffer()));

  return path;
}

/** body, ZipWriter'ın beklediği (gövde, boyut, crc) üçlüsünü hazırlar. */
function body(b: Uint8Array<ArrayBuffer>): [BlobPart[], number, number] {
  return [[b], b.length, crc32(b)];
}

const mtime = 1757066400; // 2025-09-05, sabit: tarih alanı da yazılıyor.

describe("gerçek unzip", () => {
  /*
   * ⚠️ EN ÖNEMLİ İDDİA: `unzip -t` HER GİRDİNİN CRC'sini yeniden
   * hesaplıyor. Bu test geçiyorsa yerel başlık, veri, merkezî dizin ve
   * sondaki kayıt BİRBİRİYLE TUTUYOR — biçimi doğru anlayıp
   * anlamadığımızdan bağımsız bir hüküm.
   */
  it("ürettiğimiz arşivi bozuksuz kabul ediyor", async () => {
    const z = new ZipWriter();

    // Bütün bayt değerleri: metin varsayımı yapan bir hata burada çıkar.
    const binary = new Uint8Array(256);
    for (let i = 0; i < 256; i++) binary[i] = i;

    // Tek parçadan büyük gövde.
    const big = new Uint8Array(300 * 1024);
    for (let i = 0; i < big.length; i++) big[i] = (i * 7) & 0xff;

    z.addDirectory({ path: "kok", mtime, mode: 0o040755 });
    z.addFile({ path: "kok/ikili.bin", mtime, mode: 0o100644 }, ...body(binary));
    z.addFile({ path: "kok/buyuk.dat", mtime, mode: 0o100600 }, ...body(big));
    // UTF-8 ad: bayrak 11 yazılmazsa açan taraf adı bozuyor.
    z.addFile(
      { path: "kok/günlükler/çıktı.txt", mtime, mode: 0o100644 },
      ...body(new TextEncoder().encode("merhaba\n")),
    );
    z.addDirectory({ path: "kok/boş", mtime, mode: 0o040700 });

    const path = await write("temel.zip", z.finish());
    const out = execFileSync(unzip, ["-t", path], { encoding: "utf8" });
    expect(out).toContain("No errors detected");
  });

  /*
   * ⚠️ CRC PARÇA PARÇA HESAPLANIYOR ve tek seferlik hesapla AYNI
   * çıkmak zorunda. İndirme parçalar hâlinde geliyor; ara değeri
   * yanlış taşıyan bir uygulama, ancak dosya bir parçadan büyük
   * olduğunda bozuluyor — küçük testlerde görünmez.
   */
  it("parça parça hesaplanan CRC bütünle aynı", async () => {
    const whole = new Uint8Array(100_000);
    for (let i = 0; i < whole.length; i++) whole[i] = (i * 31) & 0xff;

    let running = 0;
    for (let at = 0; at < whole.length; at += 7919) {
      running = crc32(
        whole.subarray(at, Math.min(at + 7919, whole.length)),
        running,
      );
    }
    expect(running).toBe(crc32(whole));

    // Ve unzip aynı fikirde: parçalı CRC ile yazılan arşiv sağlam.
    const z = new ZipWriter();
    const chunks: BlobPart[] = [];
    let crc = 0;
    for (let at = 0; at < whole.length; at += 7919) {
      const c = whole.subarray(at, Math.min(at + 7919, whole.length));
      chunks.push(c.slice());
      crc = crc32(c, crc);
    }
    z.addFile(
      { path: "akis.dat", mtime, mode: 0o100644 },
      chunks,
      whole.length,
      crc,
    );

    const path = await write("akis.zip", z.finish());
    expect(execFileSync(unzip, ["-t", path], { encoding: "utf8" })).toContain(
      "No errors detected",
    );
  });

  /*
   * ⚠️ ÇIKAN BAYTLAR GİRENLE AYNI OLMALI. `unzip -t` CRC'yi doğruluyor
   * ama CRC'yi de biz yazdık; asıl soru, arşivden çıkan dosyanın
   * içeriğinin girdiğiyle aynı olup olmadığı.
   */
  it("çıkarılan dosyalar bayt bayt aynı", async () => {
    const z = new ZipWriter();
    const raw = new Uint8Array(50_000);
    for (let i = 0; i < raw.length; i++) raw[i] = (i ^ 0x5a) & 0xff;

    z.addFile({ path: "a/b/veri.bin", mtime, mode: 0o100644 }, ...body(raw));
    const path = await write("cikar.zip", z.finish());

    const out = join(dir, "cikti");
    mkdirSync(out);
    execFileSync(unzip, ["-q", path, "-d", out], { encoding: "utf8" });

    const got = readFileSync(join(out, "a/b/veri.bin"));
    expect(got.length).toBe(raw.length);
    expect(crc32(got)).toBe(crc32(raw));
  });

  /*
   * ⚠️ BOŞ DİZİN ARŞİVDEN ÇIKMALI. Zip'te dizin yalnızca içindeki
   * dosyaların yolunda ima ediliyor; kendi girdisi yazılmazsa boş bir
   * klasör SESSİZCE yok oluyor ve kullanıcı indirdiği ağaçtan farklı
   * bir ağaç alıyor.
   */
  it("boş dizin arşivden çıkıyor", async () => {
    const z = new ZipWriter();
    z.addDirectory({ path: "agac/bos", mtime, mode: 0o040755 });
    z.addFile(
      { path: "agac/dolu/x.txt", mtime, mode: 0o100644 },
      ...body(new TextEncoder().encode("x")),
    );

    const path = await write("bos.zip", z.finish());
    const out = join(dir, "bos-cikti");
    mkdirSync(out);
    execFileSync(unzip, ["-q", path, "-d", out], { encoding: "utf8" });

    expect(readdirSync(join(out, "agac")).sort()).toEqual(["bos", "dolu"]);
    expect(readdirSync(join(out, "agac/bos"))).toEqual([]);
  });

  /*
   * ⚠️ ZIP-SLIP: SALDIRGAN HEDEFİN SAHİBİ.
   *
   * Hedefte "../../.ssh/authorized_keys" adında bir dosya açan biri,
   * denetçi arşivi kendi makinesinde çıkardığında EV DİZİNİNİN DIŞINA
   * yazdırabilirdi. Info-ZIP kendisi de bunu kırpıyor ama ona
   * güvenmiyoruz: arşivin İÇİNDE böyle bir ad hiç olmamalı, çünkü her
   * çıkarma aracı aynı derecede dikkatli değil.
   */
  it("hedeften gelen kaçış adı arşivin dışına yazamıyor", async () => {
    const hostile = [
      "../../../../tmp/kacis",
      "/mutlak/yol",
      "..",
      "normal\\ters.txt",
      "kontrol\u001b[2Jsil.txt",
    ];

    /*
     * Adlar SEVİYE SEVİYE tekilleştiriliyor — gezginin yapacağı şeyin
     * aynısı. Her dizinin kendi "alınmış adlar" kümesi var; bu olmadan
     * bir dosya, başka bir girdinin dizini hâline gelebiliyor.
     */
    const z = new ZipWriter();
    const taken = new Map<string, Set<string>>();
    const at = (parent: string) => {
      let s = taken.get(parent);
      if (!s) taken.set(parent, (s = new Set()));
      return s;
    };

    for (const name of hostile) {
      let path = "kok";
      for (const part of name.split("/").filter((p) => p !== "")) {
        path += "/" + uniqueName(at(path), safeName(part));
      }
      expect(path.split("/")).not.toContain("..");
      z.addFile({ path, mtime, mode: 0o100644 }, ...body(new Uint8Array([1])));
    }

    const path = await write("kacis.zip", z.finish());
    const listed = execFileSync(unzip, ["-Z1", path], { encoding: "utf8" });

    // Arşivin kendi listesinde tırmanma yok.
    for (const line of listed.trim().split("\n")) {
      expect(line.startsWith("kok/")).toBe(true);
      expect(line.split("/")).not.toContain("..");
    }

    // Ve çıkarınca gerçekten hedef dizinin içinde kalıyor.
    const out = join(dir, "kacis-cikti");
    mkdirSync(out);
    execFileSync(unzip, ["-q", path, "-d", out], { encoding: "utf8" });
    expect(readdirSync(out)).toEqual(["kok"]);
  });

  /*
   * ⚠️ UTF-8 BAYRAĞI (bit 11) OLMAZSA ad CP437 sanılıyor ve Windows'ta
   * "günlükler" → "gÃ¼nlÃ¼kler" çıkıyor. unzip bayrağı okuyup adı doğru
   * çözüyorsa bayrak yazılmış demektir.
   */
  it("Türkçe adlar bozulmadan çıkıyor", async () => {
    const z = new ZipWriter();
    z.addFile(
      { path: "günlükler/şubat/çıktı-ğüş.txt", mtime, mode: 0o100644 },
      ...body(new TextEncoder().encode("ok")),
    );

    const path = await write("utf8.zip", z.finish());
    const out = join(dir, "utf8-cikti");
    mkdirSync(out);
    execFileSync(unzip, ["-q", path, "-d", out], { encoding: "utf8" });

    expect(readdirSync(out)).toEqual(["günlükler"]);
    expect(readdirSync(join(out, "günlükler/şubat"))).toEqual([
      "çıktı-ğüş.txt",
    ]);
  });
});
