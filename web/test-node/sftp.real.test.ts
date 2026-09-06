// @vitest-environment node

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  writeFileSync,
  mkdirSync,
  symlinkSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SFTPClient } from "../src/sftp";

/*
 * ⚠️ BU DOSYANIN VAR OLMA SEBEBİ, sftp.test.ts'in KENDİ KENDİNİ
 * DOĞRULAMASI.
 *
 * Orada paketleri testin kendisi kuruyor. Yani çözümleyicinin
 * varsayımları yanlışsa test de aynı yanlış varsayımla yazılmış oluyor
 * ve ikisi birlikte yeşil kalıyor. Bu tam olarak Go tarafında
 * test/integration/sftp_test.go'nun yazdığı gerekçe; burada aynısı
 * TypeScript istemcisi için gerekiyordu.
 *
 * Burada cevapları OpenSSH'in kendi sftp-server'ı veriyor. Ölçülen şey:
 * gerçek bir sunucunun ürettiği ATTRS bayrak birleşimleri, gerçek bir
 * READDIR sayfalaması ve gerçek bir EOF, bizim çözümleyicimizden
 * geçiyor mu.
 *
 * ⚠️ SSH YOK, KİMLİK DOĞRULAMA YOK. sftp-server bir alt süreç ve
 * borularla konuşuyor — postern'in hedefte konuştuğu şeyin aynısı.
 */

// OpenSSH'in kurulum yeri dağıtıma göre değişiyor.
const CANDIDATES = [
  "/usr/libexec/sftp-server",
  "/usr/lib/openssh/sftp-server",
  "/usr/lib/ssh/sftp-server",
  "/usr/libexec/openssh/sftp-server",
];

function findServer(): string {
  for (const p of CANDIDATES) if (existsSync(p)) return p;
  /*
   * ⚠️ ATLAMIYOR, DÜŞÜYOR. Sessizce atlanan bir test, hiç olmayan bir
   * testtir ve yeşil bir CI'da bunu kimse fark etmez. OpenSSH taşıyan
   * her Unix'te bu yollardan biri var.
   */
  throw new Error(
    `sftp-server bulunamadı; bakılan yerler: ${CANDIDATES.join(", ")}`,
  );
}

/**
 * startServer, bir sftp-server alt süreci ve ona bağlı bir istemci kurar.
 *
 * chunk verilirse sunucunun baytları O BOYUTTA parçalanarak veriliyor.
 * ⚠️ Bunun var olma sebebi ölçüldü: boru okumaları burada neredeyse her
 * zaman tam paket getiriyor, yani çerçeveleme kodu gerçek sunucuya karşı
 * HİÇ SINANMIYORDU — yarım paketi atan bir mutasyon bu dosyada hayatta
 * kalıyordu. Asıl yol (websocket) ise paketi kolayca bölüyor.
 */
function startServer(chunk?: number) {
  const proc = spawn(findServer(), ["-e"], { stdio: ["pipe", "pipe", "pipe"] as const });
  const c = new SFTPClient({
    send: (frame) => {
      proc.stdin.write(frame);
    },
  });
  /*
   * ⚠️ Buffer DEĞİL Uint8Array yazılıyor. Node zaten Buffer veriyor ve
   * Buffer bir Uint8Array; ama Buffer'ın TİPİ @types/node'dan geliyor ve
   * bu proje onu bağımlılık olarak taşımıyor. Ölçüldü: tip yazılınca
   * vitest geçiyordu ama üretim derlemesi (tsc -b) düşüyordu.
   */
  proc.stdout.on("data", (b: Uint8Array) => {
    const bytes = new Uint8Array(b);
    if (!chunk) {
      c.feed(bytes);
      return;
    }
    for (let i = 0; i < bytes.length; i += chunk) {
      c.feed(bytes.subarray(i, i + chunk));
    }
  });
  proc.on("close", () => c.fail(new Error("sftp-server kapandı")));

  return { proc, client: c };
}

let srv: ChildProcessWithoutNullStreams;
let dir: string;
let client: SFTPClient;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "postern-sftp-"));
  writeFileSync(join(dir, "kucuk.txt"), "merhaba\n");
  writeFileSync(join(dir, "buyuk.bin"), new Uint8Array(3000).fill(7));
  writeFileSync(join(dir, ".gizli"), "x");
  mkdirSync(join(dir, "altdizin"));
  symlinkSync(join(dir, "kucuk.txt"), join(dir, "bag"));

  const started = startServer();
  srv = started.proc;
  client = started.client;

  await client.open();
}, 20_000);

afterAll(() => {
  srv?.kill();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

describe("gerçek sftp-server", () => {
  it("dizini okuyor ve türleri doğru ayırıyor", async () => {
    const entries = await client.readdir(dir);
    const by = new Map(entries.map((e) => [e.name, e]));

    // "." ve ".." gerçek sunucunun gönderdiği girdiler; taklit
    // sunucumuz onları hiç göndermiyordu.
    expect(by.has(".")).toBe(true);
    expect(by.get(".")!.isDir).toBe(true);

    expect(by.get("altdizin")!.isDir).toBe(true);
    expect(by.get("kucuk.txt")!.isDir).toBe(false);
    expect(by.get("kucuk.txt")!.size).toBe(8);
    expect(by.get("buyuk.bin")!.size).toBe(3000);
    expect(by.get(".gizli")).toBeTruthy();

    /*
     * ⚠️ BAĞ, BAĞ OLARAK GÖRÜNMELİ. READDIR lstat semantiği kullanıyor,
     * yani hedefin değil bağın kendisinin kipini veriyor. Panelde
     * ayrı bir ikonla çizilmesinin sebebi bu: bağın işaret ettiği yer
     * yol politikasının GÖRMEDİĞİ bir yer olabilir.
     */
    expect(by.get("bag")!.isLink).toBe(true);

    // Zaman alanı gerçek sunucudan geliyor: sıfır olsaydı panel "—"
    // yazardı ve kimse fark etmezdi.
    expect(by.get("kucuk.txt")!.mtime).toBeGreaterThan(1_600_000_000);

    // ls -l satırı da geliyor (sahip/grup yalnızca orada).
    expect(by.get("kucuk.txt")!.longname).toMatch(/kucuk\.txt/);
  });

  it("realpath göreli adı çözüyor", async () => {
    const p = await client.realpath(".");
    expect(p.startsWith("/")).toBe(true);
  });

  /**
   * ⚠️ ÇOK GİRDİLİ DİZİN, READDIR DÖNGÜSÜNÜN ASIL SINAVI.
   *
   * sftp-server bir cevaba sığdırabildiği kadarını gönderip devamını
   * bir sonraki READDIR'e bırakıyor. Tek isteğe güvenen bir istemci
   * burada SESSİZCE kırpardı — ve küçük dizinlerde çalıştığı için
   * teşhis edilmesi en zor arıza türü.
   */
  it("büyük dizini eksiksiz okuyor", async () => {
    const many = join(dir, "cok");
    mkdirSync(many);
    const names: string[] = [];
    for (let i = 0; i < 500; i++) {
      // Adlar uzun: cevabın birden çok sayfaya bölünmesi için.
      const n = `dosya-${String(i).padStart(4, "0")}-${"u".repeat(40)}`;
      writeFileSync(join(many, n), "x");
      names.push(n);
    }

    const entries = await client.readdir(many);
    const got = entries
      .map((e) => e.name)
      .filter((n) => n !== "." && n !== "..");
    expect(got.sort()).toEqual(names.sort());
  }, 20_000);

  it("olmayan dizini sebebiyle reddediyor", async () => {
    await expect(client.readdir(join(dir, "yok-boyle"))).rejects.toThrow();
  });
});

/*
 * ⚠️ GERÇEK PAKETLER, DÜŞMANCA PARÇALANMIŞ.
 *
 * Panelde araya websocket giriyor ve bir SFTP paketi rahatça iki
 * çerçeveye bölünüyor; sftp.test.ts bunu elle kurduğu paketlerle
 * ölçüyor. Burada bölünen şey GERÇEK bir sunucunun ürettiği baytlar:
 * uzunluk alanının kendisi bile ikiye ayrılıyor (chunk 1), yani
 * çerçeveleyici "4 bayt bile gelmedi" durumundan geçmek zorunda.
 */
describe("bayt bayt beslenen akış", () => {
  it("aynı listeyi veriyor", async () => {
    const { proc, client: slow } = startServer(1);
    try {
      await slow.open();
      const entries = await slow.readdir(dir);
      const names = entries
        .map((e) => e.name)
        .filter((n) => n !== "." && n !== "..")
        .sort();
      expect(names).toContain("kucuk.txt");
      expect(names).toContain("altdizin");
      expect(entries.find((e) => e.name === "kucuk.txt")!.size).toBe(8);
    } finally {
      proc.kill();
    }
  }, 30_000);
});
