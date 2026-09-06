import { describe, it, expect } from "vitest";
import { SFTPClient, SFTPError, Framer, FXP, FX, maxPacket } from "./sftp";

/**
 * Sahte hedef: istemcinin yazdığı çerçeveleri toplar, cevabı test
 * yazıyor. Soket yok — bütün protokol yolu böyle ölçülebiliyor.
 */
class FakeTarget {
  sent: Uint8Array[] = [];
  client: SFTPClient;

  constructor() {
    this.client = new SFTPClient({ send: (f) => this.sent.push(f) });
  }

  /** body, gönderilen i. çerçevenin uzunluk öneki atılmış gövdesi. */
  body(i: number): Uint8Array {
    return this.sent[i].subarray(4);
  }

  reply(...parts: Uint8Array[]) {
    for (const p of parts) this.client.feed(p);
  }
}

// ---- kodlama yardımcıları (testin kendi, bağımsız uygulaması) ----

function u32(v: number): number[] {
  return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
}

function str(s: string): number[] {
  const b = Array.from(new TextEncoder().encode(s));
  return [...u32(b.length), ...b];
}

function packet(...body: number[]): Uint8Array {
  return new Uint8Array([...u32(body.length), ...body]);
}

function readIDAt(b: Uint8Array, off: number): number {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(off);
}

describe("Framer", () => {
  it("tek çerçevedeki iki paketi ayırır", () => {
    const f = new Framer();
    const out = f.push(
      new Uint8Array([
        ...packet(FXP.VERSION, ...u32(3)),
        ...packet(FXP.STATUS),
      ]),
    );
    expect(out).toHaveLength(2);
    expect(out[0][0]).toBe(FXP.VERSION);
    expect(out[1][0]).toBe(FXP.STATUS);
  });

  /**
   * ⚠️ ASIL AYIRT EDİCİ TEST. WebSocket çerçevesi SFTP paketiyle aynı şey
   * değil; büyük bir dizin listesi kolayca ikiye bölünüyor. Bu bölünmeyi
   * ele almayan bir okuyucu, küçük dizinlerde ÇALIŞIR ve büyüklerde
   * bozulur — teşhis edilmesi en zor arıza türü.
   */
  it("iki parçaya bölünmüş paketi birleştirir", () => {
    const f = new Framer();
    const whole = packet(FXP.VERSION, ...u32(3));

    expect(f.push(whole.subarray(0, 3))).toHaveLength(0);
    expect(f.push(whole.subarray(3, 6))).toHaveLength(0);
    const out = f.push(whole.subarray(6));
    expect(out).toHaveLength(1);
    expect(out[0][0]).toBe(FXP.VERSION);
  });

  it("olmayacak uzunluğu reddeder", () => {
    const f = new Framer();
    expect(() => f.push(new Uint8Array([...u32(maxPacket + 1), 0]))).toThrow();
    expect(() => f.push(new Uint8Array(u32(0)))).toThrow();
  });
});

describe("SFTPClient", () => {
  it("INIT gönderir ve VERSION'ı bekler", async () => {
    const t = new FakeTarget();
    const opened = t.client.open();

    expect(t.body(0)[0]).toBe(FXP.INIT);
    expect(readIDAt(t.body(0), 1)).toBe(3);

    t.reply(packet(FXP.VERSION, ...u32(3)));
    await expect(opened).resolves.toBeUndefined();
  });

  it("realpath cevabındaki adı döner", async () => {
    const t = new FakeTarget();
    const p = t.client.realpath(".");
    const id = readIDAt(t.body(0), 1);

    t.reply(
      packet(
        FXP.NAME,
        ...u32(id),
        ...u32(1),
        ...str("/home/postern"),
        ...str(""),
        ...u32(0),
      ),
    );
    await expect(p).resolves.toBe("/home/postern");
  });

  /**
   * Dizin okuma DÖNGÜ: hedef listeyi parça parça veriyor ve sonu EOF
   * taşıyan bir STATUS ile bildiriyor. Tek READDIR ile yetinen bir
   * istemci uzun dizinleri SESSİZCE kırpardı.
   */
  it("READDIR'i EOF'a kadar sürdürür ve tutamağı kapatır", async () => {
    const t = new FakeTarget();
    const p = t.client.readdir("/tmp");

    // OPENDIR -> HANDLE
    expect(t.body(0)[0]).toBe(FXP.OPENDIR);
    t.reply(packet(FXP.HANDLE, ...u32(readIDAt(t.body(0), 1)), ...str("h1")));
    await Promise.resolve();

    // 1. READDIR -> bir girdi
    expect(t.body(1)[0]).toBe(FXP.READDIR);
    t.reply(
      packet(
        FXP.NAME,
        ...u32(readIDAt(t.body(1), 1)),
        ...u32(1),
        ...str("bir.txt"),
        ...str("-rw-r--r-- 1 root root 5 Sep 5 10:00 bir.txt"),
        // Bütün bayraklar açık: SIZE|UIDGID|PERMISSIONS|ACMODTIME
        ...u32(0x0f),
        ...u32(0),
        ...u32(5), // size (64 bit)
        ...u32(0),
        ...u32(0), // uid, gid
        ...u32(0o100644), // mode
        ...u32(1),
        ...u32(1757066400), // atime, mtime
      ),
    );
    await Promise.resolve();

    // 2. READDIR -> ikinci girdi, bu kez bir dizin
    expect(t.body(2)[0]).toBe(FXP.READDIR);
    t.reply(
      packet(
        FXP.NAME,
        ...u32(readIDAt(t.body(2), 1)),
        ...u32(1),
        ...str("alt"),
        ...str("drwxr-xr-x 2 root root 40 Sep 5 10:00 alt"),
        ...u32(0x04),
        ...u32(0o040755),
      ),
    );
    await Promise.resolve();

    // 3. READDIR -> EOF
    expect(t.body(3)[0]).toBe(FXP.READDIR);
    t.reply(packet(FXP.STATUS, ...u32(readIDAt(t.body(3), 1)), ...u32(FX.EOF)));

    const entries = await p;
    expect(entries.map((e) => e.name)).toEqual(["bir.txt", "alt"]);
    expect(entries[0].size).toBe(5);
    expect(entries[0].mtime).toBe(1757066400);
    expect(entries[0].isDir).toBe(false);
    expect(entries[1].isDir).toBe(true);

    // Tutamak kapatıldı.
    expect(t.body(4)[0]).toBe(FXP.CLOSE);
  });

  /**
   * ⚠️ SEBEP KULLANICIYA ULAŞMALI. Reddedilen bir yolun "not found"
   * görünmesi, tam da bu üründe düzelttiğimiz arızaydı: yönetici
   * kısıtı koyduğunu bilir, kullanıcı dosyanın yokluğunu sanar.
   */
  it("reddedilen isteği kodu ve mesajıyla reddeder", async () => {
    const t = new FakeTarget();
    const p = t.client.readdir("/etc");

    t.reply(
      packet(
        FXP.STATUS,
        ...u32(readIDAt(t.body(0), 1)),
        ...u32(FX.PERMISSION_DENIED),
        ...str("path /etc is not allowed by your role"),
      ),
    );

    await expect(p).rejects.toBeInstanceOf(SFTPError);
    await p.catch((e: SFTPError) => {
      expect(e.code).toBe(FX.PERMISSION_DENIED);
      expect(e.message).toContain("not allowed by your role");
    });
  });

  it("mesajsız durumda okunur bir karşılık koyar", async () => {
    const t = new FakeTarget();
    const p = t.client.readdir("/etc");
    t.reply(
      packet(
        FXP.STATUS,
        ...u32(readIDAt(t.body(0), 1)),
        ...u32(FX.PERMISSION_DENIED),
      ),
    );
    await p.catch((e: SFTPError) =>
      expect(e.message).toBe("permission denied"),
    );
  });

  it("soket koptuğunda bekleyen istekleri reddeder", async () => {
    const t = new FakeTarget();
    const p = t.client.readdir("/tmp");
    t.client.fail(new Error("connection lost"));
    await expect(p).rejects.toThrow("connection lost");
  });

  /**
   * ⚠️ KAPSAM KİLİDİ. Salt-okunur olmak, yazma paketlerini GÖNDERMEMEK
   * değil; onları hiç KODLAYAMAMAK. Bu test, birinin yarın "küçük bir
   * yükleme düğmesi" eklerken protokol tablosunu genişletmek zorunda
   * kalmasını sağlıyor — sessizce sızabilecek bir değişiklik değil.
   */
  it("yazma paket tipleri hiç tanımlı değil", () => {
    for (const name of [
      "OPEN",
      "WRITE",
      "MKDIR",
      "RMDIR",
      "REMOVE",
      "RENAME",
      "SETSTAT",
    ]) {
      expect(FXP).not.toHaveProperty(name);
    }
  });
});
