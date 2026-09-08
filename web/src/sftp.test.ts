import { describe, it, expect } from "vitest";
import {
  SFTPClient,
  SFTPError,
  Halted,
  Framer,
  FXP,
  FX,
  chunkSize,
  maxPacket,
  newStop,
} from "./sftp";

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

/**
 * ⚠️ KÖKEN, PROTOKOLÜN İÇİNDE DEĞİL — ÇAĞRANIN ELİNDE.
 *
 * postern reddettiği isteğe kendi STATUS paketini yazıyor, hedef de kendi
 * STATUS'ünü yazıyor: tel üzerinde ikisi AYNI paket. Ayrımı paketin
 * içindeki metinden okumak, ayrımı hedefe yazdırmak demek. Ayrım akış
 * etiketiyle geliyor ve feed onu OLDUĞU GİBİ taşıyor.
 */
describe("cevabın kökeni", () => {
  it("postern akışından gelen ret postern'e yazılıyor", async () => {
    const t = new FakeTarget();
    const p = t.client.realpath(".");
    const id = readIDAt(t.body(0), 1);

    t.client.feed(
      packet(
        FXP.STATUS,
        ...u32(id),
        ...u32(FX.PERMISSION_DENIED),
        ...str("postern: path is not permitted"),
        ...u32(0),
      ),
      "postern",
    );

    await expect(p).rejects.toMatchObject({ origin: "postern" });
  });

  /*
   * ⚠️ AYNI PAKET, HEDEFİN AKIŞINDAN. Metin birebir aynı; ayıran tek şey
   * onu hangi akışın taşıdığı. Bu iddia düşerse "postern: " öneki yeniden
   * kanıt olur ve hedef bastion'ın ağzından konuşur.
   */
  it("aynı metin hedef akışından gelirse hedefe yazılıyor", async () => {
    const t = new FakeTarget();
    const p = t.client.realpath(".");
    const id = readIDAt(t.body(0), 1);

    t.client.feed(
      packet(
        FXP.STATUS,
        ...u32(id),
        ...u32(FX.PERMISSION_DENIED),
        ...str("postern: path is not permitted"),
        ...u32(0),
      ),
      "target",
    );

    await expect(p).rejects.toMatchObject({ origin: "target" });
  });

  /*
   * ⚠️ İKİ AKIŞ AYRI ÇERÇEVELENİYOR ve bunun ölçülmesi şart.
   *
   * Sunucu kendi cevabını hedefin paket SINIRINDA araya sokuyor, ama
   * istemcinin doğruluğu buna bağlı olamaz: tek bir tampon, hedefin yarım
   * paketiyle postern'in tam paketini birbirine yapıştırırdı ve sonuç
   * "bazen çalışıyor" diye teşhis edilen bir çerçeveleme kayması olurdu.
   */
  it("hedefin yarım paketi postern'in paketini bozmuyor", async () => {
    const t = new FakeTarget();
    const a = t.client.realpath("/a");
    const b = t.client.realpath("/b");
    const idA = readIDAt(t.body(0), 1);
    const idB = readIDAt(t.body(1), 1);

    const fromTarget = packet(
      FXP.STATUS,
      ...u32(idA),
      ...u32(FX.FAILURE),
      ...str("target says no"),
      ...u32(0),
    );

    // Hedefin paketi YARIM kaldı...
    t.client.feed(fromTarget.subarray(0, 6), "target");
    // ...postern araya kendi TAM paketini soktu...
    t.client.feed(
      packet(
        FXP.STATUS,
        ...u32(idB),
        ...u32(FX.PERMISSION_DENIED),
        ...str("postern: path is not permitted"),
        ...u32(0),
      ),
      "postern",
    );
    // ...ve hedefin kalanı sonra geldi.
    t.client.feed(fromTarget.subarray(6), "target");

    await expect(b).rejects.toMatchObject({
      origin: "postern",
      message: "postern: path is not permitted",
    });
    await expect(a).rejects.toMatchObject({
      origin: "target",
      message: "target says no",
    });
  });
});

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
   * ⚠️ KAPSAM KİLİDİ — SINIR DEĞİŞTİ, KİLİT DURUYOR.
   *
   * Önceki hâli "yazma paketleri hiç tanımlı değil" diyordu. Yükleme
   * eklendiği için o cümle artık yanlış; yanlış bir gerekçenin altında
   * kod değiştirmek bu depoda kabul edilen bir şey değil, o yüzden sınır
   * yeniden çizildi.
   *
   * Yeni sınır AD UZAYINDAN geçiyor: dosya okunabiliyor ve yazılabiliyor,
   * ama silmek, taşımak, dizin yaratmak, izin değiştirmek ve bağ kurmak
   * kodlanmıyor. Panelden bir dosyayı SİLMEK, bilinçli bir protokol işi
   * olmak zorunda kalsın — sessizce eklenebilecek bir düğme olmasın.
   */
  it("ad uzayını değiştiren paket tipleri hiç tanımlı değil", () => {
    for (const name of [
      "REMOVE",
      "RENAME",
      "MKDIR",
      "RMDIR",
      "SETSTAT",
      "FSETSTAT",
      "SYMLINK",
    ]) {
      expect(FXP).not.toHaveProperty(name);
    }
  });

  // Okuma ve yazma ise TANIMLI olmalı: aktarım onlara dayanıyor ve
  // eksikliği sessiz bir arıza olurdu.
  it("aktarım için gereken tipler tanımlı", () => {
    for (const name of ["OPEN", "READ", "WRITE", "DATA", "CLOSE"]) {
      expect(FXP).toHaveProperty(name);
    }
  });
});
/** tick, mikro görev kuyruğunu boşaltır (birkaç await zincirlenmiş). */
const tick = () => new Promise((r) => setTimeout(r, 0));

/** readOffset, bir FXP_READ paketindeki dosya konumu. */
function readOffset(b: Uint8Array): number {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const hlen = dv.getUint32(5);
  const at = 9 + hlen;

  return dv.getUint32(at) * 0x100000000 + dv.getUint32(at + 4);
}

/** indexOfType, i'den itibaren ilk verilen tipteki çerçeve. */
function indexOfType(t: FakeTarget, typ: number, from = 0): number {
  for (let i = from; i < t.sent.length; i++) if (t.body(i)[0] === typ) return i;

  return -1;
}

/** openReply, OPEN isteğine tanıtıcı verir. */
async function openReply(t: FakeTarget) {
  const i = indexOfType(t, FXP.OPEN);
  t.reply(packet(FXP.HANDLE, ...u32(readIDAt(t.body(i), 1)), ...str("h1")));
  await tick();
}

function dataReply(t: FakeTarget, frame: number, body: number[]) {
  t.reply(
    packet(
      FXP.DATA,
      ...u32(readIDAt(t.body(frame), 1)),
      ...u32(body.length),
      ...body,
    ),
  );
}

function eofReply(t: FakeTarget, frame: number) {
  t.reply(packet(FXP.STATUS, ...u32(readIDAt(t.body(frame), 1)), ...u32(FX.EOF)));
}

describe("indirme", () => {
  /*
   * ⚠️ BU DOSYADAKİ EN CİDDİ İDDİA VE KOD BİR SÜRE YANLIŞTI.
   *
   * Boru hattı konumu SABİT adımlarla ilerletiyordu (offset += chunkSize).
   * Dosyanın ortasında kısa bir cevap gelirse — NFS ve FUSE bağlarında
   * sıradan — aradaki baytlar HİÇ İSTENMİYORDU: teslim edilen dosya,
   * ortasından bir parça eksik hâlde birleştiriliyordu. Hata vermiyordu,
   * kısa görünmüyordu bile; arşivde o delikli hâlin üstünden hesaplanmış
   * GEÇERLİ bir CRC ile duruyordu.
   *
   * Eski kodda bunu koruduğunu söyleyen bir not vardı ve altındaki satır
   * `eof = eof || false` idi — yani hiçbir şey. Sahte otorite bırakan
   * yorumun tam örneği.
   */
  it("dosyanın ortasındaki kısa cevaptan sonra kalınan yerden devam ediyor", async () => {
    const t = new FakeTarget();
    const got: number[] = [];
    const p = t.client.download("/f", (b) => {
      got.push(...b);
    });

    await openReply(t);

    // İlk READ 0'dan; cevap KISA (1000 bayt) ve dosya bitmedi.
    const first = indexOfType(t, FXP.READ);
    expect(readOffset(t.body(first))).toBe(0);
    dataReply(t, first, Array.from({ length: 1000 }, (_, i) => i & 0xff));
    await tick();

    /*
     * Kritik iddia: bir sonraki istek 1000'DEN başlamalı. Sabit ızgara
     * 32768'i sorardı ve 1000..32767 arası sonsuza kadar kayıp olurdu.
     */
    const next = indexOfType(t, FXP.READ, first + 1);
    const fresh = t.sent
      .map((_, i) => i)
      .filter((i) => i > first && t.body(i)[0] === FXP.READ)
      .map((i) => readOffset(t.body(i)));
    expect(Math.min(...fresh)).toBe(1000);
    expect(next).toBeGreaterThan(first);

    // Kalanı ver ve bitir.
    const after = fresh.indexOf(1000);
    const atThousand = t.sent
      .map((_, i) => i)
      .filter((i) => i > first && t.body(i)[0] === FXP.READ)[after];
    dataReply(t, atThousand, [1, 2, 3]);
    await tick();

    const last = t.sent
      .map((_, i) => i)
      .filter((i) => t.body(i)[0] === FXP.READ && readOffset(t.body(i)) === 1003)[0];
    eofReply(t, last);

    await expect(p).resolves.toBe(1003);
    expect(got.length).toBe(1003);
  });

  /*
   * ⚠️ KÜÇÜK DOSYA KÜÇÜK MALİYETLİ OLMALI ve bu bir kez öyle değildi.
   *
   * Boru hattı pencereyi koşulsuz dolduruyordu: 10 baytlık bir dosya
   * için de 16 READ gidiyordu, ve kısa cevaptan sonra pencere
   * boşaltıldığı için 16 tane daha. Hepsi hedefe ulaşıyor. Dört bin
   * küçük dosyalık bir klasör indirmesinde bu, on binlerce gereksiz
   * gidiş-dönüş demekti — özyineli indirmeyi kullanılmaz yapacak kadar.
   *
   * Boyut biliniyorken gereken istek sayısı İKİ: veriyi getiren ve
   * dosyanın bittiğini söyleyen.
   */
  it("boyutu bilinen küçük dosya iki istekle iniyor", async () => {
    const t = new FakeTarget();
    const p = t.client.download("/f", () => {}, { size: 10 });

    await openReply(t);

    const reads = () =>
      t.sent.map((_, i) => i).filter((i) => t.body(i)[0] === FXP.READ);
    expect(reads()).toHaveLength(1);

    dataReply(t, reads()[0], new Array(10).fill(1));
    await tick();

    expect(reads()).toHaveLength(2);
    expect(readOffset(t.body(reads()[1]))).toBe(10);

    eofReply(t, reads()[1]);
    await expect(p).resolves.toBe(10);
  });

  /*
   * ⚠️ TESLİM EDİLEN, LİSTEDEKİNDEN AZ OLAMAZ. Bu özellikteki bütün
   * "eksik teslim" hataları buraya çarpıyor — ve önceden hiçbir yerde
   * karşılaştırılmıyordu: download dönüş değerini kimse okumuyordu,
   * kuyruk satırı da "tamamlandı" yazıyordu.
   */
  it("beklenenden az bayt teslim edilirse iki sayıyı da söyleyerek düşüyor", async () => {
    const t = new FakeTarget();
    const p = t.client.download("/f", () => {}, { size: 5000 });

    await openReply(t);
    const first = indexOfType(t, FXP.READ);
    dataReply(t, first, [1, 2, 3, 4]);
    await tick();

    const next = t.sent
      .map((_, i) => i)
      .filter((i) => t.body(i)[0] === FXP.READ && readOffset(t.body(i)) === 4)[0];
    eofReply(t, next);

    await expect(p).rejects.toThrow(/sent 4 bytes for a file it listed as 5000/);
  });

  // Fazlası hata DEĞİL: dosya büyümüş ve sonuna kadar okunmuş demek.
  it("beklenenden fazla bayt hata değil", async () => {
    const t = new FakeTarget();
    const p = t.client.download("/f", () => {}, { size: 2 });

    await openReply(t);
    const first = indexOfType(t, FXP.READ);
    dataReply(t, first, [1, 2, 3, 4]);
    await tick();

    const next = t.sent
      .map((_, i) => i)
      .filter((i) => t.body(i)[0] === FXP.READ && readOffset(t.body(i)) === 4)[0];
    eofReply(t, next);

    await expect(p).resolves.toBe(4);
  });

  /*
   * ⚠️ İSTENENDEN FAZLA VEREN CEVAP REDDEDİLİYOR. Her 32 KiB'lık isteğe
   * 1 MiB'lık DATA gönderen bir hedef, taramada hesaplanan bütçeyi 32
   * KATINA çıkarır — yani 2 GiB tavanı indirme başlamadan ölçülmüş
   * olmasına rağmen aşılırdı.
   */
  it("istenenden büyük DATA reddediliyor", async () => {
    const t = new FakeTarget();
    const p = t.client.download("/f", () => {});

    await openReply(t);
    const first = indexOfType(t, FXP.READ);
    dataReply(t, first, new Array(chunkSize + 1).fill(7));

    await expect(p).rejects.toThrow(/for a 32768-byte read/);
  });

  /*
   * ⚠️ BÜTÇE TAVANI OLMADAN "10 bayt" DİYEN BİR HEDEF SONSUZA KADAR
   * AKABİLİRDİ. Boyutu bildiren taraf hedef; tavan, bildirdiğinin
   * tutmadığı durumu yakalıyor.
   */
  it("bütçe tavanını aşan akış kesiliyor", async () => {
    const t = new FakeTarget();
    const p = t.client.download("/f", () => {}, { limit: 10 });

    await openReply(t);
    const first = indexOfType(t, FXP.READ);
    dataReply(t, first, new Array(64).fill(1));

    await expect(p).rejects.toThrow(/past the 10 bytes left/);
  });

  /*
   * ⚠️ DURDURMA, CEVAP GELMESE DE İŞLEMELİ. Bayrak ancak iki await
   * ARASINDA okunabiliyor; susan bir hedefin üstünde Stop düğmesi
   * hiçbir şey yapmıyordu ve kullanıcıya verilmiş bir söz boşa
   * çıkıyordu.
   */
  it("cevapsız kalan istek durdurulabiliyor", async () => {
    const t = new FakeTarget();
    const { signal, stop } = newStop();
    const p = t.client.download("/f", () => {}, { signal });

    await openReply(t);
    expect(indexOfType(t, FXP.READ)).toBeGreaterThan(-1);

    // Hedef hiçbir READ'e cevap vermiyor.
    stop();

    await expect(p).rejects.toBeInstanceOf(Halted);
  });

  /*
   * ⚠️ TANITIСI AÇILMADAN ÖNCE DURDURULMUŞSA HİÇ AÇILMIYOR. Açıp
   * vazgeçmek, defterde hiç okunmayan bir dosya için `open` satırı
   * bırakırdı: "açıldı" diye okunan, karşılığında aktarım satırı
   * olmayan bir iz.
   */
  it("önceden durdurulmuş indirme dosyayı hiç açmıyor", async () => {
    const t = new FakeTarget();
    const { signal, stop } = newStop();
    stop();

    await expect(
      t.client.download("/f", () => {}, { signal }),
    ).rejects.toBeInstanceOf(Halted);
    expect(t.sent).toHaveLength(0);
  });
});

describe("dizin listesi", () => {
  /*
   * ⚠️ SIFIR GİRDİLİ NAME BİR PROTOKOL HATASI, "liste bitti" DEĞİL.
   * Listenin sonu tek bir şekilde bildiriliyor: EOF taşıyan STATUS.
   * Sıfırı bitiş saymak, hedefin listeyi ORTASINDAN kesip kalanını
   * sessizce yok etmesine izin verirdi — gezgin eksik listeyi tam
   * sanar, arşiv eksik çıkar ve atlananlar notunda hiçbir şey yazmaz.
   */
  it("sıfır girdili NAME liste sonu sayılmıyor", async () => {
    const t = new FakeTarget();
    const p = t.client.readdir("/tmp");

    t.reply(packet(FXP.HANDLE, ...u32(readIDAt(t.body(0), 1)), ...str("h1")));
    await tick();

    t.reply(packet(FXP.NAME, ...u32(readIDAt(t.body(1), 1)), ...u32(0)));

    await expect(p).rejects.toThrow(/empty listing round/);
  });
});
