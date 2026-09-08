import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FXP, FX } from "./sftp";
import { reason, closeReason } from "./FileBrowser";
import { SFTPError } from "./sftp";

/*
 * ⚠️ globalThis'e DOĞRUDAN yazıyoruz, vi.stubGlobal ile değil —
 * Terminal.test.tsx'te ölçülen sebeple: stubGlobal testler arasında
 * geri alınıyor ve ikincisinde WebSocket yine tanımsız kalıyor.
 */
class FakeWS {
  static last: FakeWS | null = null;
  /*
   * ⚠️ SABİTLER DE TAKLİT EDİLMELİ. FileBrowser gönderimden önce
   * `ws.readyState === WebSocket.OPEN` diye soruyor ve global WebSocket
   * artık bu sınıf; sabit yoksa karşılaştırma undefined'a düşüyor ve
   * istemci HİÇBİR ŞEY göndermiyor. Testin ilk hâli tam olarak buna
   * takıldı.
   */
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  binaryType = "";
  readyState = 1;
  sent: Uint8Array[] = [];
  /** cursor, `next` aramasının başlangıcı — cevaplanmış kareler geride kalıyor. */
  cursor = 0;
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: ArrayBuffer | string }) => void) | null = null;
  onclose: ((e: { code: number; reason: string }) => void) | null = null;
  onerror: (() => void) | null = null;

  constructor() {
    FakeWS.last = this;
  }
  send(f: Uint8Array) {
    this.sent.push(f);
  }
  close() {}

  /*
   * deliver, sunucudan gelen bir çerçeve — akış etiketiyle birlikte.
   *
   * act ile sarılı: gelen paket React durumunu değiştiriyor ve
   * sarmadan çağırmak uyarı üretiyor. Uyarıyı susturmak değil mesele —
   * bastırılan uyarılar, ileride GERÇEK bir yarışı görünmez kılar.
   */
  async deliver(tag: number, body: Uint8Array) {
    const framed = new Uint8Array(1 + body.length);
    framed[0] = tag;
    framed.set(body, 1);
    /*
     * ⚠️ ASENKRON act ŞART, senkron olanı yetmiyor.
     *
     * Gelen paket bir promise'i çözüyor ve React durumu o promise'in
     * DEVAMINDA değişiyor — senkron act bloğu, devam sıraya girmeden
     * dönüyor. Asenkron act mikro görev kuyruğunu da boşaltıyor.
     */
    await act(async () => {
      this.onmessage?.({ data: framed.buffer });
    });
  }

  /** body, gönderilen i. çerçevenin uzunluk öneki atılmış gövdesi. */
  body(i: number): Uint8Array {
    return this.sent[i].subarray(4);
  }
}
(globalThis as unknown as { WebSocket: unknown }).WebSocket = FakeWS;

import FileBrowser from "./FileBrowser";

// ---- protokol yardımcıları (testin kendi uygulaması) ----

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
function idOf(b: Uint8Array): number {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(1);
}
function entry(name: string, mode: number, size = 0): number[] {
  return [
    ...str(name),
    ...str(""),
    ...u32(0x05), // SIZE | PERMISSIONS
    ...u32(0),
    ...u32(size),
    ...u32(mode),
  ];
}

const DIR = 0o040755;
const FILE = 0o100644;
const LINK = 0o120777;

/*
 * next, sıradaki ISTENEN TİPTE kareyi bekler ve indeksini döner.
 *
 * ⚠️ SAYIYLA DEĞİL TİPLE ARANIYOR. İlk hâli "kaç kare gitti" sayıyordu
 * ve act mikro görevleri erken boşalttığı anda kırıldı: istek, testin
 * saymaya başlamasından ÖNCE gönderilmiş oluyordu. Tipe bakmak, testi
 * zamanlamadan bağımsız kılıyor — ve zaten sorulmak istenen şey bu:
 * "istemci OPENDIR gönderdi mi", "kaçıncı sırada gönderdi" değil.
 */
async function next(ws: FakeWS, typ: number): Promise<number> {
  let found = -1;
  await waitFor(() => {
    for (let i = ws.cursor; i < ws.sent.length; i++) {
      if (ws.body(i)[0] === typ) {
        found = i;
        return;
      }
    }
    throw new Error(`kare bekleniyor: tip ${typ}`);
  });
  ws.cursor = found + 1;
  return found;
}

/** handshake, INIT/VERSION ve realpath'i tamamlar, sonra bir dizin verir. */
async function handshake(ws: FakeWS, home: string, entries: number[][]) {
  await act(async () => {
    ws.onopen?.();
  });

  await next(ws, FXP.INIT);
  await ws.deliver(0, packet(FXP.VERSION, ...u32(3)));

  const rp = await next(ws, FXP.REALPATH);
  await ws.deliver(
    0,
    packet(
      FXP.NAME,
      ...u32(idOf(ws.body(rp))),
      ...u32(1),
      ...str(home),
      ...str(""),
      ...u32(0),
    ),
  );

  await serveDir(ws, entries);
}

/** serveDir, sıradaki OPENDIR/READDIR çiftini cevaplar. */
async function serveDir(ws: FakeWS, entries: number[][]) {
  const od = await next(ws, FXP.OPENDIR);
  await ws.deliver(
    0,
    packet(FXP.HANDLE, ...u32(idOf(ws.body(od))), ...str("h")),
  );

  /*
   * ⚠️ BOŞ DİZİN, "sıfır girdili NAME" DEĞİL. Gerçek bir sftp-server
   * boş dizinde ilk READDIR'e doğrudan EOF veriyor. Testin sıfırlı bir
   * NAME göndermesi, hedefin hiç üretmediği bir cevabı taklit etmek
   * olurdu.
   */
  if (entries.length === 0) {
    const only = await next(ws, FXP.READDIR);
    await ws.deliver(
      0,
      packet(FXP.STATUS, ...u32(idOf(ws.body(only))), ...u32(FX.EOF)),
    );
    return;
  }

  const rd = await next(ws, FXP.READDIR);
  await ws.deliver(
    0,
    packet(
      FXP.NAME,
      ...u32(idOf(ws.body(rd))),
      ...u32(entries.length),
      ...entries.flat(),
    ),
  );

  const eof = await next(ws, FXP.READDIR);
  await ws.deliver(
    0,
    packet(FXP.STATUS, ...u32(idOf(ws.body(eof))), ...u32(FX.EOF)),
  );
}

beforeEach(() => {
  FakeWS.last = null;
});

describe("FileBrowser", () => {
  it("açılışta ev dizinini listeler, dizinleri önce sıralar", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;

    await handshake(ws, "/home/yigit", [
      entry("notlar.txt", FILE, 1536),
      entry("proje", DIR),
    ]);

    await waitFor(() => expect(screen.getByText("proje")).toBeTruthy());
    const rows = screen.getAllByRole("row").slice(1); // başlık satırı hariç
    expect(rows[0].textContent).toContain("proje");
    expect(rows[1].textContent).toContain("notlar.txt");
    expect(rows[1].textContent).toContain("1.5 KiB");

    // Kırıntılar ev dizinini gösteriyor.
    expect(screen.getByRole("button", { name: "yigit" })).toBeTruthy();
  });

  /**
   * ⚠️ BU TESTİN ÖLÇTÜĞÜ ŞEY BİR YANLIŞ ANLAMAYI ÖNLÜYOR.
   *
   * Reddedilen bir dizine "girmiş" görünmek, kullanıcıya bir önceki
   * dizinin listesini yeni dizinin içeriği diye gösterirdi. Yol
   * yalnızca okuma BAŞARIRSA değişiyor.
   */
  it("reddedilen dizine girmiyor ve sebebi yazıyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;

    await handshake(ws, "/home/yigit", [entry("gizli", DIR)]);
    await waitFor(() => expect(screen.getByText("gizli")).toBeTruthy());

    await userEvent.click(screen.getByRole("button", { name: /gizli/ }));

    const od = await next(ws, FXP.OPENDIR);
    /*
     * ⚠️ POSTERN'İN CEVABI POSTERN'İN ETİKETİYLE GELİYOR (2). Aynı
     * paketi hedefin etiketinden göndermek başka bir şey ve o ayrı
     * ölçülüyor ("hedefin yazdığı 'postern: ' …").
     */
    await ws.deliver(
      2,
      packet(
        FXP.STATUS,
        ...u32(idOf(ws.body(od))),
        ...u32(FX.PERMISSION_DENIED),
        ...str("postern: path is not allowed by your role"),
      ),
    );

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toBe(
        "path is not allowed by your role",
      ),
    );

    /*
     * Yol DEĞİŞMEDİ. Soru KIRINTI ÇUBUĞUNA soruluyor: "gizli" listede
     * zaten bir düğme olarak duruyor (tıklanabilir dizin), yani onun
     * yokluğunu aramak yanlış soru olurdu. Doğru soru, o dizine
     * girilmiş gibi görünüp görünmediğimiz.
     */
    const nav = screen.getByRole("navigation", { name: "path" });
    expect(within(nav).getByText("yigit")).toBeTruthy();
    expect(within(nav).queryByText("gizli")).toBeNull();

    // Ve bir önceki listenin içeriği duruyor.
    expect(screen.getByText("gizli")).toBeTruthy();
  });

  /**
   * ⚠️ AKIŞ ETİKETİ AYIKLANIYOR. Etiketi çözümleyiciye veren bir
   * okuyucu her pakette bir bayt kayardı; stderr'i veri sanan bir
   * okuyucu ise gerekçe metnini paket sanardı.
   */
  it("stderr'i listeye değil gerekçe şeridine yazıyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;

    await handshake(ws, "/home/yigit", [entry("a.txt", FILE)]);
    await waitFor(() => expect(screen.getByText("a.txt")).toBeTruthy());

    await ws.deliver(3, new TextEncoder().encode("postern: /etc: refused\r\n"));

    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toBe(
        "postern: /etc: refused",
      ),
    );
    // Liste bozulmadı: stderr çözümleyiciye HİÇ girmedi.
    expect(screen.getByText("a.txt")).toBeTruthy();
  });

  /**
   * ⚠️ HEDEFİN stderr'İ DE BU ŞERİDE DÜŞÜYOR ve orada postern'in
   * cümlesiyle yan yana duruyor.
   *
   * SSH'ta stderr tek bir akış: postern'in uyarısı da, hedefin kendi
   * yazdığı da oradan geliyor. Şerit ikisini aynı biçimde çizseydi,
   * hedefin sahibi "postern: …" yazarak bastion'ın uyarı kutusunu
   * kendi cümlesiyle doldurabilirdi.
   */
  it("hedefin stderr'ini postern'in uyarısı gibi çizmiyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;

    await handshake(ws, "/home/yigit", [entry("a.txt", FILE)]);
    await waitFor(() => expect(screen.getByText("a.txt")).toBeTruthy());

    await ws.deliver(
      1,
      new TextEncoder().encode("postern: /etc: allowed, fetched fine\r\n"),
    );

    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toBe(
        "the target said: postern: /etc: allowed, fetched fine",
      ),
    );
  });

  /*
   * ⚠️ ŞERİDE DÜŞEN METİN DE TEMİZLENMELİ — ve bu, PR'ın kendi
   * iddiasının tutmadığı tek yüzeydi.
   *
   * Köken artık telde: hedefin stderr'i etiket 1 ile geliyor ve şerit
   * "the target said: " damgasını basıyor. Ama metin ham girdiği
   * sürece damga bir şey ifade etmiyor: içine U+202E koyan bir hedef,
   * damgayı cümlenin ortasına ya da sonuna taşıyıp satırı postern'in
   * kendi uyarısı gibi okutabiliyor. Kaçış dizileri de aynı kapıdan
   * giriyor. Yani kökeni tele taşıyıp son adımda geri vermek olurdu.
   *
   * Aynı gerekçe explain()'de zaten yazılıydı (STATUS metni için);
   * eksik olan, isteğe BAĞLANAMAYAN bu ikinci yoldu.
   */
  it("şeride düşen hedef metnini temizliyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;

    await handshake(ws, "/home/yigit", [entry("a.txt", FILE)]);
    await waitFor(() => expect(screen.getByText("a.txt")).toBeTruthy());

    await ws.deliver(
      1,
      new TextEncoder().encode(
        "izin yok\u202e\u001b[2K gnp.erutaf uyarisi\r\n",
      ),
    );

    await waitFor(() => expect(screen.getByRole("status")).toBeTruthy());
    const line = screen.getByRole("status").textContent ?? "";

    // Damga hâlâ başta ve metin hâlâ okunuyor.
    expect(line.startsWith("the target said: ")).toBe(true);
    expect(line).toContain("izin yok");

    // Ama yön ve kontrol karakterleri geçmedi.
    for (const ch of line) {
      const c = ch.codePointAt(0) ?? 0;
      expect(c < 0x20 || c === 0x7f).toBe(false);
      expect(c === 0x200e || c === 0x200f).toBe(false);
      expect(c >= 0x202a && c <= 0x202e).toBe(false);
      expect(c >= 0x2066 && c <= 0x2069).toBe(false);
    }
  });

  it("dizin boyutu göstermiyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;

    // Hedef dizin girdisine 4096 diyor; panel bunu yazarsa kullanıcı
    // klasörün 4 KiB olduğunu sanır.
    await handshake(ws, "/", [entry("etc", DIR, 4096)]);

    await waitFor(() => expect(screen.getByText("etc")).toBeTruthy());
    const row = screen.getAllByRole("row")[1];
    expect(row.textContent).not.toContain("4.0 KiB");
    expect(row.textContent).toContain("—");
  });

  it("gizli dosyalar varsayılan gizli, düğmeyle açılıyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;

    await handshake(ws, "/home/yigit", [
      entry(".bashrc", FILE),
      entry("acik.txt", FILE),
    ]);

    await waitFor(() => expect(screen.getByText("acik.txt")).toBeTruthy());
    expect(screen.queryByText(".bashrc")).toBeNull();

    await userEvent.click(screen.getByLabelText(/hidden files/i));
    expect(screen.getByText(".bashrc")).toBeTruthy();
  });

  it("soket kapanınca sebebi gösteriyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;
    await handshake(ws, "/home/yigit", []);

    await act(async () => {
      ws.onclose?.({ code: 1011, reason: "target refused the subsystem" });
    });
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toBe(
        "target refused the subsystem",
      ),
    );
  });
});

describe("sebep metni", () => {
  /**
   * ⚠️ "not found" GÖSTERMEK YANILTIR — bu üründe bir kez ölçüldü:
   * politika bir yolu reddettiğinde kullanıcı dosyanın olmadığını
   * sanıyordu. postern kendi retlerini önekliyor; önek ayıklanıyor ama
   * cümle değiştirilmiyor.
   */
  it("postern önekini ayıklıyor, cümleyi değiştirmiyor", () => {
    expect(
      reason(new SFTPError(3, "postern: read-only session", "postern")),
    ).toBe("read-only session");
  });

  it("hedefin kendi retini postern'inki gibi göstermiyor", () => {
    expect(
      reason(new SFTPError(FX.PERMISSION_DENIED, "Permission denied")),
    ).toContain("the target said");
  });

  /**
   * ⚠️ BU DOSYADAKİ ASIL İDDİA: ÖNEK KANIT DEĞİL.
   *
   * postern kendi retlerini "postern: " ile yazıyor ve burası bir
   * zamanlar o öneki KÖKEN KANITI sayıyordu. Ama hedefin STATUS mesajı
   * istemciye olduğu gibi geçiyor (internal/sftpaudit/status.go): hedefin
   * sahibi "postern: this path is allowed, fetched fine" yazdığında panel
   * o cümleyi bastion'ın gerekçesi diye çiziyordu — denetlenen makine,
   * denetleyenin ağzından konuşuyordu.
   *
   * Ölçülen şey metnin gösterilmemesi DEĞİL: gösterilebilir ve
   * gösterilmeli. Ölçülen şey, postern'in AYNI metni yazdığında çıkan
   * cümleden ayrılabilmesi.
   */
  it("hedefin yazdığı 'postern: ' öneki, postern'in sesini vermiyor", () => {
    const text = "postern: this path is allowed, fetched fine";

    const spoof = reason(new SFTPError(FX.PERMISSION_DENIED, text, "target"));
    const real = reason(new SFTPError(FX.PERMISSION_DENIED, text, "postern"));

    expect(real).toBe("this path is allowed, fetched fine");
    expect(spoof).not.toBe(real);
    expect(spoof).toBe(`the target said: ${text}`);
  });

  /**
   * ⚠️ KÖKENİ BİLMEYEN ÇAĞRI YERİ HEDEFE DÜŞÜYOR. Atıf pozitif bir kanıt
   * istiyor; varsayılanı "postern" yapmak, kanıt yokluğunu kanıt saymak
   * olurdu.
   */
  it("kökeni verilmemiş hata postern'e yazılmıyor", () => {
    expect(new SFTPError(3, "postern: nope").origin).toBe("target");
  });

  /**
   * ⚠️ HEDEFİN METNİ TEMİZLENİYOR. Kaçış dizileri ve iki yönlü yazı
   * işaretleri, düz metin olarak konsa bile satırı göründüğünden başka
   * türlü okutabiliyor — atıf damgasını cümlenin ortasına taşımak dahil.
   */
  it("hedefin metnindeki kontrol baytlarını çiziyor değil ayıklıyor", () => {
    const got = reason(
      new SFTPError(FX.PERMISSION_DENIED, "nope\u001b[2J\u202eevil", "target"),
    );

    expect(got).not.toMatch(/\u001b/);
    expect(got).not.toMatch(/\u202e/);
    expect(got).toBe("the target said: nope[2Jevil");
  });

  it("kapanış sebebi yoksa kodu yazıyor", () => {
    expect(closeReason({ code: 1000, reason: "" })).toBe("session ended");
    expect(closeReason({ code: 1006, reason: "" })).toContain("1006");
  });
});

/**
 * ⚠️ DİZİNE İŞARET EDEN BAĞ ÖLÜ UÇ OLMAMALI.
 *
 * READDIR lstat semantiği kullanıyor: bir dizine işaret eden bağ da
 * isDir=false geliyor. Yalnızca isDir'e bakan bir arayüzde o satır
 * tıklanamaz oluyordu — demoda görüldü, gerçek dosya sistemlerinde
 * dizine bağ yaygın.
 */
describe("sembolik bağlar", () => {
  it("bağ tıklanabilir ve girildiğinde yol değişiyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;

    await handshake(ws, "/home/yigit", [entry("guncel", LINK)]);
    await waitFor(() => expect(screen.getByText("guncel")).toBeTruthy());

    const link = screen.getByRole("button", { name: /guncel/ });
    await userEvent.click(link);

    // Hedef bağı çözdü ve dizin listesi geldi.
    await serveDir(ws, [entry("main.go", FILE)]);
    await waitFor(() => expect(screen.getByText("main.go")).toBeTruthy());

    const nav = screen.getByRole("navigation", { name: "path" });
    expect(within(nav).getByText("guncel")).toBeTruthy();
  });

  it("dosyaya işaret eden bağda sebebi anlaşılır yazıyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;

    await handshake(ws, "/home/yigit", [entry("kisayol", LINK)]);
    await waitFor(() => expect(screen.getByText("kisayol")).toBeTruthy());

    await userEvent.click(screen.getByRole("button", { name: /kisayol/ }));

    const od = await next(ws, FXP.OPENDIR);
    await ws.deliver(
      0,
      packet(
        FXP.STATUS,
        ...u32(idOf(ws.body(od))),
        ...u32(FX.FAILURE),
        ...str("Not a directory"),
      ),
    );

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/not a directory/i),
    );
    // Ham errno metni DEĞİL, ne yapıldığını söyleyen cümle.
    expect(screen.getByRole("alert").textContent).toMatch(
      /cannot show file contents/,
    );
  });
});

/*
 * ---- aktarım ----
 *
 * ⚠️ Buradaki iddialar protokol hakkında DEĞİL: onlar gerçek bir
 * sftp-server'a karşı ölçülüyor (test-node/sftp.real.test.ts). Burada
 * ölçülen şey ARAYÜZÜN SÖZLERİ: yükleme kapalıyken düğme basılamaz,
 * yarım kalan aktarım tamamlandı görünmez, bir hata kuyruğu durdurmaz.
 */

/** localFile, bir <input type="file"> olayına konacak sahte dosya. */
function localFile(name: string, size: number): File {
  return new File([new Uint8Array(size)], name);
}

describe("aktarım", () => {
  /**
   * ⚠️ YÜKLEME KAPALIYKEN DÜĞME BASILAMAZ OLMALI.
   *
   * Basılabilir görünüp her denemede reddedilen bir düğme, özelliğin
   * bozuk olduğunu düşündürür. Asıl kısıt sunucuda (salt-okunur kanal);
   * buradaki, kullanıcıya yalan söylememek.
   */
  it("yükleme kapalıyken düğme kapalı ve sebebi yazıyor", async () => {
    render(<FileBrowser target="web01" canWrite={false} />);
    const ws = FakeWS.last!;
    await handshake(ws, "/home/yigit", []);

    /*
     * ⚠️ ÖNCE DOSYA SEÇİLİYOR — ve bu, testin bir şey ölçmesinin şartı.
     *
     * İlk hâli seçim yapmadan düğmenin kapalı olduğunu iddia ediyordu ve
     * GEÇİYORDU: seçim yokken düğme zaten kapalı. Yani canWrite kontrolü
     * kaldırılsa bile test yeşil kalıyordu. Mutasyon bunu gösterdi.
     */
    const input = screen.getByLabelText(/choose files from this computer/i);
    await userEvent.upload(input, localFile("yedek.tar", 32));
    await userEvent.click(screen.getByLabelText("select yedek.tar"));

    const btn = screen.getByRole("button", { name: /Upload/ });
    expect(btn).toBeDisabled();
    expect(btn.getAttribute("title")).toMatch(/sftp_panel_write/);

    // Karşı kanıt: yükleme AÇIKKEN aynı seçim düğmeyi açıyor.
    expect(screen.getByRole("button", { name: /Download/ })).toBeDisabled();
  });

  it("yükleme açıkken seçim düğmeyi etkinleştiriyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;
    await handshake(ws, "/home/yigit", []);

    const input = screen.getByLabelText(/choose files from this computer/i);
    await userEvent.upload(input, localFile("yedek.tar", 32));
    await userEvent.click(screen.getByLabelText("select yedek.tar"));

    expect(screen.getByRole("button", { name: /Upload/ })).toBeEnabled();
  });

  it("indirme seçimi olmadan basılamıyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;
    await handshake(ws, "/home/yigit", [entry("a.txt", FILE, 10)]);

    expect(screen.getByRole("button", { name: /Download/ })).toBeDisabled();
  });

  /**
   * ⚠️ DİZİN SEÇİLEBİLİR OLDU ve ne olacağı ÖNCEDEN yazılı.
   *
   * Bu kutu bir zamanlar bilerek yoktu: seçilebilir görünüp indirilmeyen
   * bir kutu, verilmemiş bir söz olurdu. Artık söz veriliyor — ama
   * tarayıcı bir klasörü olduğu gibi teslim edemiyor, sonuç bir zip. Onu
   * ancak indirme bitince öğrenmek, beklenmedik bir dosya türüyle
   * karşılaşmak olurdu.
   */
  it("dizin seçilebiliyor ve zip olacağını önceden söylüyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;
    await handshake(ws, "/home/yigit", [
      entry("proje", DIR),
      entry("a.txt", FILE, 10),
    ]);

    expect(screen.getByLabelText("select a.txt")).toBeTruthy();

    // Seçmeden önce söz de yok.
    expect(screen.queryByText(/arrive as/i)).toBeNull();

    await userEvent.click(screen.getByLabelText("select proje"));

    expect(screen.getByRole("button", { name: /Download/ })).toBeEnabled();
    expect(screen.getByText(/arrive as a \.zip/i)).toBeTruthy();
  });

  it("yerel dosya seçilince listede boyutuyla görünüyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;
    await handshake(ws, "/home/yigit", []);

    const input = screen.getByLabelText(/choose files from this computer/i);
    await userEvent.upload(input, localFile("yedek.tar", 2048));

    expect(screen.getByText("yedek.tar")).toBeTruthy();
    expect(screen.getByText("2.0 KiB")).toBeTruthy();
    // Seçilene kadar yükleme düğmesi kapalı.
    expect(screen.getByRole("button", { name: /Upload/ })).toBeDisabled();
  });

  /**
   * ⚠️ REDDEDİLEN AKTARIM "tamamlandı" GÖRÜNMEMELİ ve sebebi satırında
   * olmalı. "Failed" tek başına kullanıcının ne yapacağını söylemiyor.
   */
  it("reddedilen yükleme sebebiyle düşüyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;
    await handshake(ws, "/home/yigit", []);

    const input = screen.getByLabelText(/choose files from this computer/i);
    await userEvent.upload(input, localFile("gizli.txt", 16));
    await userEvent.click(screen.getByLabelText("select gizli.txt"));
    await userEvent.click(screen.getByRole("button", { name: /Upload/ }));

    // İstemci dosyayı açmaya çalışıyor; postern reddediyor.
    const od = await next(ws, FXP.OPEN);
    await ws.deliver(
      0,
      packet(
        FXP.STATUS,
        ...u32(idOf(ws.body(od))),
        ...u32(FX.PERMISSION_DENIED),
        ...str("postern: this path is read-only"),
      ),
    );

    await waitFor(() =>
      expect(screen.getByText(/this path is read-only/)).toBeTruthy(),
    );
    expect(screen.queryByText(/completed/)).toBeNull();
  });

  /**
   * ⚠️ BİR AKTARIMIN HATASI KUYRUĞU DURDURMAMALI. Beş dosya seçip
   * birinde izin hatası almak, kalan dördünün de iptal olması demek
   * değil.
   */
  it("düşen aktarımdan sonra sıradaki koşuyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;
    await handshake(ws, "/home/yigit", []);

    const input = screen.getByLabelText(/choose files from this computer/i);
    await userEvent.upload(input, [
      localFile("bir.txt", 8),
      localFile("iki.txt", 8),
    ]);
    await userEvent.click(screen.getByLabelText("select bir.txt"));
    await userEvent.click(screen.getByLabelText("select iki.txt"));
    await userEvent.click(screen.getByRole("button", { name: /Upload/ }));

    // Birincisi reddediliyor.
    const first = await next(ws, FXP.OPEN);
    await ws.deliver(
      0,
      packet(
        FXP.STATUS,
        ...u32(idOf(ws.body(first))),
        ...u32(FX.PERMISSION_DENIED),
        ...str("postern: refused"),
      ),
    );

    // İkincisi yine de DENENİYOR: kuyruk durmadı.
    const second = await next(ws, FXP.OPEN);
    expect(idOf(ws.body(second))).not.toBe(idOf(ws.body(first)));
  });
});
/*
 * ⚠️ ÖZYİNELİ DİZİN İNDİRME — BİLEŞENİN UÇTAN UCA KANITI.
 *
 * Arşivin BİÇİMİ burada ölçülmüyor; onun hükmünü gerçek `unzip` veriyor
 * (test-node/zip.real.test.ts) ve gezginin kuralları tree.test.ts'te.
 * Burada ölçülen şey yalnızca bu katmanın söyleyebileceği şey: seçilen
 * klasör için hangi isteklerin TELE ÇIKTIĞI, ve kullanıcının sonunda ne
 * gördüğü.
 */

/*
 * bytesOf, bir Blob'un baytları.
 *
 * ⚠️ Blob.arrayBuffer() jsdom'da YOK; FileReader var. Arşivin
 * baytlarını gerçekten okumak, "kaydedildi" ile "içinde doğru şey var"
 * arasındaki farkı ölçebilmenin şartı.
 */
function bytesOf(b: Blob): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(new Uint8Array(r.result as ArrayBuffer));
    r.onerror = () => reject(r.error);
    r.readAsArrayBuffer(b);
  });
}

/** readOffset, bir FXP_READ paketindeki dosya konumu. */
function readOffset(b: Uint8Array): number {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const hlen = dv.getUint32(5);
  const at = 9 + hlen;

  return dv.getUint32(at) * 0x100000000 + dv.getUint32(at + 4);
}

/**
 * readAt, BELİRLİ bir konumu soran READ karesini bekler.
 *
 * ⚠️ TİPE BAKMAK YETMİYOR, KONUMA DA BAKILMALI. İstemci pencere
 * dolduracak kadar isteği aynı anda gönderiyor; "sıradaki READ" o
 * pencereden herhangi biri oluyor. Testin ilk hâli tipe bakıyordu ve
 * kısa cevaptan sonra istemcinin KALDIĞI YERDEN sorduğunu göremiyordu:
 * yanlış isteğe EOF veriyor, indirme asılı kalıyordu.
 */
async function readAt(ws: FakeWS, offset: number): Promise<number> {
  let found = -1;
  await waitFor(() => {
    for (let i = ws.cursor; i < ws.sent.length; i++) {
      const b = ws.body(i);
      if (b[0] === FXP.READ && readOffset(b) === offset) {
        found = i;
        return;
      }
    }
    throw new Error(`READ@${offset} bekleniyor`);
  });
  ws.cursor = found + 1;

  return found;
}

/** serveFile, bir OPEN/READ/READ(EOF) turunu cevaplar. */
async function serveFile(ws: FakeWS, content: Uint8Array) {
  const op = await next(ws, FXP.OPEN);
  await ws.deliver(
    0,
    packet(FXP.HANDLE, ...u32(idOf(ws.body(op))), ...str("fh")),
  );

  const first = await readAt(ws, 0);
  await ws.deliver(
    0,
    packet(
      FXP.DATA,
      ...u32(idOf(ws.body(first))),
      ...u32(content.length),
      ...Array.from(content),
    ),
  );

  /*
   * ⚠️ KISA CEVAP EOF DEĞİL: istemci teslim edilenin BİTTİĞİ yerden
   * soruyor ve dosyanın bittiğini ancak oradan öğreniyor. Konum burada
   * content.length — sabit ızgaradaki bir sonraki adım değil.
   */
  const beyond = await readAt(ws, content.length);
  await ws.deliver(
    0,
    packet(FXP.STATUS, ...u32(idOf(ws.body(beyond))), ...u32(FX.EOF)),
  );
}

describe("dizin indirme", () => {
  let saved: { name: string; blob: Blob } | null = null;
  let click: typeof HTMLAnchorElement.prototype.click;

  beforeEach(() => {
    saved = null;
    let last: Blob | null = null;

    /*
     * jsdom'da nesne URL'i yok. saveBlob'un yaptığı iki şeyi de
     * yakalıyoruz: Blob'u ve bağlantının `download` adını.
     */
    const u = globalThis.URL as unknown as {
      createObjectURL: (b: Blob) => string;
      revokeObjectURL: (s: string) => void;
    };
    u.createObjectURL = (b: Blob) => {
      last = b;
      return "blob:test";
    };
    u.revokeObjectURL = () => {};

    click = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
      saved = { name: this.download, blob: last! };
    };
  });

  afterEach(() => {
    HTMLAnchorElement.prototype.click = click;
  });

  it("klasörü gezip tek arşiv veriyor, bağa ve \".\" ile \"..\"ye girmiyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;
    await handshake(ws, "/home/yigit", [entry("proje", DIR)]);

    await userEvent.click(screen.getByLabelText("select proje"));
    await userEvent.click(screen.getByRole("button", { name: /Download/ }));

    // Klasörün kendisi.
    await serveDir(ws, [
      entry(".", DIR),
      entry("..", DIR),
      entry("src", DIR),
      entry("not.txt", FILE, 5),
      entry("guncel", LINK),
    ]);
    // Yalnızca gerçek alt dizin: "." ve ".." açılmadı.
    await serveDir(ws, [entry("main.go", FILE, 4)]);

    // Dosyalar derinlik önce: src/main.go, sonra not.txt.
    await serveFile(ws, new TextEncoder().encode("main"));
    await serveFile(ws, new TextEncoder().encode("nnnnn"));

    await waitFor(() => expect(saved).not.toBeNull());
    expect(saved!.name).toBe("proje.zip");

    /*
     * ⚠️ AÇILAN DİZİN SAYISI ÖLÇÜLÜYOR ve sebebi denetim defterinde:
     * her OPENDIR bir satır. "." ya da ".." açan bir gezgin burada
     * fazladan istekle yakalanır — ve gerçek bir hedefte sonsuza kadar
     * dönerdi.
     */
    const opendirs = ws.sent.filter((_, i) => ws.body(i)[0] === FXP.OPENDIR);
    expect(opendirs.length).toBe(3); // ev + proje + proje/src

    // Her dosya AYRI bir OPEN ile geçti: defterde kendi satırı var.
    const opens = ws.sent.filter((_, i) => ws.body(i)[0] === FXP.OPEN);
    expect(opens.length).toBe(2);

    // Arşivin içinde ağacın yolları ve eksikler notu var.
    const text = new TextDecoder().decode(await bytesOf(saved!.blob));
    expect(text).toContain("proje/src/main.go");
    expect(text).toContain("proje/not.txt");
    expect(text).toContain("POSTERN-NOT-INCLUDED.txt");
  });

  /*
   * ⚠️ ATLANANLAR YEŞİL SATIRIN İÇİNDE. Düz bir "tamamlandı", atlanmış
   * bir bağ varken kullanıcıya tam bir kopya aldığını söylerdi.
   */
  it("eksik varsa satır bunu yazıyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;
    await handshake(ws, "/home/yigit", [entry("proje", DIR)]);

    await userEvent.click(screen.getByLabelText("select proje"));
    await userEvent.click(screen.getByRole("button", { name: /Download/ }));

    await serveDir(ws, [entry("bag", LINK), entry("a.txt", FILE, 3)]);
    await serveFile(ws, new TextEncoder().encode("abc"));

    await waitFor(() =>
      expect(screen.getByText(/1 not included/)).toBeTruthy(),
    );
    expect(screen.getByText(/completed/)).toBeTruthy();
  });

  /*
   * ⚠️ DURDURULAN İNDİRMEDEN GERİYE HİÇBİR ŞEY KALMIYOR ve satır bunu
   * SÖYLÜYOR. Arşiv ancak sonunda kaydediliyor; "iptal edildi" deyip
   * kullanıcıyı yarım bir dosya aramaya göndermek yanlış olurdu.
   */
  it("durdurulan klasör indirmesi ne bırakmadığını söylüyor", async () => {
    render(<FileBrowser target="web01" canWrite />);
    const ws = FakeWS.last!;
    await handshake(ws, "/home/yigit", [entry("proje", DIR)]);

    await userEvent.click(screen.getByLabelText("select proje"));
    await userEvent.click(screen.getByRole("button", { name: /Download/ }));

    await serveDir(ws, [entry("a.txt", FILE, 3), entry("b.txt", FILE, 3)]);

    // İlk dosyanın OPEN'ı yola çıktı; durdurma ondan sonra geliyor.
    const op = await next(ws, FXP.OPEN);
    await userEvent.click(screen.getByRole("button", { name: "Stop" }));
    await ws.deliver(
      0,
      packet(FXP.HANDLE, ...u32(idOf(ws.body(op))), ...str("fh")),
    );

    await waitFor(() =>
      expect(screen.getByText(/nothing was saved/)).toBeTruthy(),
    );
    expect(saved).toBeNull();

    /*
     * ⚠️ İKİNCİ DOSYA HİÇ AÇILMADI. Durdurulan bir indirme sonraki
     * dosyaya geçseydi, defterde hiç okunmayan bir dosya için `open`
     * satırı kalırdı — "açıldı" diye okunan, karşılığında aktarım
     * satırı olmayan bir iz.
     */
    const opens = ws.sent.filter((_, i) => ws.body(i)[0] === FXP.OPEN);
    expect(opens.length).toBe(1);
  });
});
