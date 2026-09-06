import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";
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
    render(<FileBrowser target="web01" />);
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
    render(<FileBrowser target="web01" />);
    const ws = FakeWS.last!;

    await handshake(ws, "/home/yigit", [entry("gizli", DIR)]);
    await waitFor(() => expect(screen.getByText("gizli")).toBeTruthy());

    await userEvent.click(screen.getByRole("button", { name: /gizli/ }));

    const od = await next(ws, FXP.OPENDIR);
    await ws.deliver(
      0,
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
    render(<FileBrowser target="web01" />);
    const ws = FakeWS.last!;

    await handshake(ws, "/home/yigit", [entry("a.txt", FILE)]);
    await waitFor(() => expect(screen.getByText("a.txt")).toBeTruthy());

    await ws.deliver(1, new TextEncoder().encode("postern: /etc: refused\r\n"));

    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toBe(
        "postern: /etc: refused",
      ),
    );
    // Liste bozulmadı: stderr çözümleyiciye HİÇ girmedi.
    expect(screen.getByText("a.txt")).toBeTruthy();
  });

  it("dizin boyutu göstermiyor", async () => {
    render(<FileBrowser target="web01" />);
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
    render(<FileBrowser target="web01" />);
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
    render(<FileBrowser target="web01" />);
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
    expect(reason(new SFTPError(3, "postern: read-only session"))).toBe(
      "read-only session",
    );
  });

  it("hedefin kendi retini postern'inki gibi göstermiyor", () => {
    expect(
      reason(new SFTPError(FX.PERMISSION_DENIED, "Permission denied")),
    ).toContain("on the target");
  });

  it("kapanış sebebi yoksa kodu yazıyor", () => {
    expect(closeReason({ code: 1000, reason: "" })).toBe("session ended");
    expect(closeReason({ code: 1006, reason: "" })).toContain("1006");
  });
});
