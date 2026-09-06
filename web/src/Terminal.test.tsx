import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

/*
 * ⚠️ xterm TAKLİT EDİLİYOR, WebSocket DE.
 *
 * Sınanan şey terminal emülasyonu değil, KAPANIŞ SEBEBİNİN kullanıcıya
 * ulaşıp ulaşmadığı. Gerçek xterm'i çizdirmek testi jsdom'un canvas
 * eksiklerine bağlar ve ölçtüğümüz şeyi bulanıklaştırırdı.
 */
const written: string[] = [];
const bytes: Uint8Array[] = [];

vi.mock("@xterm/xterm", () => ({
  Terminal: class {
    cols = 80;
    rows = 24;
    // Tema efekti term.options.theme'e yazıyor (Terminal.tsx:156).
    options: Record<string, unknown> = {};
    loadAddon() {}
    open() {}
    focus() {}
    write(d: Uint8Array | string) {
      // Etiket ayıklamasını ölçebilmek için ham baytlar da tutuluyor.
      if (typeof d === "string") written.push(d);
      else bytes.push(new Uint8Array(d));
    }
    writeln(s: string) {
      written.push(s);
    }
    onData() {
      return { dispose() {} };
    }
    dispose() {}
  },
}));
vi.mock("@xterm/addon-fit", () => ({
  FitAddon: class {
    activate() {}
    dispose() {}
    fit() {}
  },
}));
vi.mock("@xterm/xterm/css/xterm.css", () => ({}));

class FakeWS {
  static last: FakeWS | null = null;
  binaryType = "";
  readyState = 0;
  onopen: (() => void) | null = null;
  onmessage: ((e: unknown) => void) | null = null;
  onclose: ((e: { reason?: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor() {
    FakeWS.last = this;
  }
  send() {}
  close() {}
}
/*
 * ⚠️ globalThis'e DOĞRUDAN yazıyoruz, vi.stubGlobal ile değil.
 *
 * Ölçüldü: stubGlobal testler arasında geri alınıyor ve ikinci testte
 * WebSocket yine tanımsız kalıyordu — ilk test geçip diğerleri
 * düşüyordu, yani sorun taklit ettiğimiz şeyde değil taklidin
 * ömründeydi.
 */
(globalThis as unknown as { WebSocket: unknown }).WebSocket = FakeWS;

/*
 * jsdom'da ResizeObserver yok; Terminal ilk fit'i ona bağlıyor
 * (Terminal.tsx'teki gerekçe: open() ile aynı tikte fit çağırmak
 * saçma bir hücre genişliği buluyor).
 *
 * globalThis'e DOĞRUDAN yazıyoruz: vi.stubGlobal testler arasında
 * geri alınabiliyor ve ikinci testte tekrar tanımsız kalıyordu.
 */
(globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

import Terminal from "./Terminal";

beforeEach(() => {
  written.length = 0;
  FakeWS.last = null;
});

describe("terminal kapanışı", () => {
  const mount = () => {
    render(<Terminal target="web01" theme="dark" />);
    if (!FakeWS.last) throw new Error("WebSocket hiç kurulmadı");
    return FakeWS.last;
  };

  /*
   * ⚠️ ÖLÇÜLEN ARIZA: hedefi bu bastion'ın CA'sına güvenecek şekilde
   * yapılandırmamış bir kurulumda, kabuk düğmesine basan kullanıcının
   * gördüğü tek şey "[disconnected]" idi. Sunucu sebebi biliyordu ama
   * WebSocket YÜKSELTİLMEDEN HTTP hatası döndürüyordu — ve tarayıcı,
   * başarısız bir el sıkışmanın durum kodunu da gövdesini de
   * JavaScript'e vermiyor. Sebep artık kapanış çerçevesiyle geliyor.
   */
  it("sunucunun verdiği sebebi yazıyor", () => {
    const ws = mount();
    ws.onclose?.({
      reason:
        "The target refused this bastion's certificate — it needs to trust the CA.",
    });
    expect(written.join("\n")).toContain("refused this bastion's certificate");
    expect(written.join("\n")).not.toContain("[disconnected]");
  });

  // Sebep yoksa eski metin kalmalı: normal çıkışta da onclose çalışıyor
  // ve orada söylenecek bir şey yok.
  it("sebep yoksa sade kapanış yazıyor", () => {
    const ws = mount();
    ws.onclose?.({ reason: "" });
    expect(written.join("\n")).toContain("[disconnected]");
  });

  it("sebep alanı hiç yoksa da çökmüyor", () => {
    const ws = mount();
    ws.onclose?.({});
    expect(written.join("\n")).toContain("[disconnected]");
  });

  /*
   * ⚠️ İLK BAYT AKIŞ ETİKETİ, EKRANA YAZILMAZ.
   *
   * Sunucu kanal verisini (0) ve stderr'i (1) ayrı etiketlerle gönderiyor —
   * ayrım SSH'ın kendi ayrımı ve bu kanal ileride SFTP taşıyacak. Etiketi
   * ayıklamayan bir istemci her çerçevenin başına görünmez bir karakter
   * yazar: terminalde göze çarpmaz, ikili bir protokolde çerçevelemeyi
   * kaydırır.
   */
  it("akis etiketini ayiklayip yaziyor", () => {
    bytes.length = 0;
    render(<Terminal target="web01" theme="dark" />);

    const frame = new Uint8Array([0, 0x68, 0x69]); // etiket 0 + "hi"
    FakeWS.last!.onmessage!({ data: frame.buffer });

    expect(bytes).toHaveLength(1);
    expect(Array.from(bytes[0])).toEqual([0x68, 0x69]);
  });

  it("stderr cercevesi de terminale yaziliyor", () => {
    bytes.length = 0;
    render(<Terminal target="web01" theme="dark" />);

    // Etiket 1 = stderr. Terminalde ikisi de aynı yere gidiyor: pty zaten
    // birleştiriyor ve kullanıcının gördüğü tek akış.
    FakeWS.last!.onmessage!({ data: new Uint8Array([1, 0x21]).buffer });

    expect(bytes).toHaveLength(1);
    expect(Array.from(bytes[0])).toEqual([0x21]);
  });

  // Boş çerçeve çökertmemeli: etiket bile yoksa yazacak bir şey yok.
  it("bos cerceveyi yok sayiyor", () => {
    bytes.length = 0;
    render(<Terminal target="web01" theme="dark" />);

    FakeWS.last!.onmessage!({ data: new Uint8Array([]).buffer });

    expect(bytes).toHaveLength(0);
  });
});
