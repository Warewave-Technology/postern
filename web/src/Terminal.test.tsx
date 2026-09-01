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

vi.mock("@xterm/xterm", () => ({
  Terminal: class {
    cols = 80;
    rows = 24;
    // Tema efekti term.options.theme'e yazıyor (Terminal.tsx:156).
    options: Record<string, unknown> = {};
    loadAddon() {}
    open() {}
    focus() {}
    write() {}
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
});
