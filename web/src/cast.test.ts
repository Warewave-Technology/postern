import { describe, expect, it } from "vitest";
import { CastError, compress, duration, formatDuration, parseCast } from "./cast";

describe("parseCast", () => {
  const header = '{"version":2,"width":120,"height":30,"timestamp":1}';

  it("başlığı ve olayları okur", () => {
    const cast = parseCast(`${header}\n[0.1,"o","hello"]\n[0.5,"r","80x24"]\n`);

    expect(cast.header.width).toBe(120);
    expect(cast.events).toHaveLength(2);
    expect(cast.events[0]).toEqual({ time: 0.1, kind: "o", data: "hello" });
    expect(cast.truncated).toBe(false);
  });

  // Süren bir oturumun dosyası büyümeye devam ediyor. Yarım kalan SON
  // satırda durup işaretlemek, atmaktan iyi: izlenebilir olan kısım
  // izlenebilir kalıyor.
  it("yarim kalan son satirda durur ve isaretler", () => {
    const cast = parseCast(`${header}\n[0.1,"o","tam"]\n[0.2,"o","yar`);

    expect(cast.events).toHaveLength(1);
    expect(cast.truncated).toBe(true);
  });

  // Ortadaki bozuk bir satır gerçekten bozuk bir dosya demek — sessizce
  // yutmak, eksik bir kaydı tam sanmak olurdu.
  it("ortadaki bozuk satiri yutmaz", () => {
    expect(() => parseCast(`${header}\n[bozuk\n[0.2,"o","x"]\n`)).toThrow(CastError);
  });

  it("surumu desteklenmeyen kaydi reddeder", () => {
    expect(() => parseCast('{"version":1}\n')).toThrow(CastError);
  });

  it("bos kaydi reddeder", () => {
    expect(() => parseCast("")).toThrow(CastError);
  });
});

describe("compress", () => {
  // Uzun sessizlikler kısaltılmazsa üç saatlik bir kayıt üç saatte
  // izlenir — yani izlenmez, yani kayıt fiilen denetlenmez.
  it("sinirdan uzun bosluklari kisaltir", () => {
    const out = compress(
      [
        { time: 0, kind: "o", data: "a" },
        { time: 100, kind: "o", data: "b" },
      ],
      2,
    );

    expect(out[0].playAt).toBe(0);
    expect(out[1].playAt).toBe(2);
  });

  it("kisa bosluklara dokunmaz", () => {
    const out = compress(
      [
        { time: 0, kind: "o", data: "a" },
        { time: 1, kind: "o", data: "b" },
      ],
      2,
    );

    expect(out[1].playAt).toBe(1);
  });

  // Denetimde "ne zaman oldu" sorusunun cevabı oynatma hızından
  // bağımsız olmalı: sıkıştırma orijinal zaman damgasını DEĞİŞTİRMEZ.
  it("orijinal zaman damgasini korur", () => {
    const out = compress([{ time: 0, kind: "o", data: "a" }, { time: 100, kind: "o", data: "b" }], 2);

    expect(out[1].time).toBe(100);
  });

  it("sirali kalir", () => {
    const out = compress(
      [
        { time: 0, kind: "o", data: "a" },
        { time: 50, kind: "o", data: "b" },
        { time: 51, kind: "o", data: "c" },
      ],
      2,
    );

    expect(out[0].playAt).toBeLessThanOrEqual(out[1].playAt);
    expect(out[1].playAt).toBeLessThanOrEqual(out[2].playAt);
  });
});

describe("formatDuration", () => {
  it.each([
    [0, "0:00"],
    [5, "0:05"],
    [65, "1:05"],
    [3600, "1:00:00"],
    [3725, "1:02:05"],
    [-5, "0:00"],
  ])("%d saniye -> %s", (secs, want) => {
    expect(formatDuration(secs)).toBe(want);
  });
});

describe("duration", () => {
  it("bos kayit sifir", () => expect(duration([])).toBe(0));
  it("son olayin zamani", () =>
    expect(duration([{ time: 1, kind: "o", data: "" }, { time: 9, kind: "o", data: "" }])).toBe(9));
});
