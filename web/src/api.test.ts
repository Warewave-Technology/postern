import { describe, expect, it } from "vitest";
import { ApiError, api, onSessionLost, toMessage } from "./api";

// toMessage'ın BOŞ DÖNMEMESİ bir görünüm tercihi değil güvenlik
// özelliği: ErrorLine boş mesajda hiçbir şey çizmiyor, dolayısıyla
// başarısız bir SİLME işlemi başarılı olmuş gibi görünüyordu. Bir
// bastion'ın yetkilendirme ekranında sessizce başarısız olan bir iptal,
// olabilecek en kötü arızadır.
describe("toMessage", () => {
  it.each([
    ["bos dize", ""],
    ["undefined", undefined],
    ["null", null],
    ["mesajsiz Error", new Error("")],
    ["mesajsiz ApiError", new ApiError(500, "")],
    ["nesne", {}],
    ["sayi", 0],
  ])("%s icin bos donmez", (_name, input) => {
    const msg = toMessage(input);
    expect(msg).not.toBe("");
    expect(msg.trim().length).toBeGreaterThan(0);
  });

  it("ApiError mesajini kullanir", () => {
    expect(toMessage(new ApiError(409, "already exists"))).toBe("already exists");
  });

  it("mesajsiz ApiError'da durum kodunu soyler", () => {
    expect(toMessage(new ApiError(503, ""))).toContain("503");
  });

  // fetch ağ hatasında TypeError atar ve "Failed to fetch" kullanıcıya
  // hiçbir şey anlatmaz.
  it("ag hatasini insanca anlatir", () => {
    expect(toMessage(new TypeError("Failed to fetch"))).toMatch(/reach postern/i);
  });
});

/*
 * 401 HER UÇTAN geldiğinde duyurulmalı.
 *
 * ⚠️ Bu bir görünüm ayrıntısı değil: oturumu bitmiş kullanıcı, yönetim
 * ekranında "Error: unauthenticated" satırıyla oturup kalıyordu.
 * Ekrandaki her sayı artık geçersiz ama ekran duruyor — bir yetkilendirme
 * panelinde en yanıltıcı hâl bu. Yakalama api.ts'te TEK YERDE, çünkü
 * sayfa sayfa yakalamak bir sonraki eklenen sayfayı unutmak demek.
 */
describe("oturum kaybi duyurusu", () => {
  const withFetch = async (status: number, run: () => Promise<unknown>) => {
    const original = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ error: "unauthenticated" }), {
        status,
        headers: { "Content-Type": "application/json" },
      })) as typeof fetch;
    try {
      await run().catch(() => {});
    } finally {
      globalThis.fetch = original;
    }
  };

  it("401'de dinleyici cagrilir", async () => {
    let fired = 0;
    onSessionLost(() => fired++);
    await withFetch(401, () => api.users());
    expect(fired).toBe(1);
  });

  // 403 "bu isi yapamazsin", 401 "artik sen degilsin". Ikisini
  // karistirmak, yetkisi olmayan bir sayfaya bakan admini gerceklestigi
  // gibi oturumdan atardi.
  it("403 oturumu bitirmez", async () => {
    let fired = 0;
    onSessionLost(() => fired++);
    await withFetch(403, () => api.users());
    expect(fired).toBe(0);
  });

  it("500 oturumu bitirmez", async () => {
    let fired = 0;
    onSessionLost(() => fired++);
    await withFetch(500, () => api.users());
    expect(fired).toBe(0);
  });

  // Kayıt indirme gibi düz metin uçları da aynı kanaldan geçmeli:
  // biri unutulursa o yoldan gelen 401 yine ekranda kalırdı.
  it("duz metin uclari da duyurur", async () => {
    let fired = 0;
    onSessionLost(() => fired++);
    await withFetch(401, () => api.sessionRecording("abc"));
    expect(fired).toBe(1);
  });
});
