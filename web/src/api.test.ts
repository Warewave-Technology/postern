import { describe, expect, it } from "vitest";
import { ApiError, toMessage } from "./api";

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
