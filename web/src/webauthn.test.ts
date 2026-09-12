import { describe, expect, it } from "vitest";
import {
  assertionToJSON,
  attestationToJSON,
  b64urlToBytes,
  bytesToB64url,
  toCreationOptions,
  toRequestOptions,
} from "./webauthn";

/*
 * ⚠️ BU DOSYA TEK BİR ARIZAYI KOVALIYOR: SESSİZ YANLIŞ ÇEVİRİ.
 *
 * Çeviri bozuksa ekranda görünen şey "anahtarınız kabul edilmedi" olur
 * ve suçlu doğrulayıcı sanılır. Üstelik meydan okumalar rastgele
 * olduğu için arıza ARA ARA çıkar — en pahalı tür.
 */
describe("base64url", () => {
  /*
   * ⚠️ base64url, base64 DEĞİL. "-" ve "_" karakterleri atob'a doğrudan
   * verilirse bozuk bayt üretiyor; meydan okumalar rastgele olduğu için
   * o karakterler zamanın bir kısmında geliyor.
   */
  it("base64'ün ayrıldığı iki karakteri doğru çözüyor", () => {
    // 0xfb 0xff 0xfe → base64 "+//+", base64url "-__-"
    const bytes = b64urlToBytes("-__-");

    expect(Array.from(bytes)).toEqual([0xfb, 0xff, 0xfe]);
  });

  it("dolgusuz dizgiyi çözüyor", () => {
    expect(Array.from(b64urlToBytes("QQ"))).toEqual([0x41]);
  });

  it("gidip geri geliyor", () => {
    const src = new Uint8Array([0, 1, 250, 251, 252, 253, 254, 255]);
    const round = b64urlToBytes(bytesToB64url(src.buffer));

    expect(Array.from(round)).toEqual(Array.from(src));
  });

  // ⚠️ Dolgu "=" base64url'de YOK: URL'de ve JSON'da taşınırken kaçış
  // gerektirdiği için şartname onu atıyor.
  it("dolgu üretmiyor", () => {
    expect(bytesToB64url(new Uint8Array([0x41]).buffer)).toBe("QQ");
  });
});

describe("seçenek çevirisi", () => {
  it("kayıt seçeneklerindeki metinleri tampona çeviriyor", () => {
    const opts = toCreationOptions({
      publicKey: {
        challenge: "QQ",
        user: { id: "Qg", name: "ayse", displayName: "ayse" },
        rp: { id: "postern.example.com", name: "postern" },
        pubKeyCredParams: [],
        excludeCredentials: [{ type: "public-key", id: "Qw" }],
      },
    });

    expect(Array.from(new Uint8Array(opts.challenge as ArrayBuffer))).toEqual([
      0x41,
    ]);
    expect(Array.from(new Uint8Array(opts.user.id as ArrayBuffer))).toEqual([
      0x42,
    ]);
    /*
     * ⚠️ excludeCredentials ÇEVRİLMEK ZORUNDA. Metin olarak bırakılsaydı
     * tarayıcı listeyi yok sayar ve aynı doğrulayıcı ikinci kez
     * kaydedilirdi: kullanıcı iki satır görür ve hangisinin hangi cihaz
     * olduğunu ayırt edemez.
     */
    expect(opts.excludeCredentials).toHaveLength(1);
    expect(
      Array.from(new Uint8Array(opts.excludeCredentials![0].id as ArrayBuffer)),
    ).toEqual([0x43]);
  });

  it("giriş seçeneklerindeki izinli anahtarları çeviriyor", () => {
    const opts = toRequestOptions({
      publicKey: {
        challenge: "QQ",
        allowCredentials: [
          { type: "public-key", id: "Qg", transports: ["usb"] },
        ],
      },
    });

    expect(opts.allowCredentials).toHaveLength(1);
    expect(
      Array.from(new Uint8Array(opts.allowCredentials![0].id as ArrayBuffer)),
    ).toEqual([0x42]);
    expect(opts.allowCredentials![0].transports).toEqual(["usb"]);
  });

  // Sunucu bazı yollarda publicKey sarmalayıcısı olmadan da gönderebilir.
  it("sarmalayıcısız gövdeyi de kabul ediyor", () => {
    expect(toRequestOptions({ challenge: "QQ" }).challenge).toBeTruthy();
  });
});

// bytes, testte tampon üretmeyi kısaltır.
const bytes = (...b: number[]) => new Uint8Array(b).buffer;

describe("yanıt çevirisi", () => {
  it("kayıt yanıtını şartnamedeki adlarla gönderiyor", () => {
    const json = attestationToJSON({
      id: "abc",
      rawId: bytes(0x41),
      type: "public-key",
      response: {
        clientDataJSON: bytes(0x42),
        attestationObject: bytes(0x43),
      },
    } as unknown as PublicKeyCredential) as any;

    expect(json.rawId).toBe("QQ");
    expect(json.response.clientDataJSON).toBe("Qg");
    expect(json.response.attestationObject).toBe("Qw");
  });

  /*
   * ⚠️ userHandle YOKSA GÖNDERİLMİYOR. Boş dizgi göndermek sunucuya
   * "kullanıcı kimliği budur" demek olurdu; yokluk ile boşluğu ayırmak
   * doğrulamanın kendi işi.
   */
  it("userHandle yoksa alanı hiç koymuyor", () => {
    const json = assertionToJSON({
      id: "abc",
      rawId: bytes(0x41),
      type: "public-key",
      response: {
        clientDataJSON: bytes(0x42),
        authenticatorData: bytes(0x43),
        signature: bytes(0x44),
        userHandle: null,
      },
    } as unknown as PublicKeyCredential) as any;

    expect(json.response.userHandle).toBeUndefined();
    expect(json.response.signature).toBe("RA");
  });

  it("userHandle varsa taşıyor", () => {
    const json = assertionToJSON({
      id: "abc",
      rawId: bytes(0x41),
      type: "public-key",
      response: {
        clientDataJSON: bytes(0x42),
        authenticatorData: bytes(0x43),
        signature: bytes(0x44),
        userHandle: bytes(0x45),
      },
    } as unknown as PublicKeyCredential) as any;

    expect(json.response.userHandle).toBe("RQ");
  });
});
