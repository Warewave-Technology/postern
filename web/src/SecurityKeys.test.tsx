import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import SecurityKeys from "./SecurityKeys";
import { api } from "./api";

beforeEach(() => {
  vi.restoreAllMocks();
  (window as any).PublicKeyCredential = function () {};
  Object.defineProperty(navigator, "credentials", {
    configurable: true,
    value: { create: vi.fn(), get: vi.fn() },
  });
});

const list = (only: boolean, n = 1) =>
  vi.spyOn(api, "webauthnList").mockResolvedValue({
    credentials: Array.from({ length: n }, (_, i) => ({
      id: `k${i}`,
      name: `anahtar ${i}`,
      created_at: "2026-09-01T10:00:00Z",
    })),
    only,
  });

/*
 * ⚠️ BU DOSYADAKİ EN ÖNEMLİ İDDİA: KART, KAZANILMAMIŞ BİR GÜVENCE
 * SATMIYOR.
 *
 * Anahtar kaydeden kullanıcı "artık güvendeyim" sanıyor. Oysa kod hâlâ
 * açıksa saldırgan anahtarı hiç sormadan kodu ister — yani hesabın
 * kimlik avına dayanıklılığı kodunki kadar. Kartın bunu YAZMASI
 * gerekiyor; susması, yanlış bir güven üretirdi.
 */
describe("guvenlik anahtari karti", () => {
  it("kod acikken hesabin hala kimlik avina acik oldugunu soyluyor", async () => {
    list(false);
    render(<SecurityKeys />);

    await waitFor(() =>
      expect(screen.getByText(/Codes are still accepted/i)).toBeInTheDocument(),
    );
    expect(screen.getByText(/as phishable as that code/i)).toBeInTheDocument();
  });

  it("kod kapaliyken kurtarma yolunun ne oldugunu soyluyor", async () => {
    list(true);
    render(<SecurityKeys />);

    await waitFor(() =>
      expect(screen.getByText(/Codes are off/i)).toBeInTheDocument(),
    );
    // ⚠️ Kurtarma kodu YOK ve bunu kilidi açmadan ÖNCE söylemek gerekiyor.
    expect(
      screen.getByText(/an administrator has to reset this/i),
    ).toBeInTheDocument();
  });

  /*
   * ⚠️ ANAHTAR YOKKEN KİLİT DÜĞMESİ HİÇ ÇİZİLMİYOR. Çizilseydi
   * kullanıcı kodu kapatıp kendini dışarıda bırakmayı deneyebilirdi;
   * sunucu reddediyor ama panelin çalışmayan bir düğme göstermesi
   * için sebep yok.
   */
  it("anahtar yokken kilit dugmesi yok", async () => {
    vi.spyOn(api, "webauthnList").mockResolvedValue({
      credentials: [],
      only: false,
    });
    render(<SecurityKeys />);

    await waitFor(() =>
      expect(screen.getByText(/No security key is registered/i)).toBeInTheDocument(),
    );
    expect(
      screen.queryByRole("button", { name: /stop accepting codes/i }),
    ).toBeNull();
  });

  /*
   * ⚠️ İPTAL HATA DEĞİL. Anahtarı takmaktan vazgeçen kullanıcıya kırmızı
   * bir satır göstermek, kendi kararını arıza sanmasına yol açar.
   */
  it("kullanici vazgecince hata gostermiyor", async () => {
    list(false);
    vi.spyOn(api, "webauthnBegin").mockResolvedValue({
      publicKey: { challenge: "QQ", user: { id: "Qg" } },
    });
    (navigator.credentials.create as any).mockRejectedValue(
      new Error("The operation either timed out or was not allowed"),
    );
    render(<SecurityKeys />);

    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /register a security key/i }),
      ).toBeInTheDocument(),
    );
    await userEvent.click(
      screen.getByRole("button", { name: /register a security key/i }),
    );

    await waitFor(() =>
      expect(api.webauthnBegin).toHaveBeenCalled(),
    );
    expect(screen.queryByRole("alert")).toBeNull();
  });

  // ⚠️ "Hiç kullanılmadı" ile bir tarih AYRI: kaybolan anahtarı silecek
  // olan kişi tam olarak buna bakıyor.
  it("hic kullanilmamis anahtari tarihle gostermiyor", async () => {
    list(false);
    render(<SecurityKeys />);

    await waitFor(() => expect(screen.getByText("never")).toBeInTheDocument());
  });
});
