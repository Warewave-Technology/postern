import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import MyKeys from "./MyKeys";
import { ApiError, api } from "./api";

const key = {
  fingerprint: "SHA256:aaaa",
  comment: "you@laptop",
  added_at: "2026-08-29T10:00:00Z",
};

describe("kendi anahtarlarim", () => {
  it("ilk anahtar icin yeniden dogrulama SORMAZ", async () => {
    vi.spyOn(api, "myKeys").mockResolvedValue({
      keys: [],
      reauth_required: false,
      reauth_possible: true,
    });
    const add = vi.spyOn(api, "addMyKey").mockResolvedValue({ ok: true });

    render(<MyKeys />);
    await waitFor(() =>
      expect(screen.getByLabelText(/Public key/i)).toBeInTheDocument(),
    );

    expect(screen.queryByLabelText(/sign-in secret/i)).not.toBeInTheDocument();

    await userEvent.type(
      screen.getByLabelText(/Public key/i),
      "ssh-ed25519 AAAA test",
    );
    await userEvent.click(screen.getByRole("button", { name: /Add key/i }));

    await waitFor(() =>
      expect(add).toHaveBeenCalledWith("ssh-ed25519 AAAA test", ""),
    );
  });

  /*
   * ⚠️ Anahtarı OLAN hesaba ikinci anahtar eklemek, oturumu ele geçiren
   * birinin kalıcılık kurma hamlesi — parola değişse bile yaşayan bir
   * giriş bırakır. O yüzden postern yeniden soruyor.
   */
  it("ikinci anahtar icin sir ister ve gerekcesini soyler", async () => {
    vi.spyOn(api, "myKeys").mockResolvedValue({
      keys: [key],
      reauth_required: true,
      reauth_possible: true,
    });
    const add = vi.spyOn(api, "addMyKey").mockResolvedValue({ ok: true });

    render(<MyKeys />);
    await waitFor(() =>
      expect(screen.getByLabelText(/sign-in secret/i)).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/stolen session would keep access/i),
    ).toBeInTheDocument();

    await userEvent.type(
      screen.getByLabelText(/Public key/i),
      "ssh-ed25519 BBBB",
    );
    await userEvent.type(screen.getByLabelText(/sign-in secret/i), "AAAA-BBBB");
    await userEvent.click(screen.getByRole("button", { name: /Add key/i }));

    await waitFor(() =>
      expect(add).toHaveBeenCalledWith("ssh-ed25519 BBBB", "AAAA-BBBB"),
    );
  });

  // Doğrulanabilir bir sır yoksa uydurma bir kutu göstermek yerine
  // çalışan yolu söyle.
  it("yeniden dogrulanamayan hesaba formu HIC gostermez", async () => {
    vi.spyOn(api, "myKeys").mockResolvedValue({
      keys: [key],
      reauth_required: true,
      reauth_possible: false,
    });

    render(<MyKeys />);
    await waitFor(() =>
      expect(screen.getByText(/Ask an administrator/i)).toBeInTheDocument(),
    );
    expect(screen.queryByLabelText(/Public key/i)).not.toBeInTheDocument();
  });

  it("sunucu reddederse hatayi gosterir", async () => {
    vi.spyOn(api, "myKeys").mockResolvedValue({
      keys: [],
      reauth_required: false,
      reauth_possible: true,
    });
    vi.spyOn(api, "addMyKey").mockRejectedValue(
      new ApiError(409, "public key login is switched off on this bastion"),
    );

    render(<MyKeys />);
    await waitFor(() =>
      expect(screen.getByLabelText(/Public key/i)).toBeInTheDocument(),
    );

    await userEvent.type(
      screen.getByLabelText(/Public key/i),
      "ssh-ed25519 AAAA",
    );
    await userEvent.click(screen.getByRole("button", { name: /Add key/i }));

    await waitFor(() =>
      expect(
        screen.getByText(/switched off on this bastion/i),
      ).toBeInTheDocument(),
    );
  });
});

/*
 * ⚠️ KENDİ ANAHTARINI KALDIRABİLMEK.
 *
 * Uç ve denetim satırı ilk günden vardı ama panelde çağıran yoktu —
 * üstelik silme ucu anahtarın METNİNİ istiyordu ve liste ucu metni hiç
 * döndürmüyor, yani panelin ucun istediği değere sahip olması mümkün
 * değildi. Sonuç: anahtarının ele geçtiğini fark eden kullanıcı onu
 * iptal edemiyordu — bu ekranın kendi gerekçesi ikinci anahtarı
 * "saldırganın kalıcılık kurma hamlesi" diye tanımlarken.
 */
describe("kendi anahtarımı kaldırmak", () => {
  const key = {
    fingerprint: "SHA256:abc123",
    comment: "laptop",
    added_at: "2026-08-01T00:00:00Z",
  };

  it("parmak iziyle siliyor", async () => {
    vi.stubGlobal(
      "confirm",
      vi.fn((_m?: string) => true),
    );
    vi.spyOn(api, "myKeys").mockResolvedValue({
      keys: [key],
      reauth_required: true,
      reauth_possible: true,
    });
    const rm = vi
      .spyOn(api, "removeMyKeyByFingerprint")
      .mockResolvedValue({ ok: true });

    render(<MyKeys />);
    await screen.findByText("SHA256:abc123");
    await userEvent.click(
      screen.getByRole("button", { name: /remove key SHA256:abc123/i }),
    );

    await waitFor(() => expect(rm).toHaveBeenCalledWith("SHA256:abc123"));
  });

  /*
   * ⚠️ ONAY, SON ANAHTAR OLMA İHTİMALİNİ SÖYLÜYOR. Tek anahtarını
   * silen kişi bağlantısını kaybediyor ve bunu sonradan öğrenmemeli.
   */
  it("onay son anahtar uyarısını taşıyor", async () => {
    const confirmSpy = vi.fn((_m?: string) => true);
    vi.stubGlobal("confirm", confirmSpy);
    vi.spyOn(api, "myKeys").mockResolvedValue({
      keys: [key],
      reauth_required: true,
      reauth_possible: true,
    });
    vi.spyOn(api, "removeMyKeyByFingerprint").mockResolvedValue({ ok: true });

    render(<MyKeys />);
    await screen.findByText("SHA256:abc123");
    await userEvent.click(
      screen.getByRole("button", { name: /remove key SHA256:abc123/i }),
    );
    expect(confirmSpy.mock.calls[0][0] ?? "").toMatch(/last one/i);
  });
});
