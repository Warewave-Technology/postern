import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Users from "./Users";
import { api, type User } from "../api";

const user = (over: Partial<User> = {}): User => ({
  name: "suheda",
  os_user: "suheda",
  admin: false,
  roles: [],
  keys: 0,
  state: "active",
  ...over,
});

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal("confirm", vi.fn((_m?: string) => true));
  vi.spyOn(api, "roles").mockResolvedValue([]);
});

describe("hesap durumu", () => {
  /*
   * ⚠️ PASİF HESAP LİSTEDE GÖRÜNMELİ.
   *
   * Kaynağın bir süredir doğrulamadığı hesaplar kendiliğinden
   * pasifleşiyor. Bunu göstermeyen bir liste "neden giremiyorum"
   * sorusunu cevaplayamaz ve yönetici postern'de bir arıza arar —
   * oysa cevap "kaynak bu kişiyi doğrulamıyor".
   */
  it("pasif hesabi isaretler", async () => {
    vi.spyOn(api, "users").mockResolvedValue([
      user({ state: "inactive", last_confirmed: "2026-06-01T00:00:00Z" }),
    ]);
    render(<Users publicKeyLogin />);
    await waitFor(() =>
      expect(screen.getByText("inactive")).toBeInTheDocument(),
    );
  });

  it("aktif hesabi vurgulamaz", async () => {
    vi.spyOn(api, "users").mockResolvedValue([user()]);
    render(<Users publicKeyLogin />);
    await waitFor(() => expect(screen.getByText("active")).toBeInTheDocument());
    expect(screen.queryByText("inactive")).toBeNull();
  });

  /*
   * ⚠️ PASİFLEŞTİRME PANELDEN YAPILABİLİR — yönetici bayrağından
   * farklı olarak. is_admin yetki YÜKSELTİYOR, pasifleştirme yetkiyi
   * KALDIRIYOR; kaldırma yönündeki bir işlemi host'a bağlamak olay
   * müdahalesini yavaşlatmaktan başka bir şey yapmaz.
   */
  it("pasiflestirme sunucuya gider", async () => {
    vi.spyOn(api, "users").mockResolvedValue([user()]);
    const setState = vi.spyOn(api, "setUserState").mockResolvedValue({ ok: true });

    render(<Users publicKeyLogin />);
    await userEvent.click(
      await screen.findByRole("button", { name: /deactivate suheda/i }),
    );
    await waitFor(() =>
      expect(setState).toHaveBeenCalledWith("suheda", "inactive"),
    );
  });

  it("pasif hesabi geri acar", async () => {
    vi.spyOn(api, "users").mockResolvedValue([user({ state: "inactive" })]);
    const setState = vi.spyOn(api, "setUserState").mockResolvedValue({ ok: true });

    render(<Users publicKeyLogin />);
    await userEvent.click(
      await screen.findByRole("button", { name: /reactivate suheda/i }),
    );
    await waitFor(() => expect(setState).toHaveBeenCalledWith("suheda", "active"));
  });

  // Onay metni rollerin ve anahtarların KORUNDUĞUNU söylemeli: aksi
  // hâlde yönetici geri dönüşü olmayan bir işlem sanır ve yapmaz.
  it("onay metni geri donusun mumkun oldugunu soyler", async () => {
    const confirmSpy = vi.fn((_m?: string) => true);
    vi.stubGlobal("confirm", confirmSpy);
    vi.spyOn(api, "users").mockResolvedValue([user()]);
    vi.spyOn(api, "setUserState").mockResolvedValue({ ok: true });

    render(<Users publicKeyLogin />);
    await userEvent.click(
      await screen.findByRole("button", { name: /deactivate suheda/i }),
    );
    const msg = confirmSpy.mock.calls[0][0] ?? "";
    expect(msg).toMatch(/roles and keys are kept/i);
    expect(msg).toMatch(/signing in through the source reactivates them/i);
  });
});
