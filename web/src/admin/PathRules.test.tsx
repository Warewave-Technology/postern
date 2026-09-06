import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import PathRules from "./PathRules";
import { api, type PathRule } from "../api";

const rule = (over: Partial<PathRule> = {}): PathRule => ({
  prefix: "/var/log",
  allow: true,
  can_write: false,
  ...over,
});

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal(
    "confirm",
    vi.fn((_m?: string) => true),
  );
});

describe("kuralsız rol", () => {
  /**
   * ⚠️ BU EKRANIN EN ÖNEMLİ CÜMLESİ.
   *
   * Boş bir tablo "hiçbir yere erişemez" diye okunur. Gerçek tam tersi:
   * kuralsız rol KISITSIZ. Yanılgı yanlış tarafa düşüyor — yönetici
   * koymadığı bir korumayı koymuş sanar ve aramayı bırakır.
   */
  it("kısıtsız olduğunu açıkça yazıyor", async () => {
    vi.spyOn(api, "rolePaths").mockResolvedValue([]);
    render(<PathRules role="ops" />);

    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toMatch(/unrestricted/),
    );
    expect(screen.queryByRole("table")).toBeNull();
  });
});

describe("kural listesi", () => {
  it("erişim türünü ayırt ediyor", async () => {
    vi.spyOn(api, "rolePaths").mockResolvedValue([
      rule({ prefix: "/home/dev", can_write: true }),
      rule({ prefix: "/home/dev/.ssh", allow: false }),
      rule({ prefix: "/var/log" }),
    ]);
    render(<PathRules role="dev" />);

    await waitFor(() => expect(screen.getByRole("table")).toBeTruthy());
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows[0].textContent).toContain("read-write");
    expect(rows[1].textContent).toContain("denied");
    expect(rows[2].textContent).toContain("read-only");
  });

  /**
   * ⚠️ SON KURALI SİLMEK BİR DARALTMA DEĞİL, KISITIN KALKMASI.
   *
   * Onay metni bunu söylemezse yönetici tek satır sildiğini sanır ve
   * rolü herkese açar.
   */
  it("son kuralı silerken kısıtın kalkacağını söylüyor", async () => {
    vi.spyOn(api, "rolePaths").mockResolvedValue([rule()]);
    const del = vi.spyOn(api, "deleteRolePath").mockResolvedValue(undefined);
    render(<PathRules role="ops" />);

    await waitFor(() => expect(screen.getByRole("table")).toBeTruthy());
    await userEvent.click(screen.getByRole("button", { name: /remove rule/ }));

    const asked = (globalThis.confirm as ReturnType<typeof vi.fn>).mock
      .calls[0][0] as string;
    expect(asked).toMatch(/unrestricted/);
    expect(del).toHaveBeenCalledWith("ops", "/var/log");
  });

  it("birden çok kural varken kısıt kalkmıyor demiyor", async () => {
    vi.spyOn(api, "rolePaths").mockResolvedValue([
      rule(),
      rule({ prefix: "/tmp" }),
    ]);
    vi.spyOn(api, "deleteRolePath").mockResolvedValue(undefined);
    render(<PathRules role="ops" />);

    await waitFor(() => expect(screen.getByRole("table")).toBeTruthy());
    await userEvent.click(
      screen.getByRole("button", {
        name: "remove rule /var/log from role ops",
      }),
    );

    const asked = (globalThis.confirm as ReturnType<typeof vi.fn>).mock
      .calls[0][0] as string;
    expect(asked).not.toMatch(/unrestricted/);
  });
});

describe("kural ekleme", () => {
  it("erişim seçimini doğru alanlara çeviriyor", async () => {
    vi.spyOn(api, "rolePaths").mockResolvedValue([]);
    const set = vi.spyOn(api, "setRolePath").mockResolvedValue(undefined);
    render(<PathRules role="ops" />);
    await waitFor(() => expect(screen.getByRole("status")).toBeTruthy());

    await userEvent.type(screen.getByLabelText("Prefix"), "/srv");
    await userEvent.selectOptions(screen.getByLabelText(/access for/), "write");
    await userEvent.click(screen.getByRole("button", { name: "Add rule" }));

    expect(set).toHaveBeenCalledWith("ops", {
      prefix: "/srv",
      allow: true,
      can_write: true,
    });
  });

  /**
   * ⚠️ RET, YAZMA İZNİ TAŞIMIYOR. Sunucu bu çelişkiyi zaten reddediyor;
   * arayüzün onu HİÇ üretmemesi gerekiyor, yoksa kullanıcı sebebini
   * anlamadığı bir hata alır.
   */
  it("ret seçildiğinde yazma göndermiyor", async () => {
    vi.spyOn(api, "rolePaths").mockResolvedValue([]);
    const set = vi.spyOn(api, "setRolePath").mockResolvedValue(undefined);
    render(<PathRules role="ops" />);
    await waitFor(() => expect(screen.getByRole("status")).toBeTruthy());

    await userEvent.type(screen.getByLabelText("Prefix"), "/etc");
    await userEvent.selectOptions(screen.getByLabelText(/access for/), "deny");
    await userEvent.click(screen.getByRole("button", { name: "Add rule" }));

    expect(set).toHaveBeenCalledWith("ops", {
      prefix: "/etc",
      allow: false,
      can_write: false,
    });
  });

  it("baştaki ve sondaki boşluğu kırpıyor", async () => {
    vi.spyOn(api, "rolePaths").mockResolvedValue([]);
    const set = vi.spyOn(api, "setRolePath").mockResolvedValue(undefined);
    render(<PathRules role="ops" />);
    await waitFor(() => expect(screen.getByRole("status")).toBeTruthy());

    // Gözle görünmeyen bir boşluk, hiçbir zaman eşleşmeyen bir kural
    // yazdırırdı: yönetici koruma koyduğunu sanır, koymamış olurdu.
    await userEvent.type(screen.getByLabelText("Prefix"), "  /srv  ");
    await userEvent.click(screen.getByRole("button", { name: "Add rule" }));

    expect(set.mock.calls[0][1].prefix).toBe("/srv");
  });

  it("sunucunun retini olduğu gibi gösteriyor", async () => {
    vi.spyOn(api, "rolePaths").mockResolvedValue([]);
    vi.spyOn(api, "setRolePath").mockRejectedValue(
      new Error(
        "prefix must be absolute: postern cannot resolve a relative path",
      ),
    );
    render(<PathRules role="ops" />);
    await waitFor(() => expect(screen.getByRole("status")).toBeTruthy());

    await userEvent.type(screen.getByLabelText("Prefix"), "var/log");
    await userEvent.click(screen.getByRole("button", { name: "Add rule" }));

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/must be absolute/),
    );
  });
});
