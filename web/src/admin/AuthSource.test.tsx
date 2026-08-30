import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AuthSource from "./AuthSource";
import { api, type AuthSourceStatus } from "../api";

const status = (over: Partial<AuthSourceStatus> = {}): AuthSourceStatus => ({
  source: "local",
  stored: true,
  options: [
    { source: "local", eligible: true },
    { source: "oidc", eligible: true },
    { source: "ldap", eligible: true },
  ],
  ...over,
});

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal("confirm", vi.fn((_m?: string) => true));
});

describe("aktif giris kaynagi", () => {
  /*
   * ⚠️ SEÇİLEMEZ BİR SEÇENEĞİN SEBEBİ EKRANDA OLMALI.
   *
   * Gri bir düğme gösterip susmak, operatöre config dosyasında ya da
   * dizinde ne eksik olduğunu aratırdı — ve bu ekranda "aratmak",
   * çoğu zaman kimsenin giremediği bir panelde aramak demek.
   */
  it("secilemeyen kaynagin sebebini yazar ve dugmesini kapatir", async () => {
    vi.spyOn(api, "authSource").mockResolvedValue(
      status({
        options: [
          { source: "local", eligible: true },
          {
            source: "oidc",
            eligible: false,
            why: "the identity provider is not configured in the config file",
          },
          { source: "ldap", eligible: true },
        ],
      }),
    );

    render(<AuthSource />);
    await waitFor(() =>
      expect(
        screen.getByText(/identity provider is not configured/i),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByRole("button", { name: /switch panel sign-in to oidc/i }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: /switch panel sign-in to ldap/i }),
    ).toBeEnabled();
  });

  // Aktif kaynağın kendisine geçiş düğmesi olmamalı: hiçbir şey yapmayan
  // bir düğme, çalışmayan bir düğmeden ayırt edilemez.
  it("aktif kaynak icin dugme cizmez", async () => {
    vi.spyOn(api, "authSource").mockResolvedValue(status({ source: "local" }));
    render(<AuthSource />);

    await waitFor(() => expect(screen.getByText(/in use/i)).toBeInTheDocument());
    expect(
      screen.queryByRole("button", { name: /switch panel sign-in to local/i }),
    ).toBeNull();
  });

  /*
   * ⚠️ "SEÇİLDİ" İLE "TÜRETİLDİ" AYRI GÖRÜNMELİ.
   *
   * Ayarı hiç yazmamış bir kurulumda kaynak config dosyasından
   * çıkarılıyor. Bunu seçilmiş gibi göstermek, operatöre hiç vermediği
   * bir kararı verdiğini düşündürür — ve o karar, panelin kapısı.
   */
  it("turetilmis kaynagi acikca soyler", async () => {
    vi.spyOn(api, "authSource").mockResolvedValue(
      status({ source: "oidc", stored: false }),
    );
    render(<AuthSource />);

    await waitFor(() =>
      expect(screen.getByText(/Nothing is stored, so this was derived/i)).toBeInTheDocument(),
    );
  });

  it("saklanmis kaynakta o uyariyi cizmez", async () => {
    vi.spyOn(api, "authSource").mockResolvedValue(status({ stored: true }));
    render(<AuthSource />);

    await waitFor(() => expect(screen.getByText(/in use/i)).toBeInTheDocument());
    expect(screen.queryByText(/this was derived/i)).toBeNull();
  });

  // Geçişin ne kapattığı ve nasıl geri alınacağı onay metninde olmalı:
  // bu ekranın en olası kötü günü, metnin bir daha okunamadığı gün.
  it("onay metni kapanacaklari ve geri donus komutunu sayar", async () => {
    const confirmSpy = vi.fn((_m?: string) => true);
    vi.stubGlobal("confirm", confirmSpy);
    vi.spyOn(api, "authSource").mockResolvedValue(status({ source: "local" }));
    const set = vi
      .spyOn(api, "setAuthSource")
      .mockResolvedValue({ ok: true, source: "ldap", note: "done" });

    render(<AuthSource />);
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /switch panel sign-in to ldap/i }),
      ).toBeEnabled(),
    );
    await userEvent.click(
      screen.getByRole("button", { name: /switch panel sign-in to ldap/i }),
    );

    const msg = confirmSpy.mock.calls[0][0] ?? "";
    expect(msg).toMatch(/Every other sign-in method closes/i);
    expect(msg).toMatch(/auth\.source --value local/);
    await waitFor(() => expect(set).toHaveBeenCalledWith("ldap"));
  });

  // Çıkış yolu her zaman görünür: kötü gün geldiğinde bu ekran
  // açılmayacak, o yüzden iyi günde okunmuş olması gerekiyor.
  it("host'tan geri donus yolunu her zaman gosterir", async () => {
    vi.spyOn(api, "authSource").mockResolvedValue(status());
    render(<AuthSource />);

    await waitFor(() =>
      expect(
        screen.getByText(/postern settings set --key auth\.source --value local/),
      ).toBeInTheDocument(),
    );
  });
});
