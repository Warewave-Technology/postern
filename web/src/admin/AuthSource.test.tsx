import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AuthSource from "./AuthSource";
import { api, type AuthSourceStatus, type Setting } from "../api";

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
  vi.stubGlobal(
    "confirm",
    vi.fn((_m?: string) => true),
  );
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

    await waitFor(() =>
      expect(screen.getByText(/in use/i)).toBeInTheDocument(),
    );
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
      expect(
        screen.getByText(/Nothing is stored, so this was derived/i),
      ).toBeInTheDocument(),
    );
  });

  it("saklanmis kaynakta o uyariyi cizmez", async () => {
    vi.spyOn(api, "authSource").mockResolvedValue(status({ stored: true }));
    render(<AuthSource />);

    await waitFor(() =>
      expect(screen.getByText(/in use/i)).toBeInTheDocument(),
    );
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
        screen.getByText(
          /postern settings set --key auth\.source --value local/,
        ),
      ).toBeInTheDocument(),
    );
  });
});

/*
 * ⚠️ EKRANI OLMAYAN AYAR, PANELDEN YÖNETİLEBİLİR SAYILAMAZ.
 *
 * Üçü de sunucu tarafında panelden yazılabilir işaretliydi ama hiçbir
 * ekranda alanı yoktu. auth.auto_create'in tek yazıldığı yer kurulum
 * sihirbazıydı ve o bir kez bitince bir daha çizilmiyor: ilk kurulumda
 * "kuyruğa al" diyen bir kurum kararını bir daha değiştiremiyordu.
 */
describe("hesap politikası", () => {
  const withSettings = (rows: Setting[]) => {
    vi.spyOn(api, "authSource").mockResolvedValue({
      source: "local",
      stored: true,
      options: [{ source: "local", eligible: true }],
      unseen_mappings: [],
    });
    vi.spyOn(api, "settings").mockResolvedValue(rows);
    return render(<AuthSource />);
  };

  it("otomatik açılışın açık/kapalı olduğunu söylüyor ve çevirebiliyor", async () => {
    const set = vi
      .spyOn(api, "setSetting")
      .mockResolvedValue({ ok: true, source: "local" });
    withSettings([
      {
        key: "auth.auto_create",
        value: "true",
        secret: false,
        updated_by: "test",
      },
    ]);

    expect(
      await screen.findByText(/an account is created for them/i),
    ).toBeTruthy();

    await userEvent.click(
      screen.getByRole("button", { name: /queue new people for approval/i }),
    );
    await waitFor(() =>
      expect(set).toHaveBeenCalledWith("auth.auto_create", "false"),
    );
  });

  it("kuyruk modunda ne olduğunu söylüyor", async () => {
    withSettings([
      {
        key: "auth.auto_create",
        value: "false",
        secret: false,
        updated_by: "test",
      },
    ]);
    expect(await screen.findByText(/put in a queue/i)).toBeTruthy();
  });

  /*
   * ⚠️ ONAY METNİ NE OLACAĞINI SÖYLEMEK ZORUNDA. Otomatik açılışı
   * açmak, kaynağın kefil olduğu herkese yönetici bakmadan hesap
   * vermek demek; bunu söylemeyen bir düğme, kararı gizler.
   */
  it("otomatik açılışı açarken sonucunu söylüyor", async () => {
    const confirmSpy = vi.fn((_m?: string) => true);
    vi.stubGlobal("confirm", confirmSpy);
    vi.spyOn(api, "setSetting").mockResolvedValue({
      ok: true,
      source: "local",
    });
    withSettings([
      {
        key: "auth.auto_create",
        value: "false",
        secret: false,
        updated_by: "test",
      },
    ]);

    await userEvent.click(
      await screen.findByRole("button", {
        name: /create accounts automatically/i,
      }),
    );
    expect(confirmSpy.mock.calls[0][0] ?? "").toMatch(
      /without an administrator looking/i,
    );
  });

  // Hesap ömrü alanları mevcut değerle doluyor ve ikisi birden
  // kaydediliyor: birini kaydedip öbürünü unutmak, iki adımlı bir
  // yaşam döngüsünü yarım bırakır.
  it("hesap ömrünü okuyup kaydediyor", async () => {
    const set = vi
      .spyOn(api, "setSetting")
      .mockResolvedValue({ ok: true, source: "local" });
    withSettings([
      {
        key: "auth.confirm_ttl",
        value: "45d",
        secret: false,
        updated_by: "test",
      },
      {
        key: "auth.delete_after",
        value: "180d",
        secret: false,
        updated_by: "test",
      },
    ]);

    const box = await screen.findByLabelText(/deactivate after/i);
    expect((box as HTMLInputElement).value).toBe("45d");

    await userEvent.click(
      screen.getByRole("button", { name: /save the account lifetime/i }),
    );
    await waitFor(() =>
      expect(set).toHaveBeenCalledWith("auth.confirm_ttl", "45d"),
    );
    expect(set).toHaveBeenCalledWith("auth.delete_after", "180d");
  });
});

/*
 * ⚠️ "BAKAMADIM", "SORUN YOK" DEĞİLDİR — VE BURADA FARK EN PAHALISI.
 *
 * Eşleme kontrolü çöktüğünde uç `unseen_mappings` alanını boş
 * bırakıyordu ve panel hiçbir şey çizmiyordu: ekran, kontrolün
 * çalışıp temiz çıktığı hâlle BİREBİR aynı görünüyordu.
 *
 * Bu ekranın tek işi giriş kaynağını değiştirmeye karar vermek ve o,
 * ürünün en kilitlenme eğilimli işlemi. Sessiz bir "sorun yok", tam da
 * uyarının okunması gereken anda okunmuyordu.
 */
describe("eslemeler okunamadiginda", () => {
  it("bakamadigini soyler, 'hepsi yerinde' demez", async () => {
    vi.spyOn(api, "authSource").mockResolvedValue(
      status({ unseen_error: true }),
    );
    vi.spyOn(api, "settings").mockResolvedValue([] as Setting[]);

    render(<AuthSource />);

    await waitFor(() =>
      expect(
        screen.getByText(/mapping check could not run/i),
      ).toBeInTheDocument(),
    );
  });

  // Karşı taraf: kontrol çalışıp temiz çıktığında ekran sessiz kalmalı.
  // Olmasaydı, uyarıyı her zaman gösteren bir düzeltme de testi geçerdi.
  it("kontrol calisip temiz ciktiginda sessiz kalir", async () => {
    vi.spyOn(api, "authSource").mockResolvedValue(
      status({ unseen_mappings: [] }),
    );
    vi.spyOn(api, "settings").mockResolvedValue([] as Setting[]);

    render(<AuthSource />);

    // Ekranın YÜKLENDİĞİNİ bekle, sonra uyarının olmadığını doğrula:
    // yüklenmeden bakmak, her düzeltmeyi geçiren bir test olurdu.
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: /^sign-in$/i })).toBeInTheDocument(),
    );
    expect(screen.queryByText(/mapping check could not run/i)).toBeNull();
  });
});
