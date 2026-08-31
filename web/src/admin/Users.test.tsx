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
  vi.stubGlobal(
    "confirm",
    vi.fn((_m?: string) => true),
  );
  vi.spyOn(api, "roles").mockResolvedValue([]);
  /*
   * jsdom <dialog>'un showModal/close'unu uygulamıyor. Ekleme formu
   * modalda olduğu için onsuz o formu açan hiçbir test yazılamıyor —
   * ve yazılamayan test, yazılmayan testtir.
   */
  if (!HTMLDialogElement.prototype.showModal) {
    HTMLDialogElement.prototype.showModal = function () {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function () {
      this.open = false;
    };
  }
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
    render(<Users publicKeyLogin localSource={true} />);
    await waitFor(() =>
      expect(screen.getByText("inactive")).toBeInTheDocument(),
    );
  });

  it("aktif hesabi vurgulamaz", async () => {
    vi.spyOn(api, "users").mockResolvedValue([user()]);
    render(<Users publicKeyLogin localSource={true} />);
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
    const setState = vi
      .spyOn(api, "setUserState")
      .mockResolvedValue({ ok: true });

    render(<Users publicKeyLogin localSource={true} />);
    await userEvent.click(
      await screen.findByRole("button", { name: /deactivate suheda/i }),
    );
    await waitFor(() =>
      expect(setState).toHaveBeenCalledWith("suheda", "inactive"),
    );
  });

  it("pasif hesabi geri acar", async () => {
    vi.spyOn(api, "users").mockResolvedValue([user({ state: "inactive" })]);
    const setState = vi
      .spyOn(api, "setUserState")
      .mockResolvedValue({ ok: true });

    render(<Users publicKeyLogin localSource={true} />);
    await userEvent.click(
      await screen.findByRole("button", { name: /reactivate suheda/i }),
    );
    await waitFor(() =>
      expect(setState).toHaveBeenCalledWith("suheda", "active"),
    );
  });

  // Onay metni rollerin ve anahtarların KORUNDUĞUNU söylemeli: aksi
  // hâlde yönetici geri dönüşü olmayan bir işlem sanır ve yapmaz.
  it("onay metni geri donusun mumkun oldugunu soyler", async () => {
    const confirmSpy = vi.fn((_m?: string) => true);
    vi.stubGlobal("confirm", confirmSpy);
    vi.spyOn(api, "users").mockResolvedValue([user()]);
    vi.spyOn(api, "setUserState").mockResolvedValue({ ok: true });

    render(<Users publicKeyLogin localSource={true} />);
    await userEvent.click(
      await screen.findByRole("button", { name: /deactivate suheda/i }),
    );
    const msg = confirmSpy.mock.calls[0][0] ?? "";
    expect(msg).toMatch(/roles and keys are kept/i);
    expect(msg).toMatch(/signing in through the source reactivates them/i);
  });
});

/*
 * ⚠️ ADI SERBEST BIRAKMA YALNIZCA SİLİNMİŞ HESAPLARDA.
 *
 * Aktif ya da pasif birinin adını almak, o kişi hâlâ kullanıyorken
 * kimliğini elinden almak olurdu. Purge yaşam döngüsünün son adımı,
 * bir kısayol değil.
 */
describe("adi serbest birakma", () => {
  it("yalnizca silinmis hesapta gorunur", async () => {
    vi.spyOn(api, "users").mockResolvedValue([
      user({ name: "aktif", state: "active" }),
      user({ name: "pasif", state: "inactive" }),
      user({ name: "silinmis", state: "deleted" }),
    ]);
    render(<Users publicKeyLogin localSource={true} />);

    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /free the name silinmis/i }),
      ).toBeInTheDocument(),
    );
    expect(
      screen.queryByRole("button", { name: /free the name aktif/i }),
    ).toBeNull();
    expect(
      screen.queryByRole("button", { name: /free the name pasif/i }),
    ).toBeNull();
  });

  /*
   * ⚠️ ONAY METNİ, SATIRIN KALDIĞINI SÖYLEMEK ZORUNDA.
   *
   * "Free the name" okuyan yönetici bunu kalıcı bir silme sanabilir ve
   * ya yapmaz ya da geçmişi sildiğini düşünerek yapar. İkisi de yanlış:
   * kayıt duruyor, denetim okunabilir kalıyor.
   */
  it("onay metni kaydin kaldigini soyler", async () => {
    const confirmSpy = vi.fn((_m?: string) => true);
    vi.stubGlobal("confirm", confirmSpy);
    vi.spyOn(api, "users").mockResolvedValue([user({ state: "deleted" })]);
    const purge = vi.spyOn(api, "purgeUser").mockResolvedValue({
      ok: true,
      keys_released: 1,
      roles_released: 2,
      note: "",
    });

    render(<Users publicKeyLogin localSource={true} />);
    await userEvent.click(
      await screen.findByRole("button", { name: /free the name suheda/i }),
    );

    const msg = confirmSpy.mock.calls[0][0] ?? "";
    expect(msg).toMatch(/account row is kept/i);
    expect(msg).toMatch(/audit entries naming/i);
    expect(msg).toMatch(/records when the name\s+was released/i);
    await waitFor(() => expect(purge).toHaveBeenCalledWith("suheda"));
  });
});

describe("giriş bilgisi", () => {
  /*
   * ⚠️ DEĞER HESAPLA BİRLİKTE DOĞUYOR.
   *
   * Ayrı bir "ver" adımı vardı ve o adım unutulabilirdi: postern'de
   * kaydı olan ama hiçbir şekilde giremeyen bir kullanıcı, kimsenin
   * fark etmediği bir yarım iş. Kutu bir bildirim satırı DEĞİL, çünkü
   * değer bir daha gösterilemiyor.
   */
  it("kullanıcı yaratılınca değeri tek seferlik gösteriyor", async () => {
    vi.spyOn(api, "users").mockResolvedValue([]);
    vi.spyOn(api, "createUser").mockResolvedValue({
      username: "ayse",
      secret: "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ",
    });

    render(<Users publicKeyLogin={true} localSource={true} />);
    await screen.findByText(/no users/i).catch(() => null);

    await userEvent.click(screen.getByRole("button", { name: "New user" }));
    await userEvent.type(screen.getByLabelText(/^name/i), "ayse");
    await userEvent.type(screen.getByLabelText(/os user/i), "ayse");
    await userEvent.click(screen.getByRole("button", { name: /^create/i }));

    await waitFor(() =>
      expect(screen.getByText("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ")).toBeTruthy(),
    );
    expect(screen.getByText(/only time it is shown/i)).toBeTruthy();

    // Escape kutuyu KAPATMAMALI: kaydedilmemiş bir değeri kazara yok
    // etmek, onu bir daha üretememek demek.
    await userEvent.keyboard("{Escape}");
    expect(screen.getByText("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ")).toBeTruthy();
  });

  /*
   * ⚠️ HESAP AÇILDI AMA SIR VERİLEMEDİ HÂLİ YUTULMUYOR.
   *
   * Yutulsaydı, yönetici "oluştu" yazısını görüp giderdi ve geriye
   * hiçbir şekilde giremeyen bir kullanıcı kalırdı.
   */
  it("sır verilemediyse bunu söylüyor", async () => {
    vi.spyOn(api, "users").mockResolvedValue([]);
    vi.spyOn(api, "createUser").mockResolvedValue({
      username: "ayse",
      secret: "",
      credential_error: "a sign-in value could not be issued",
    });

    render(<Users publicKeyLogin={true} localSource={true} />);
    await userEvent.click(screen.getByRole("button", { name: "New user" }));
    await userEvent.type(screen.getByLabelText(/^name/i), "ayse");
    await userEvent.type(screen.getByLabelText(/os user/i), "ayse");
    await userEvent.click(screen.getByRole("button", { name: /^create/i }));

    await waitFor(() =>
      expect(screen.getByText(/could not be issued/i)).toBeTruthy(),
    );
  });

  /*
   * ⚠️ SIFIRLAMA YÖNETİCİ SATIRINDA YOK.
   *
   * Yöneticinin kimlik bilgisi acil durum kapısı ve yalnızca host'tan
   * çıkabiliyor. Panelden değiştirilebilseydi, paneli ele geçiren kişi
   * mevcut bir yöneticinin yerine geçerdi.
   */
  it("sıfırlama yalnızca yönetici olmayan satırlarda", async () => {
    vi.spyOn(api, "users").mockResolvedValue([
      user({ name: "ops", admin: true }),
      user({ name: "ayse", admin: false }),
    ]);

    render(<Users publicKeyLogin={true} localSource={true} />);
    await screen.findByText("ayse");

    expect(
      screen.getByLabelText("reset the sign-in value for ayse"),
    ).toBeTruthy();
    expect(
      screen.queryByLabelText("reset the sign-in value for ops"),
    ).toBeNull();
  });

  // Yerel kapı kapalıyken hiç çizilmiyor: orada üretilen bir değer
  // hiçbir zaman kullanılamaz.
  it("yerel kaynak kapalıyken sıfırlama hiç yok", async () => {
    vi.spyOn(api, "users").mockResolvedValue([user({ name: "ayse" })]);

    render(<Users publicKeyLogin={true} localSource={false} />);
    await screen.findByText("ayse");

    expect(
      screen.queryByLabelText("reset the sign-in value for ayse"),
    ).toBeNull();
  });

  it("sıfırlamada üstüne yazıldığını açıkça söylüyor", async () => {
    vi.spyOn(api, "users").mockResolvedValue([user({ name: "ayse" })]);
    vi.spyOn(api, "resetCredential").mockResolvedValue({
      username: "ayse",
      secret: "AAAA-BBBB",
      replaced: true,
    });

    render(<Users publicKeyLogin={true} localSource={true} />);
    await screen.findByText("ayse");
    await userEvent.click(
      screen.getByLabelText("reset the sign-in value for ayse"),
    );

    await waitFor(() =>
      expect(screen.getByText(/no longer works/i)).toBeTruthy(),
    );
  });
});
