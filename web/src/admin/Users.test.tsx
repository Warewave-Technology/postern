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
});

/*
 * ⚠️ ADMIN SÜTUNU BAŞLIĞI TEKRAR ETMİYOR.
 *
 * Başlığı "Admin" olan bir sütunda hücrenin "admin" demesi, soruyu
 * soruyla cevaplamaktı. Sütun bir evet/hayır soruyor; hücre onu
 * cevaplıyor.
 */
describe("admin sütunu", () => {
  it("evet/hayır cevabı veriyor, etiketi tekrarlamıyor", async () => {
    vi.spyOn(api, "users").mockResolvedValue([
      user({ name: "ops", admin: true }),
      user({ name: "ayse", admin: false }),
    ]);

    render(<Users publicKeyLogin localSource={true} />);
    await screen.findByText("ayse");

    const cells = [...document.querySelectorAll("tbody tr")].map((tr) =>
      (tr as HTMLTableRowElement).cells[2].textContent?.trim(),
    );
    expect(cells).toContain("yes");
    expect(cells).toContain("no");
    // "admin" YALNIZCA kullanıcı adı olarak geçebilir, hücrede değil.
    expect(cells).not.toContain("admin");
  });
});

/*
 * ⚠️ ANAHTAR SAYISI LİSTEDE.
 *
 * Sıfır anahtarlı bir hesap, rolü ne olursa olsun hiçbir hedefe SSH ile
 * ulaşamıyor. Sayıyı göstermeyen bir liste, "kim hiç bağlanamıyor"
 * sorusu için yöneticiyi her kullanıcıyı tek tek açmaya gönderiyordu.
 */
describe("anahtar sayısı", () => {
  it("sayıyı gösteriyor ve sıfırı sessizce vurguluyor", async () => {
    vi.spyOn(api, "users").mockResolvedValue([
      user({ name: "ayse", keys: 2 }),
      user({ name: "deniz", keys: 0 }),
    ]);

    render(<Users publicKeyLogin localSource={true} />);
    await screen.findByText("ayse");

    const keysCol = [...document.querySelectorAll("tbody tr")].map((tr) =>
      (tr as HTMLTableRowElement).cells[5].textContent?.trim(),
    );
    expect(keysCol).toEqual(["2", "0"]);
    // Sıfır bir açıklama taşıyor: sayı tek başına neden önemli olduğunu
    // söylemiyor.
    expect(
      screen.getByTitle(/cannot connect over SSH/i).textContent?.trim(),
    ).toBe("0");
  });

  // Anahtar girişi kapalıyken sütun HİÇ çizilmiyor: devre dışı bir
  // sütun, özelliğin bozuk mu kapalı mı olduğunu belirsiz bırakır.
  it("anahtar girişi kapalıyken sütun yok", async () => {
    vi.spyOn(api, "users").mockResolvedValue([user({ keys: 3 })]);
    render(<Users publicKeyLogin={false} localSource={true} />);
    await screen.findByRole("link", { name: "suheda" }).catch(() => null);
    await waitFor(() =>
      expect(document.querySelectorAll("tbody tr").length).toBe(1),
    );
    expect(
      [...document.querySelectorAll("th")].map((t) => t.textContent?.trim()),
    ).not.toContain("Keys");
  });
});
