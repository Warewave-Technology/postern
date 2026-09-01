import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import UserDetail from "./UserDetail";
import { api, type UserDetail as Detail } from "../api";

const detail = (over: Partial<Detail> = {}): Detail => ({
  name: "suheda",
  os_user: "suheda",
  email: "suheda@warewave.io",
  admin: false,
  admin_via: "",
  state: "active",
  sso_only: false,
  dir_bound: false,
  roles: [],
  targets: [],
  keys: [],
  sessions: [],
  ...over,
});

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal(
    "confirm",
    vi.fn((_m?: string) => true),
  );
  vi.spyOn(api, "roles").mockResolvedValue([]);
});

const show = (over: Partial<Detail> = {}, props = {}) => {
  vi.spyOn(api, "userDetail").mockResolvedValue(detail(over));
  return render(
    <UserDetail
      name={over.name ?? "suheda"}
      publicKeyLogin={true}
      localSource={true}
      onBack={() => {}}
      {...props}
    />,
  );
};

describe("hesap durumu", () => {
  /*
   * ⚠️ PASİFLEŞTİRME PANELDEN YAPILABİLİR — yönetici bayrağından
   * farklı olarak. is_admin yetki YÜKSELTİYOR, pasifleştirme yetkiyi
   * KALDIRIYOR; kaldırma yönündeki bir işlemi host'a bağlamak olay
   * müdahalesini yavaşlatmaktan başka bir şey yapmaz.
   */
  it("pasiflestirme sunucuya gider", async () => {
    const setState = vi
      .spyOn(api, "setUserState")
      .mockResolvedValue({ ok: true });
    show();

    await userEvent.click(
      await screen.findByRole("button", { name: /deactivate suheda/i }),
    );
    await waitFor(() =>
      expect(setState).toHaveBeenCalledWith("suheda", "inactive"),
    );
  });

  it("pasif hesabi geri acar", async () => {
    const setState = vi
      .spyOn(api, "setUserState")
      .mockResolvedValue({ ok: true });
    show({ state: "inactive" });

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
    vi.spyOn(api, "setUserState").mockResolvedValue({ ok: true });
    show();

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
    show({ state: "active" });
    await screen.findByText("Account");
    expect(screen.queryByRole("button", { name: /free the name/i })).toBeNull();
  });

  /*
   * ⚠️ SİLİNMİŞ HESAPTA GERİ AÇMA DÜĞMESİ DE OLMALI.
   *
   * Bir ara koşul `state !== "deleted"` yazılmıştı ve sonucu şuydu:
   * yaşam döngüsü işinin kendiliğinden sildiği bir hesabın sayfasında
   * GERİ DÖNÜŞSÜZ olan tek düğme kalıyordu. Store bunun tersini açıkça
   * söylüyor: "'deleted'ten 'active'e dönüş SERBEST: yanlışlıkla
   * silinmiş bir hesabın geri gelememesi, tek tıkla kalıcı bir kayıp
   * demekti."
   */
  it("silinmis hesap geri acilabiliyor", async () => {
    const setState = vi
      .spyOn(api, "setUserState")
      .mockResolvedValue({ ok: true });
    show({ state: "deleted" });

    await userEvent.click(
      await screen.findByRole("button", { name: /^reactivate suheda$/i }),
    );
    await waitFor(() =>
      expect(setState).toHaveBeenCalledWith("suheda", "active"),
    );
  });

  // Geri açmanın onayı, bunun kalıcı bir çözüm OLMADIĞINI söylemeli:
  // kaynak hâlâ doğrulamıyorsa yaşam döngüsü işi hesabı yeniden kapatır
  // ve yönetici sorunu çözdüğünü sanır.
  it("geri acma onayi bunun gecici olabilecegini soyler", async () => {
    const confirmSpy = vi.fn((_m?: string) => true);
    vi.stubGlobal("confirm", confirmSpy);
    vi.spyOn(api, "setUserState").mockResolvedValue({ ok: true });
    show({ state: "deleted" });

    await userEvent.click(
      await screen.findByRole("button", { name: /^reactivate suheda$/i }),
    );
    expect(confirmSpy.mock.calls[0][0] ?? "").toMatch(/only a reprieve/i);
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
    const purge = vi.spyOn(api, "purgeUser").mockResolvedValue({
      ok: true,
      keys_released: 1,
      roles_released: 2,
      note: "",
    });
    show({ state: "deleted" });

    await userEvent.click(
      await screen.findByRole("button", { name: /free the name suheda/i }),
    );
    const msg = confirmSpy.mock.calls[0][0] ?? "";
    expect(msg).toMatch(/account row is kept/i);
    expect(msg).toMatch(/audit entries naming/i);
    await waitFor(() => expect(purge).toHaveBeenCalledWith("suheda"));
  });
});

describe("giriş bilgisi", () => {
  /*
   * ⚠️ YÖNETİCİDE SIFIRLAMA YOK.
   *
   * Yöneticinin kimlik bilgisi bir acil durum kapısı ve yalnızca
   * host'tan çıkabiliyor. Panelden değiştirilebilseydi, paneli ele
   * geçiren kişi mevcut bir yöneticinin yerine geçerdi. Düğmeyi
   * gizlemek bir kolaylık — asıl garanti sunucuda.
   */
  it("yönetici hesabında sıfırlama yok, sebebi yazıyor", async () => {
    show({ admin: true, admin_via: "cli" });
    await screen.findByText("Sign-in");

    expect(
      screen.queryByRole("button", { name: /reset the sign-in value/i }),
    ).toBeNull();
    expect(screen.getByText(/break-glass secret/i)).toBeTruthy();
  });

  it("sıradan hesapta sıfırlama var ve değeri tek kez gösteriyor", async () => {
    const reset = vi.spyOn(api, "resetCredential").mockResolvedValue({
      username: "suheda",
      secret: "AAAA-BBBB-CCCC",
      replaced: true,
    });
    show({
      credential: {
        kind: "password",
        must_change: false,
        created_at: "2026-08-01T00:00:00Z",
        created_by: "yigit",
      },
    });

    await userEvent.click(
      await screen.findByRole("button", {
        name: /reset the sign-in value for suheda/i,
      }),
    );
    await waitFor(() => expect(reset).toHaveBeenCalledWith("suheda"));
    expect(screen.getByText("AAAA-BBBB-CCCC")).toBeTruthy();
    expect(screen.getByText(/only time it is shown/i)).toBeTruthy();

    // Escape kutuyu KAPATMAMALI: değer bir daha üretilemiyor.
    await userEvent.keyboard("{Escape}");
    expect(screen.getByText("AAAA-BBBB-CCCC")).toBeTruthy();
  });

  // Yerel kapı kapalıyken kart hiç çizilmiyor: postern orada hiçbir
  // değer doğrulamıyor, göstermek uygulanmayan bir mekanizmayı varmış
  // gibi sunmak olurdu.
  it("yerel kaynak kapalıyken giriş bilgisi kartı yok", async () => {
    show({}, { localSource: false });
    await screen.findByText("Account");
    expect(screen.queryByText("Sign-in")).toBeNull();
  });

  /*
   * ⚠️ DEĞİŞTİRİLMEMİŞ DEĞER UYARI İSTİYOR.
   *
   * O hâldeki hesabın kimlik bilgisini VEREN de biliyor. Yöneticinin
   * bunu görmesi gerekiyor, çünkü "neden giremiyor" sorusunun cevabı
   * da bu: kişi giriyor ama paneli açamıyor.
   */
  it("değiştirilmemiş değer için uyarı çiziyor", async () => {
    show({
      credential: {
        kind: "issued",
        must_change: true,
        created_at: "2026-08-01T00:00:00Z",
        created_by: "yigit",
      },
    });
    await waitFor(() =>
      expect(screen.getByText(/still\s+knows the value/i)).toBeTruthy(),
    );
  });
});

describe("roller ve anahtarlar", () => {
  /*
   * ⚠️ ROLSÜZ HESAP UYARI İSTİYOR.
   *
   * Erişim yalnızca rollerden geliyor. Rolü olmayan bir hesap hiçbir
   * hedefe ulaşamıyor ve bunu söylemeyen bir ekran, yöneticiye işin
   * bittiğini düşündürür.
   */
  it("rolü olmayan hesabı uyarıyor", async () => {
    show({ roles: [] });
    await waitFor(() =>
      expect(screen.getByText(/reaches no target at all/i)).toBeTruthy(),
    );
  });

  /*
   * ⚠️ ROLÜ GERİ ALMAK ONAY İSTİYOR ve onay NEYİ kaybettirdiğini
   * söylüyor. Bir rolü geri almak, o kişinin eriştiği HER hedefi
   * anında kapatıyor; listeden detaya taşınırken bu koruma bir ara
   * düşmüştü.
   */
  it("rolü geri alabiliyor ve önce ne kaybedileceğini söylüyor", async () => {
    const confirmSpy = vi.fn((_m?: string) => true);
    vi.stubGlobal("confirm", confirmSpy);
    const revoke = vi.spyOn(api, "revokeRole").mockResolvedValue(undefined);
    show({ roles: [{ name: "ops", targets: ["web01", "db01"] }] });

    await userEvent.click(
      await screen.findByRole("button", { name: /revoke ops from suheda/i }),
    );
    const msg = confirmSpy.mock.calls[0][0] ?? "";
    expect(msg).toMatch(/web01, db01/);
    await waitFor(() => expect(revoke).toHaveBeenCalledWith("suheda", "ops"));
  });

  /*
   * ⚠️ REDDEDİLEN ANAHTAR KUTUDA KALMALI.
   *
   * run() hata durumunda da BAŞARIYLA çözülüyor (hatayı yutup ekrana
   * yazıyor). Temizlemeyi ona zincirlemek, sunucu "bu anahtar geçersiz"
   * dediğinde de kutuyu boşaltırdı: kullanıcı düzeltecek metni
   * kaybederdi.
   */
  it("sunucu anahtarı reddederse metin kutuda kalıyor", async () => {
    vi.spyOn(api, "addKey").mockRejectedValue(new Error("not a public key"));
    show();

    const box = await screen.findByLabelText(/add a public key/i);
    await userEvent.type(box, "bozuk-anahtar");
    await userEvent.click(
      screen.getByRole("button", { name: /add this key/i }),
    );

    await waitFor(() =>
      expect(screen.getByText(/not a public key/i)).toBeTruthy(),
    );
    expect((box as HTMLTextAreaElement).value).toBe("bozuk-anahtar");
  });

  /*
   * ⚠️ "ÇEKİLEMEDİ" İLE "HİÇ YOK" AYRI ŞEYLER.
   *
   * Rol listesi düşünce kutu "no roles defined" diyordu ve operatör
   * Roles ekranına gidip orada duran rolleri görüyordu.
   */
  it("rol listesi çekilemezse bunu söylüyor", async () => {
    vi.spyOn(api, "roles").mockRejectedValue(new Error("boom"));
    show();
    await waitFor(() =>
      expect(screen.getByText(/roles could not be loaded/i)).toBeTruthy(),
    );
  });

  /*
   * ⚠️ ANAHTARLAR PARMAK İZİYLE LİSTELENİYOR ve satır başına siliniyor.
   *
   * Eski hâl yalnızca bir SAYI gösteriyor, silmek için anahtarın
   * METNİNİ istiyordu — yani "şu anahtarı kaldır" demek için önce onu
   * başka bir yerden bulmak gerekiyordu. Gösterilmeyen bir şeyi silmek
   * kör bir tıklamadır.
   */
  it("anahtarı parmak iziyle siliyor", async () => {
    const rm = vi
      .spyOn(api, "removeKeyByFingerprint")
      .mockResolvedValue(undefined);
    show({
      keys: [
        {
          fingerprint: "SHA256:abc123",
          comment: "laptop",
          added_at: "2026-08-01T00:00:00Z",
        },
      ],
    });

    expect(await screen.findByText("SHA256:abc123")).toBeTruthy();
    await userEvent.click(
      screen.getByRole("button", {
        name: /remove key SHA256:abc123 from suheda/i,
      }),
    );
    await waitFor(() =>
      expect(rm).toHaveBeenCalledWith("suheda", "SHA256:abc123"),
    );
  });

  // Anahtar girişi kapalıyken kart hiç çizilmiyor: devre dışı bir kart,
  // özelliğin bozuk mu kapalı mı olduğunu belirsiz bırakır.
  it("anahtar girişi kapalıyken kart yok", async () => {
    show({}, { publicKeyLogin: false });
    await screen.findByText("Account");
    expect(screen.queryByText("SSH keys")).toBeNull();
  });
});

/*
 * ⚠️ YÖNETİCİLİĞİN KAYNAĞI EKRANDA.
 *
 * Grup üzerinden gelen yetki ile acil durum için elle açılmış hesap
 * ayırt edilemezse, operatör kaldıramayacağı bir yetkiyi
 * kaldırabileceğini sanır.
 */
describe("yöneticilik kaynağı", () => {
  it("gruptan geleni ve host'tan geleni ayırıyor", async () => {
    show({ admin: true, admin_via: "group" });
    expect(await screen.findByText(/from the directory group/i)).toBeTruthy();
  });

  it("cli ile verileni ayırıyor", async () => {
    show({ admin: true, admin_via: "cli" });
    expect(await screen.findByText(/granted on the host/i)).toBeTruthy();
  });
});

/*
 * ⚠️ OS KULLANICISI VE E-POSTA DÜZELTİLEBİLİR OLMAK ZORUNDA.
 *
 * Uç (PATCH) ve denetim satırı ilk günden vardı, panelde çağıran
 * yoktu: yanlış yazılmış bir OS kullanıcısını düzeltmek için host'a
 * girmek gerekiyordu. İkisi de kimlik EŞLEŞTİRME anahtarı — e-posta
 * OIDC eşleşmesinde, os_user hedefteki hesapta — yani yazım hatası
 * sessiz bir erişim sorunu demek.
 */
describe("hesap bilgilerini düzeltmek", () => {
  it("düzenleme kapalıyken alanlar yok", async () => {
    show();
    await screen.findByText("Account");
    expect(screen.queryByLabelText(/os user/i)).toBeNull();

    /*
     * ⚠️ GÖRÜNEN METNİ DE DOĞRULUYORUZ, yalnızca aria-label'ı değil.
     *
     * İlk hâli yalnızca etikete bakıyordu ve MUTASYON TESTİNİ GEÇTİ:
     * düğmenin yazısını "x" yapmak testi düşürmüyordu. Etiket ekran
     * okuyucunun duyduğu, yazı ise gözün gördüğü şey — ikisi de
     * doğrulanmalı.
     */
    const btn = screen.getByRole("button", { name: /edit these details/i });
    expect(btn.textContent?.trim()).toBe("Edit");
  });

  it("düzenleyip kaydedebiliyor", async () => {
    const patch = vi.spyOn(api, "patchUser").mockResolvedValue(undefined);
    show({ os_user: "syheda", email: "s@warewave.io" });

    await userEvent.click(
      await screen.findByRole("button", { name: /edit these details/i }),
    );

    const box = screen.getByLabelText(/os user/i) as HTMLInputElement;
    // Mevcut değerle doluyor: sıfırdan yazdırmak, düzeltmeyi yeniden
    // yazmaya çevirir.
    expect(box.value).toBe("syheda");

    await userEvent.clear(box);
    await userEvent.type(box, "suheda");
    await userEvent.click(
      screen.getByRole("button", { name: /save these details/i }),
    );

    await waitFor(() =>
      expect(patch).toHaveBeenCalledWith("suheda", {
        os_user: "suheda",
        email: "s@warewave.io",
      }),
    );
  });

  // Boş OS kullanıcısı gönderilemiyor: hedefte açılacak hesap o ve
  // boşu göndermek sunucudan bir hata almaktan başka bir şey yapmaz.
  it("OS kullanıcısı boşken kaydedilemiyor", async () => {
    show({ os_user: "suheda" });
    await userEvent.click(
      await screen.findByRole("button", { name: /edit these details/i }),
    );
    await userEvent.clear(screen.getByLabelText(/os user/i));
    expect(
      screen.getByRole("button", { name: /save these details/i }),
    ).toHaveProperty("disabled", true);
  });
});
