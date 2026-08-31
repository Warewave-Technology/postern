import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import OIDCSettingsScreen from "./OIDCSettings";
import { api, type OIDCSettings } from "../api";

const settings = (over: Partial<OIDCSettings> = {}): OIDCSettings => ({
  issuer_url: "",
  client_id: "",
  client_secret_set: false,
  managed_in_db: true,
  configured: false,
  live: false,
  ...over,
});

beforeEach(() => {
  vi.restoreAllMocks();
  // Yönetici grubu kaydetmek onay istiyor (yetki dağıtan bir eylem);
  // jsdom window.confirm'i uygulamıyor.
  vi.stubGlobal(
    "confirm",
    vi.fn((_m?: string) => true),
  );
});

const show = (over: Partial<OIDCSettings> = {}) => {
  vi.spyOn(api, "oidcSettings").mockResolvedValue(settings(over));
  return render(<OIDCSettingsScreen />);
};

/*
 * ⚠️ BU EKRANIN VAR OLMA SEBEBİ.
 *
 * Bu ayarlar bir süre YALNIZCA kurulum sihirbazının içinden
 * yazılabiliyordu; sihirbaz bitince bir daha çizilmiyor. Sonuç: ilk
 * kurulumda OIDC'yi seçmeyen bir kurulum onu sonradan HİÇ
 * yapılandıramıyor, dolayısıyla kaynağı da hiç OIDC'ye çeviremiyordu.
 */
describe("kimlik sağlayıcı ayarları", () => {
  it("hiç yapılandırılmamışken boş formu ve sebebini gösteriyor", async () => {
    show();
    expect(await screen.findByText(/not configured yet/i)).toBeTruthy();
    expect(
      (screen.getByLabelText(/issuer address/i) as HTMLInputElement).value,
    ).toBe("");
  });

  it("mevcut değerleri forma dolduruyor", async () => {
    show({
      issuer_url: "https://idp.example/realms/x",
      client_id: "postern",
      configured: true,
      live: true,
    });
    await waitFor(() =>
      expect(
        (screen.getByLabelText(/issuer address/i) as HTMLInputElement).value,
      ).toBe("https://idp.example/realms/x"),
    );
    expect(screen.getByText(/reached the provider/i)).toBeTruthy();
  });

  /*
   * ⚠️ BOŞ SIR "DEĞİŞTİRME" DEMEK, "TEMİZLE" DEĞİL.
   *
   * Boşu temizleme saymak, sırsız bir public client kurulumunu kazayla
   * silmenin — ya da var olan sırrı sessizce düşürmenin — yolu olurdu.
   */
  it("sır boşken gönderilmiyor", async () => {
    const set = vi
      .spyOn(api, "setOIDCSettings")
      .mockResolvedValue({ ok: true, live: true, error: "" });
    show({ issuer_url: "https://idp.example", client_id: "postern" });

    await waitFor(() =>
      expect(screen.getByLabelText(/client id/i)).toBeTruthy(),
    );
    await userEvent.click(
      screen.getByRole("button", { name: /save and test/i }),
    );

    await waitFor(() =>
      expect(set).toHaveBeenCalledWith(
        "https://idp.example",
        "postern",
        undefined,
      ),
    );
  });

  it("sır yazıldıysa gönderiliyor ve kutu temizleniyor", async () => {
    const set = vi
      .spyOn(api, "setOIDCSettings")
      .mockResolvedValue({ ok: true, live: true, error: "" });
    show({ issuer_url: "https://idp.example", client_id: "postern" });

    const box = await screen.findByLabelText(/client secret/i);
    await userEvent.type(box, "s3cret");
    await userEvent.click(
      screen.getByRole("button", { name: /save and test/i }),
    );

    await waitFor(() =>
      expect(set).toHaveBeenCalledWith(
        "https://idp.example",
        "postern",
        "s3cret",
      ),
    );
    // Sır ekranda ASILI KALMIYOR.
    await waitFor(() => expect((box as HTMLInputElement).value).toBe(""));
  });

  /*
   * ⚠️ "AYARLI" İLE "ÇALIŞIYOR" AYRI SORULAR.
   *
   * Ayarlı ama ulaşılamayan bir sağlayıcıya geçmek, kimsenin
   * giremediği bir panel bırakır. Ekran ikisini karıştırmamalı.
   */
  it("ayarlı ama ulaşılamıyorsa bunu ayrıca söylüyor", async () => {
    show({
      issuer_url: "https://idp.example",
      client_id: "postern",
      configured: true,
      live: false,
    });
    expect(await screen.findByText(/has not been able to reach/i)).toBeTruthy();
  });

  /*
   * ⚠️ ULAŞILAMASA BİLE AYARLAR KAYDEDİLİYOR ve alanlar KORUNUYOR.
   *
   * Aksi hâlde çalışmayan bir sağlayıcı hiçbir zaman düzeltilemezdi:
   * kaydetmek için ulaşmak, ulaşmak için kaydetmek gerekirdi.
   */
  it("ulaşılamadığında hatayı gösteriyor ama yazılanı silmiyor", async () => {
    vi.spyOn(api, "setOIDCSettings").mockResolvedValue({
      ok: true,
      live: false,
      error: "connection refused",
    });
    show({ issuer_url: "https://idp.example", client_id: "postern" });

    await waitFor(() =>
      expect(screen.getByLabelText(/client id/i)).toBeTruthy(),
    );
    await userEvent.click(
      screen.getByRole("button", { name: /save and test/i }),
    );

    await waitFor(() =>
      expect(screen.getByText(/connection refused/i)).toBeTruthy(),
    );
    expect(
      (screen.getByLabelText(/issuer address/i) as HTMLInputElement).value,
    ).toBe("https://idp.example");
  });

  // Zorunlu alanlar boşken gönderilemiyor: sunucu zaten reddederdi ama
  // kullanıcıya bunu bir hata satırıyla öğretmek gereksiz.
  it("zorunlu alanlar boşken kaydedilemiyor", async () => {
    show();
    await screen.findByText(/not configured yet/i);
    expect(
      screen.getByRole("button", { name: /save and test/i }),
    ).toHaveProperty("disabled", true);
  });

  /*
   * ⚠️ HEDEF DEĞİŞİRSE SIRRIN DÜŞECEĞİ ÖNCEDEN YAZIYOR.
   *
   * Sunucudaki kural: panel yöneticisi issuer'ı kendi sunucusuna
   * çevirip saklanan sırrı oraya gönderemesin. Söylenmezse operatör
   * sırrın neden kaybolduğunu bir arıza sanar.
   */
  it("sır varken, hedefi değiştirmenin onu düşüreceğini söylüyor", async () => {
    show({
      issuer_url: "https://idp.example",
      client_id: "postern",
      client_secret_set: true,
      configured: true,
    });
    expect(await screen.findByText(/drops the stored\s+secret/i)).toBeTruthy();
  });
});

/*
 * ⚠️ YÖNETİCİ GRUBU BURADA DA AYARLANABİLMELİ.
 *
 * Aynı ayarın tam hâli DİZİN ekranında ve orası dizin yapılandırılmadan
 * çizilmiyor. OIDC girişinde yöneticilik yalnızca grup iddiasından
 * geliyor ve kaynağı OIDC'ye çevirmek grubun ayarlı olmasını şart
 * koşuyor — yani dizini olmayan bir kurulum, ayarı yapamadığı için
 * OIDC'ye HİÇ geçemiyordu.
 */
describe("yönetici grubu", () => {
  const mountWithGroup = (g = "") => {
    vi.spyOn(api, "adminGroup").mockResolvedValue({
      group: g,
      holders: [],
      enumerable: false,
    });
    return show({ issuer_url: "https://idp.example", client_id: "postern" });
  };

  it("OIDC ekranında ayarlanabiliyor", async () => {
    const set = vi.spyOn(api, "setAdminGroup").mockResolvedValue({
      ok: true,
      group: "platform-admins",
      granted: [],
      revoked: [],
      deferred: true,
    });
    mountWithGroup();

    const box = await screen.findByLabelText(/group name/i);
    await userEvent.type(box, "platform-admins");
    await userEvent.click(
      screen.getByRole("button", { name: /save the administrator group/i }),
    );

    // ⚠️ ONAY LİSTESİ BOŞ: sayılamayan bir kaynakta böyle bir liste
    // yok ve olmayan bir listeyi onaylatmak, veremediğimiz bir
    // güvenceyi veriyormuş gibi yapmak olurdu.
    await waitFor(() =>
      expect(set).toHaveBeenCalledWith("platform-admins", []),
    );
  });

  /*
   * ⚠️ "ŞİMDİ KİMSE DEĞİŞMİYOR" SÖYLENMEK ZORUNDA.
   *
   * Dizin ekranında kaydetmek anında yetki dağıtıyor; burada
   * dağıtmıyor. İkisini aynı sanan operatör, yetkinin uygulanmadığını
   * düşünüp ikinci kez uğraşır.
   */
  it("yetkinin bir sonraki girişte uygulanacağını söylüyor", async () => {
    vi.spyOn(api, "setAdminGroup").mockResolvedValue({
      ok: true,
      group: "platform-admins",
      granted: [],
      revoked: [],
      deferred: true,
    });
    mountWithGroup();

    await userEvent.type(
      await screen.findByLabelText(/group name/i),
      "platform-admins",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /save the administrator group/i }),
    );

    await waitFor(() =>
      expect(screen.getByText(/at their next sign-in/i)).toBeTruthy(),
    );
  });

  // Önizleme VAAT EDİLMİYOR: sağlayıcıya "bu grupta kimler var" diye
  // sorulamıyor ve ekran bunu açıkça yazmalı.
  it("üyelerin önceden listelenemeyeceğini yazıyor", async () => {
    mountWithGroup();
    expect(await screen.findByText(/cannot ask\s+who is in it/i)).toBeTruthy();
  });
});
