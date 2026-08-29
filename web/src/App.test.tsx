import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import { ApiError, api, type Me } from "./api";

const myTargets = [{ name: "web01", labels: { env: "prod" } }];

const me: Me = {
  name: "yigit",
  os_user: "yigit",
  admin: false,
  targets: ["web01"],
  terminal_enabled: true,
  public_key_login: true,
};

describe("App önyükleme", () => {
  // ⚠️ Eskiden HER hata "giriş yapmamışsın" ekranına düşüyordu. Yani
  // veritabanı çökmüşken kullanıcıya "oturum aç" deniyor, o da IdP'ye
  // gidip geri dönüyor ve aynı arızaya düşüyordu — çıkışı olmayan bir
  // döngü. 401 ile 500 ayrı ekranlar olmalı.
  it("401'de giris ekrani gosterir", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "unauthenticated"));
    vi.spyOn(api, "authMethods").mockResolvedValue({ oidc: true });

    render(<App />);
    await waitFor(() =>
      expect(
        screen.getByText(/Sign in with your identity provider/i),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("500'de giris DEGIL 'ulasilamiyor' ekrani gosterir", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(500, "internal error"));

    render(<App />);
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());

    expect(
      screen.queryByText(/Sign in with your identity provider/i),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });

  it("ag hatasinda da 'ulasilamiyor' ekrani", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new TypeError("Failed to fetch"));

    render(<App />);
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/reach postern/i),
    );
  });

  it("Retry istegi yeniden gonderir", async () => {
    const spy = vi
      .spyOn(api, "me")
      .mockRejectedValue(new ApiError(500, "boom"));

    render(<App />);
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /retry/i }),
      ).toBeInTheDocument(),
    );

    spy.mockResolvedValue(me);
    vi.spyOn(api, "myTargets").mockResolvedValue(myTargets);
    await userEvent.click(screen.getByRole("button", { name: /retry/i }));

    await waitFor(() => expect(screen.getByText("web01")).toBeInTheDocument());
  });

  it("yuklenirken bos ekran degil 'Loading' gosterir", () => {
    vi.spyOn(api, "me").mockImplementation(() => new Promise(() => {}));

    render(<App />);
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });
});

describe("App gezinmesi", () => {
  // ⚠️ Bulunulan sekme disabled ile işaretleniyordu: bu onu sekme
  // sırasından ÇIKARIYOR ve ekran okuyucuya "kullanılamaz" dedirtiyor.
  // Klavye kullanıcısı olduğu yere odaklanamıyordu.
  it("secili ust sekme odaklanabilir kalir ve aria-current tasir", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ ...me, admin: true });

    render(<App />);
    const home = await screen.findByRole("button", { name: "Home" });

    expect(home).not.toBeDisabled();
    expect(home).toHaveAttribute("aria-current", "page");

    const settings = screen.getByRole("button", { name: "Settings" });
    expect(settings).not.toHaveAttribute("aria-current");
  });

  // Home HERKESİN ekranı; yönetim bölümlerinin tamamı Settings altında.
  // Admin olmayana Settings sekmesi HİÇ çizilmiyor: görünüp 403 vermek,
  // olmayan bir yetkiyi vaat etmektir.
  it("admin olmayana Settings sekmesi gosterilmez", async () => {
    vi.spyOn(api, "me").mockResolvedValue(me);

    render(<App />);
    await screen.findByRole("button", { name: "Home" });

    expect(
      screen.queryByRole("button", { name: "Settings" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Users" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Admin log" }),
    ).not.toBeInTheDocument();
  });

  it("Settings acilinca sol bolum listesi cikar ve secili bolum isaretli olur", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ ...me, admin: true });
    // Overview açılışta oturumları çekiyor; canlı akış jsdom'da yok ve
    // bileşen yoklamaya düşüyor (kendi hata yolu).
    vi.spyOn(api, "sessions").mockResolvedValue([]);

    render(<App />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Settings" }),
    );

    const overview = await screen.findByRole("button", { name: "Overview" });
    expect(overview).toHaveAttribute("aria-current", "page");
    expect(overview).not.toBeDisabled();

    // Bölümlerin tamamı burada; üst sekmelerde değil.
    for (const label of [
      "Users",
      "Roles",
      "Mappings",
      "Targets",
      "LDAP",
      "Sessions",
      "Admin log",
    ]) {
      expect(screen.getByRole("button", { name: label })).toBeInTheDocument();
    }
  });
});

describe("App kabuk baglantisi", () => {
  // Sunucuda rota yoksa bağlantı HİÇ gösterilmemeli: basan kullanıcı
  // 404 alıp "[disconnected]" görüyor ve kapalı bir özelliğin BOZUK
  // olduğunu sanıyordu.
  it("terminal kapaliyken baglanti yok, sebebi yazili", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ ...me, terminal_enabled: false });
    vi.spyOn(api, "myTargets").mockResolvedValue(myTargets);

    render(<App />);
    await screen.findByText("web01");

    expect(
      screen.queryByRole("link", { name: /open a shell/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/browser terminal is switched off/i),
    ).toBeInTheDocument();
  });

  // ⚠️ DÜĞME DEĞİL BAĞLANTI ve yeni sekmede açılıyor: orta tık ve
  // "yeni sekmede aç" bağlam menüsü çalışsın, ve kabuk panelin
  // içinde ekranın yarısını çevre kabuğa vermesin.
  it("terminal aciksa yeni sekmede acilan kabuk baglantisi var", async () => {
    vi.spyOn(api, "me").mockResolvedValue(me);
    vi.spyOn(api, "myTargets").mockResolvedValue(myTargets);

    render(<App />);
    const link = await screen.findByRole("link", {
      name: /open a shell on web01 in a new tab/i,
    });

    expect(link).toHaveAttribute("href", "/shell/web01");
    expect(link).toHaveAttribute("target", "_blank");
    // noopener: açılan sekme window.opener ile bu sayfayı yönlendiremesin.
    expect(link.getAttribute("rel")).toContain("noopener");
  });

  it("etiketler kutuda gorunur ve sorguyla suzulur", async () => {
    vi.spyOn(api, "me").mockResolvedValue(me);
    vi.spyOn(api, "myTargets").mockResolvedValue([
      { name: "web01", labels: { env: "prod" } },
      { name: "db01", labels: { env: "staging" } },
    ]);

    render(<App />);
    await screen.findByText("web01");
    expect(screen.getByText("db01")).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText(/filter targets/i), "env: prod");

    await waitFor(() =>
      expect(screen.queryByText("db01")).not.toBeInTheDocument(),
    );
    expect(screen.getByText("web01")).toBeInTheDocument();
  });
});

/*
 * Oturum ALT SAYFADA düşünce giriş ekranına dönmeli.
 *
 * ⚠️ Ölçülen kusur: 401 yönetim sayfalarının kendi hata satırında
 * çiziliyordu ve kullanıcı, ekrandaki her sayı geçersizken "Error:
 * unauthenticated" yazısıyla Overview'da oturup kalıyordu. Bir
 * yetkilendirme panelinde gösterilebilecek en yanıltıcı ekran bu.
 *
 * Test api.* metodunu DEĞİL fetch'i taklit ediyor: kanal api.ts'in
 * içinde ve metodu mock'lamak tam da sınanmak istenen yolu atlardı.
 */
describe("App oturum bitisi", () => {
  it("alt sayfadan gelen 401 giris ekranina dondurur", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/api/me")) {
        return new Response(JSON.stringify(me), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url.includes("/api/auth/methods")) {
        return new Response(JSON.stringify({ oidc: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      // Hedef listesi: oturum bu arada düştü.
      return new Response(JSON.stringify({ error: "unauthenticated" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;

    try {
      render(<App />);

      // Önce içeri girmiş olmalı…
      await screen.findByRole("button", { name: "Home" });

      // …sonra 401 gelince giriş ekranına dönmeli, sebebiyle birlikte.
      await waitFor(() =>
        expect(screen.getByText(/Session ended/i)).toBeInTheDocument(),
      );
      expect(
        screen.getByText(/Sign in with your identity provider/i),
      ).toBeInTheDocument();
      // Yönetim ekranı ARTIK GÖRÜNMEMELİ.
      expect(
        screen.queryByRole("button", { name: "Settings" }),
      ).not.toBeInTheDocument();
    } finally {
      globalThis.fetch = original;
    }
  });
});

/*
 * ÜRÜNÜN YENİ HÂLİ: kimlik sağlayıcısı olmayan kurulum.
 *
 * Panel bugüne kadar koşulsuz bir "kimlik sağlayıcınla gir" düğmesi
 * çiziyordu, çünkü OIDC'siz bir panel diye bir şey yoktu — HTTP
 * yüzeyinin tamamı `if cfg.OOBEnabled()` içindeydi. Artık dizini olan
 * ama IdP'si olmayan kurum da paneli çalıştırabiliyor ve o kurulumda o
 * düğme 404'e giderdi: kullanıcı ürünü bozuk sanardı.
 */
describe("giris yollari", () => {
  it("oidc yoksa IdP dugmesini CIZMEZ ve ne yapilacagini soyler", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "unauthenticated"));
    vi.spyOn(api, "authMethods").mockResolvedValue({ oidc: false });

    render(<App />);

    await waitFor(() =>
      expect(
        screen.getByText(/No sign-in method is configured/i),
      ).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/Sign in with your identity provider/i),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/postern admin bootstrap/)).toBeInTheDocument();
  });

  it("uc cevap vermezse dugme cizilmez", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "unauthenticated"));
    vi.spyOn(api, "authMethods").mockRejectedValue(new ApiError(500, "boom"));

    render(<App />);

    await waitFor(() =>
      expect(screen.getByText(/^Sign in$/)).toBeInTheDocument(),
    );
    // Yanlış yönlendirmektense hiç yönlendirmemek: 404'e giden bir
    // düğme, kullanıcıya ürünün bozuk olduğunu söyler.
    expect(
      screen.queryByText(/Sign in with your identity provider/i),
    ).not.toBeInTheDocument();
  });
});
