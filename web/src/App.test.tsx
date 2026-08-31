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
    vi.spyOn(api, "authMethods").mockResolvedValue({
      source: "oidc",
      oidc: true,
      local: false,
      ldap: false,
    });

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
        return new Response(
          JSON.stringify({
            source: "oidc",
            oidc: true,
            local: false,
            ldap: false,
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
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
  it("oidc yoksa IdP dugmesini CIZMEZ, yerel formu cizer", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "unauthenticated"));
    vi.spyOn(api, "authMethods").mockResolvedValue({
      source: "local",
      oidc: false,
      local: true,
      ldap: false,
    });

    render(<App />);

    await waitFor(() =>
      expect(screen.getByLabelText(/Sign-in secret/i)).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/Sign in with your identity provider/i),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/postern admin bootstrap/)).toBeInTheDocument();
  });

  // Hiçbir kapı yoksa ekran çıkmaz sokak olmamalı.
  it("hicbir kapi yoksa ne yapilacagini soyler", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "unauthenticated"));
    vi.spyOn(api, "authMethods").mockResolvedValue({
      source: "oidc",
      oidc: false,
      local: false,
      ldap: false,
    });

    render(<App />);

    await waitFor(() =>
      expect(
        screen.getByText(/No sign-in method is available/i),
      ).toBeInTheDocument(),
    );
  });

  /*
   * Yerel kapı: sır doğruysa oturum açılır.
   *
   * ⚠️ Metinler "password" değil "secret" diyor ve bu kasıtlı —
   * kullanıcının buraya kurumsal parolasını yazma refleksini
   * beslememek gerekiyor.
   */
  it("yerel sirla giris yapar", async () => {
    const meSpy = vi
      .spyOn(api, "me")
      .mockRejectedValueOnce(new ApiError(401, "unauthenticated"))
      .mockResolvedValue(me);
    vi.spyOn(api, "authMethods").mockResolvedValue({
      source: "local",
      oidc: false,
      local: true,
      ldap: false,
    });
    vi.spyOn(api, "myTargets").mockResolvedValue(myTargets);
    const login = vi.spyOn(api, "localLogin").mockResolvedValue({ ok: true });

    render(<App />);
    await waitFor(() =>
      expect(screen.getByLabelText(/Sign-in secret/i)).toBeInTheDocument(),
    );

    await userEvent.type(screen.getByLabelText(/Username/i), "ops");
    await userEvent.type(screen.getByLabelText(/Sign-in secret/i), "AAAA-BBBB");
    await userEvent.click(screen.getByRole("button", { name: /^Sign in$/i }));

    await waitFor(() => expect(login).toHaveBeenCalledWith("ops", "AAAA-BBBB"));
    expect(meSpy).toHaveBeenCalled();
  });

  it("yanlis sirda hata gosterir ve formda kalir", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "unauthenticated"));
    vi.spyOn(api, "authMethods").mockResolvedValue({
      source: "local",
      oidc: false,
      local: true,
      ldap: false,
    });
    vi.spyOn(api, "localLogin").mockRejectedValue(
      new ApiError(401, "wrong username or secret"),
    );

    render(<App />);
    await waitFor(() =>
      expect(screen.getByLabelText(/Sign-in secret/i)).toBeInTheDocument(),
    );

    await userEvent.type(screen.getByLabelText(/Username/i), "ops");
    await userEvent.type(screen.getByLabelText(/Sign-in secret/i), "yanlis");
    await userEvent.click(screen.getByRole("button", { name: /^Sign in$/i }));

    await waitFor(() =>
      expect(screen.getByText(/wrong username or secret/i)).toBeInTheDocument(),
    );
    expect(screen.getByLabelText(/Sign-in secret/i)).toBeInTheDocument();
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

/*
 * ⚠️ DİZİN KAPISI, YEREL KAPIYLA AYNI METNİ KULLANAMAZ.
 *
 * İkisi de kullanıcı adı + gizli bir değer istiyor; ama biri makine
 * üretimi bir sır, diğeri KURUMSAL PAROLA. Aynı etiketle sunmak
 * kullanıcıya "her zaman aynı şeyi yaz" öğretir ve o alışkanlık,
 * kurumsal parolanın yanlış kutuya girildiği gün pahalıya patlar.
 */
describe("dizin kapisi", () => {
  it("dizin kipinde parola ister, makine sirri degil", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "unauthenticated"));
    vi.spyOn(api, "authMethods").mockResolvedValue({
      source: "ldap",
      oidc: false,
      local: false,
      ldap: true,
    });

    render(<App />);

    await waitFor(() =>
      expect(screen.getByLabelText(/Directory password/i)).toBeInTheDocument(),
    );
    expect(screen.queryByLabelText(/Sign-in secret/i)).toBeNull();
    // ⚠️ Ve bunun SSH'ı ilgilendirmediğini söylüyor: kullanıcı bu
    // parolayı ssh'ta denemeye kalkmasın.
    expect(
      screen.getByText(/Your SSH access does not use this password/i),
    ).toBeInTheDocument();
  });

  // Aynı anda tek kapı: sunucu iki kapıyı birden açık bildirmiyor, ama
  // ekran da iki formu birden çizmemeli.
  it("dizin kipinde yerel formu cizmez", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "unauthenticated"));
    vi.spyOn(api, "authMethods").mockResolvedValue({
      source: "ldap",
      oidc: false,
      local: false,
      ldap: true,
    });

    render(<App />);
    await waitFor(() =>
      expect(screen.getByLabelText(/Directory password/i)).toBeInTheDocument(),
    );
    expect(screen.queryByText(/postern admin bootstrap/)).toBeNull();
    expect(
      screen.queryByText(/Sign in with your identity provider/i),
    ).toBeNull();
  });
});

/*
 * ⚠️ KURULUM BİTMEDİYSE PANEL SADECE SİHİRBAZDAN İBARET.
 *
 * Menü maddesi olarak bırakıldığında atlanıyordu ve geriye kaynağı
 * seçilmemiş — kapısı config dosyasından TÜRETİLEN — bir kurulum
 * kalıyordu. Ürünün en kritik kararı keşfe bırakılamaz.
 */
describe("ilk kurulum zorunlulugu", () => {
  it("kurulum bitmediyse baska hicbir sekme cizilmez", async () => {
    vi.spyOn(api, "me").mockResolvedValue({
      ...me,
      admin: true,
      setup_required: true,
    });
    vi.spyOn(api, "authSource").mockResolvedValue({
      source: "local",
      stored: false,
      options: [
        { source: "local", eligible: true },
        { source: "oidc", eligible: false, why: "not configured" },
        { source: "ldap", eligible: false, why: "not configured" },
      ],
    });
    vi.spyOn(api, "settings").mockResolvedValue([]);
    vi.spyOn(api, "oidcSettings").mockResolvedValue({
      issuer_url: "",
      client_id: "",
      client_secret_set: false,
      groups_claim: "",
      scopes: "",
      managed_in_db: false,
      configured: false,
      live: false,
    });
    vi.spyOn(api, "adminGroup").mockResolvedValue({
      group: "",
      holders: [],
      enumerable: false,
    });

    render(<App />);

    await waitFor(() =>
      expect(screen.getByText(/Set up sign-in/i)).toBeInTheDocument(),
    );
    // Ne sekmeler, ne ana ekran.
    expect(screen.queryByRole("button", { name: /^Settings$/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Home$/ })).toBeNull();
  });

  // Yönetici olmayan biri o sırada girerse: boş ekran değil, sebep.
  it("yonetici olmayana sebebini soyler", async () => {
    vi.spyOn(api, "me").mockResolvedValue({
      ...me,
      admin: false,
      setup_required: true,
    });
    render(<App />);
    await waitFor(() =>
      expect(
        screen.getByText(/has not finished its first-run setup/i),
      ).toBeInTheDocument(),
    );
  });
});

/*
 * ⚠️ YEREL KAYNAKTA GRUP DİYE BİR ŞEY YOK.
 *
 * Kodda doğrulandı: hiçbir RolesForGroups çağrısı yerel giriş yolunda
 * değil ve onay kuyruğuna yazma yalnızca kaynak kapılarından geçiyor.
 * Boş duran iki menü maddesi, operatöre "burada bir şey yapmam
 * gerekiyor mu" diye sordurur ve eşleme yapıp neden çalışmadığını
 * aratır.
 */
describe("kaynaga bagli menu", () => {
  const mocks = (source: "local" | "ldap") => {
    vi.spyOn(api, "me").mockResolvedValue({
      ...me,
      admin: true,
      setup_required: false,
    });
    vi.spyOn(api, "authSource").mockResolvedValue({
      source,
      stored: true,
      options: [
        { source: "local", eligible: true },
        { source: "oidc", eligible: true },
        { source: "ldap", eligible: true },
      ],
    });
  };

  it("yerel modda Mappings ve Pending listelenmez", async () => {
    mocks("local");
    render(<App />);
    await userEvent.click(
      await screen.findByRole("button", { name: /^Settings$/ }),
    );
    // ⚠️ Menü daraltması SUNUCUNUN cevabına bağlı, yani asenkron:
    // varlığı beklemek yetmiyor, YOKLUĞU beklemek gerekiyor.
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: /^Mappings$/ })).toBeNull(),
    );
    expect(screen.queryByRole("button", { name: /^Pending$/ })).toBeNull();
    expect(screen.getByRole("button", { name: /^Users$/ })).toBeInTheDocument();
    // Kaynağı değiştirebileceği ekran DURUYOR: yoksa geri dönüş yolu
    // da kaybolurdu.
    expect(
      screen.getByRole("button", { name: /^Sign-in$/ }),
    ).toBeInTheDocument();
  });

  it("dizin modunda ikisi de listelenir", async () => {
    mocks("ldap");
    render(<App />);
    await userEvent.click(
      await screen.findByRole("button", { name: /^Settings$/ }),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /^Mappings$/ }),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByRole("button", { name: /^Pending$/ }),
    ).toBeInTheDocument();
  });
});

describe("zorunlu parola değişikliği", () => {
  /*
   * ⚠️ PANELİN GERİ KALANI HİÇ ÇİZİLMİYOR.
   *
   * Yönetici tarafından verilen değeri veren de biliyor, yani bu
   * hâldeki oturum henüz "o kişinin" oturumu değil. Sekmeler, menü ve
   * kurulum sihirbazı bu ekranın yanında görünmemeli — asıl koruma
   * sunucuda, ama ekranın da yanlış bir şey vaat etmemesi gerekiyor.
   */
  it("parola değiştirilene kadar başka hiçbir şey çizilmiyor", async () => {
    vi.spyOn(api, "me").mockResolvedValue({
      name: "ayse",
      os_user: "ayse",
      admin: true,
      targets: [],
      terminal_enabled: true,
      public_key_login: true,
      must_change_password: true,
      password_policy: { min_length: 12, max_length: 256, min_distinct: 5 },
    });

    render(<App />);
    await screen.findByText("Set your password");

    expect(screen.queryByRole("button", { name: "Settings" })).toBeNull();
    expect(screen.queryByText("Your targets")).toBeNull();
  });

  /*
   * ⚠️ KURULUM SİHİRBAZINDAN DA ÖNCE.
   *
   * Sıra kasıtlı: kısıtlı bir oturuma kurulum sihirbazını açmak,
   * kurulumun tamamını değeri bilen ikinci kişiye açmak olurdu.
   */
  it("kurulum sihirbazının önüne geçiyor", async () => {
    vi.spyOn(api, "me").mockResolvedValue({
      name: "ayse",
      os_user: "ayse",
      admin: true,
      targets: [],
      terminal_enabled: true,
      public_key_login: true,
      setup_required: true,
      must_change_password: true,
    });

    render(<App />);
    await screen.findByText("Set your password");
    expect(screen.queryByText(/set up sign-in/i)).toBeNull();
  });
});

/*
 * ⚠️ OIDC EKRANI MENÜDE, VE KAYNAKTAN BAĞIMSIZ.
 *
 * Bu ayarlar bir süre yalnızca kurulum sihirbazının içinden
 * yazılabiliyordu; sihirbaz bitince bir daha çizilmiyor. Sonuç: ilk
 * kurulumda OIDC'yi seçmeyen bir kurulum onu sonradan HİÇ
 * yapılandıramıyor, dolayısıyla kaynağı da hiç OIDC'ye çeviremiyordu.
 *
 * Yerel modda da görünmek ZORUNDA: kaynağı OIDC'ye çevirebilmek için
 * önce onu yapılandırmak gerekiyor. LDAP ekranı da aynı sebeple orada.
 */
describe("kimlik sağlayıcı ekranı", () => {
  const adminMe = {
    name: "yigit",
    os_user: "yigit",
    admin: true,
    targets: [],
    terminal_enabled: true,
    public_key_login: true,
  };

  /*
   * ⚠️ MADDE ADI PROTOKOL: "OIDC", "Identity provider" değil.
   * Yanındaki "LDAP" ile aynı düzlemde olmalı — biri protokolüyle
   * öbürü genel bir tabirle anılırsa menüde hangisinin ne olduğu
   * okunmuyor. Üstelik "identity provider" LDAP'ı da kapsıyor.
   */
  it("Identity grubunda LDAP'ın yanında duruyor", async () => {
    vi.spyOn(api, "me").mockResolvedValue(adminMe);
    render(<App />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Settings" }),
    );

    expect(await screen.findByRole("button", { name: "OIDC" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "LDAP" })).toBeTruthy();
  });

  it("yerel kaynakta da duruyor — yoksa OIDC'ye hiç geçilemez", async () => {
    vi.spyOn(api, "me").mockResolvedValue(adminMe);
    vi.spyOn(api, "authSource").mockResolvedValue({
      source: "local",
      stored: true,
      options: [],
      unseen_mappings: [],
    });

    render(<App />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Settings" }),
    );
    // Yerel modda kaynağa bağlı ekranlar (Mappings, Pending) düşüyor;
    // bu düşmemeli.
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Mappings" })).toBeNull(),
    );
    expect(screen.getByRole("button", { name: "OIDC" })).toBeTruthy();
  });
});

/*
 * ⚠️ ANAHTAR GİRİŞİ KAPALIYKEN ANA EKRANDA KART YOK.
 *
 * Koşulsuz çiziliyordu ve sunucu ekleme isteğini 409 ile reddediyordu:
 * kullanıcı bir kutu, bir düğme ve bir hata görüyor, özelliğin BOZUK mu
 * yoksa KAPALI mı olduğunu ayırt edemiyordu.
 */
describe("anahtar girişi kapalıyken ana ekran", () => {
  it("anahtar kartını çizmiyor ve sebebini söylüyor", async () => {
    vi.spyOn(api, "me").mockResolvedValue({
      name: "ayse",
      os_user: "ayse",
      admin: false,
      targets: [],
      terminal_enabled: false,
      public_key_login: false,
    });

    render(<App />);
    await screen.findByText("Your targets");
    expect(screen.queryByText("Your SSH keys")).toBeNull();
    expect(
      screen.getAllByText(/switched off on this bastion/i).length,
    ).toBeGreaterThan(0);
  });

  it("açıkken çiziyor", async () => {
    vi.spyOn(api, "me").mockResolvedValue({
      name: "ayse",
      os_user: "ayse",
      admin: false,
      targets: [],
      terminal_enabled: false,
      public_key_login: true,
    });
    vi.spyOn(api, "myKeys").mockResolvedValue({
      keys: [],
      reauth_required: false,
      reauth_possible: false,
    });

    render(<App />);
    expect(await screen.findByText("Your SSH keys")).toBeTruthy();
  });
});
