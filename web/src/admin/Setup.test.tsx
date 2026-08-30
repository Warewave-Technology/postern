import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Setup from "./Setup";
import { api, type AuthSourceStatus, type Setting } from "../api";

const status = (over: Partial<AuthSourceStatus> = {}): AuthSourceStatus => ({
  source: "local",
  stored: false,
  options: [
    { source: "local", eligible: true },
    { source: "oidc", eligible: true },
    { source: "ldap", eligible: true },
  ],
  ...over,
});

const settings = (adminGroup = "sysadmins"): Setting[] => [
  { key: "ldap.admin_group", value: adminGroup, secret: false, updated_by: "ops" },
  { key: "auth.auto_create", value: "false", secret: false, updated_by: "ops" },
];

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal("confirm", vi.fn((_m?: string) => true));
  vi.spyOn(api, "authSource").mockResolvedValue(status());
  vi.spyOn(api, "settings").mockResolvedValue(settings());
  vi.spyOn(api, "mappings").mockResolvedValue([]);
  vi.spyOn(api, "unmappedGroups").mockResolvedValue([]);
  vi.spyOn(api, "roles").mockResolvedValue([]);
  // OIDC ayarları artık veritabanında ve sihirbaz onları okuyor.
  vi.spyOn(api, "oidcSettings").mockResolvedValue({
    issuer_url: "",
    client_id: "",
    client_secret_set: false,
    managed_in_db: false,
    configured: false,
    live: false,
  });
  vi.spyOn(api, "adminGroup").mockResolvedValue({
    group: "sysadmins",
    holders: [{ username: "ops", via: "cli" }],
    enumerable: true,
  });
});

describe("kurulum sihirbazi", () => {
  /*
   * ⚠️ SİHİRBAZIN VAR OLMA SEBEBİ.
   *
   * Kaynağı çevirmek yerel kapıyı kapatıyor ve yönetici hesabı ad
   * eşleşmesiyle devralınamıyor. Kendi kimliğini bağlamadan çevirirse
   * kurulumu yapan kişi geri giremez — o yüzden düğme kapalı.
   */
  it("ldap secilince once kimlik baglanmali", async () => {
    render(<Setup meName="ops" />);
    await waitFor(() => expect(screen.getByText(/Which source opens the panel/i)).toBeInTheDocument());

    await userEvent.click(screen.getByRole("radio", { name: /Directory \(LDAP\)/i }));
    await userEvent.click(screen.getByRole("button", { name: /Link yourself, then switch/i }));

    const go = await screen.findByRole("button", {
      name: /switch the panel to this source/i,
    });
    expect(go).toBeDisabled();
    expect(screen.getByText(/Link your account first/i)).toBeInTheDocument();
  });

  it("kimlik baglaninca gecis acilir ve sifre sunucuya gider", async () => {
    const bind = vi.spyOn(api, "bindOwnDirectory").mockResolvedValue({
      ok: true,
      identity: "f74a3e90-373a-1041-92eb-dbd441920715",
      directory_username: "yigit.basalma",
    });

    render(<Setup meName="ops" />);
    await waitFor(() => expect(screen.getByText(/Which source opens the panel/i)).toBeInTheDocument());
    await userEvent.click(screen.getByRole("radio", { name: /Directory \(LDAP\)/i }));
    await userEvent.click(screen.getByRole("button", { name: /Link yourself, then switch/i }));

    await userEvent.type(screen.getByLabelText(/Your directory username/i), "yigit.basalma");
    await userEvent.type(screen.getByLabelText(/Your directory password/i), "gizli");
    await userEvent.click(screen.getByRole("button", { name: /link my directory account/i }));

    await waitFor(() => expect(bind).toHaveBeenCalledWith("yigit.basalma", "gizli"));
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /switch the panel to this source/i }),
      ).toBeEnabled(),
    );
  });

  /*
   * ⚠️ OIDC'de bağlama ÖNCEDEN yapılamıyor ve bunu saklamıyoruz: kapı
   * kapalıyken tarayıcı turu atılamaz. Ekran bunun yerine ne olacağını
   * söylüyor, çünkü sessiz kalmak kullanıcıyı kilitli bir panele
   * gönderirdi.
   */
  it("oidc'de once baglanamayacagini acikca soyler", async () => {
    render(<Setup meName="ops" />);
    await waitFor(() => expect(screen.getByText(/Which source opens the panel/i)).toBeInTheDocument());
    await userEvent.click(screen.getByRole("radio", { name: /Identity provider/i }));
    await userEvent.click(screen.getByRole("button", { name: /Link yourself, then switch/i }));

    expect(
      screen.getByText(/no way to prove an OIDC identity before switching/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/single-use permission/i)).toBeInTheDocument();
  });

  // ⚠️ Grup claim'i, kurulumda en sık kaçırılan adım: gelmezse herkes
  // grupsuz görünür ve hiçbir eşleme tutmaz.
  it("oidc icin grup claim'inin nasil ayarlanacagini anlatir", async () => {
    render(<Setup meName="ops" />);
    await waitFor(() => expect(screen.getByText(/Which source opens the panel/i)).toBeInTheDocument());
    await userEvent.click(screen.getByRole("radio", { name: /Identity provider/i }));
    await userEvent.click(screen.getByRole("button", { name: /Configure it/i }));

    expect(screen.getByText(/has to send group names/i)).toBeInTheDocument();
    expect(screen.getByText(/Group Membership/i)).toBeInTheDocument();
  });

  // ⚠️ Eşleme, auto-create anahtarının ALT AYARI DEĞİL: kuyruktan
  // onaylanan kişinin rolleri de oradan geliyor.
  it("eslemenin her iki durumda da gerektigini soyler", async () => {
    render(<Setup meName="ops" />);
    await waitFor(() => expect(screen.getByText(/Which source opens the panel/i)).toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: /Groups and roles/i }));

    expect(screen.getByText(/Mapping is needed either way/i)).toBeInTheDocument();
  });

  // Yönetici grubu yoksa uyarı çıkmalı: o modda yöneticilik yalnızca
  // gruptan geliyor.
  it("yonetici grubu bosken uyarir", async () => {
    vi.spyOn(api, "settings").mockResolvedValue(settings(""));
    render(<Setup meName="ops" />);
    await waitFor(() => expect(screen.getByText(/Which source opens the panel/i)).toBeInTheDocument());
    await userEvent.click(screen.getByRole("radio", { name: /Directory \(LDAP\)/i }));
    await userEvent.click(screen.getByRole("button", { name: /Administrators/i }));

    expect(
      screen.getByText(/An administrator group is required/i),
    ).toBeInTheDocument();
  });
});

/*
 * ⚠️ ZATEN BAĞLI OLAN YÖNETİCİ, İLERLEYEMEYECEĞİ BİR DUVARA DAYANMAMALI.
 *
 * Bağlama ucu haklı olarak çatışma döner (bir hesap bir kimliğe bağlanır
 * ve bağ sessizce değişemez). Sihirbaz bunu bilmezse, ekranda "önce
 * bağla" yazar ve düğme kapalı kalır — kurulum orada durur.
 */
describe("zaten bagli yonetici", () => {
  it("baglama adimini gecilmis sayar", async () => {
    render(<Setup meName="ops" dirBound />);
    await waitFor(() =>
      expect(screen.getByText(/Which source opens the panel/i)).toBeInTheDocument(),
    );
    await userEvent.click(screen.getByRole("radio", { name: /Directory \(LDAP\)/i }));
    await userEvent.click(
      screen.getByRole("button", { name: /Link yourself, then switch/i }),
    );

    expect(screen.getByText(/already linked to a directory identity/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /switch the panel to this source/i }),
    ).toBeEnabled();
  });
});


/*
 * ⚠️ SİHİRBAZ, KİMLİK SAĞLAYICIYI ARTIK KENDİSİ YAPILANDIRIYOR.
 *
 * Ayarlar config dosyasındayken sihirbazın OIDC adımı bir talimat
 * metninden ibaretti: "dosyayı düzenle ve yeniden başlat". Bu, ürünün
 * "kurulumdan sonra sunucuya hiç dokunma" hedefiyle çelişiyordu.
 */
describe("oidc yapilandirmasi", () => {
  it("issuer ve client id'yi sunucuya yazar", async () => {
    const save = vi
      .spyOn(api, "setOIDCSettings")
      .mockResolvedValue({ ok: true, live: true, error: "" });

    render(<Setup meName="ops" />);
    await waitFor(() =>
      expect(screen.getByText(/Which source opens the panel/i)).toBeInTheDocument(),
    );
    await userEvent.click(screen.getByRole("radio", { name: /Identity provider/i }));
    await userEvent.click(screen.getByRole("button", { name: /Configure it/i }));

    await userEvent.type(
      screen.getByLabelText(/Issuer address/i),
      "https://idp.example/realms/x",
    );
    await userEvent.type(screen.getByLabelText(/Client id/i), "postern");
    await userEvent.click(
      screen.getByRole("button", { name: /save and contact the identity provider/i }),
    );

    // ⚠️ Sır BOŞ bırakıldı: gönderilmemeli. Boşu "temizle" saymak,
    // sırsız public client kurulumunu kazayla silmenin yolu olurdu.
    await waitFor(() =>
      expect(save).toHaveBeenCalledWith(
        "https://idp.example/realms/x",
        "postern",
        undefined,
      ),
    );
  });

  it("sir yazildiysa gonderir", async () => {
    const save = vi
      .spyOn(api, "setOIDCSettings")
      .mockResolvedValue({ ok: true, live: true, error: "" });

    render(<Setup meName="ops" />);
    await waitFor(() =>
      expect(screen.getByText(/Which source opens the panel/i)).toBeInTheDocument(),
    );
    await userEvent.click(screen.getByRole("radio", { name: /Identity provider/i }));
    await userEvent.click(screen.getByRole("button", { name: /Configure it/i }));

    await userEvent.type(
      screen.getByLabelText(/Issuer address/i),
      "https://idp.example/realms/x",
    );
    await userEvent.type(screen.getByLabelText(/Client id/i), "postern");
    await userEvent.type(screen.getByLabelText(/Client secret/i), "gizli");
    await userEvent.click(
      screen.getByRole("button", { name: /save and contact the identity provider/i }),
    );

    await waitFor(() =>
      expect(save).toHaveBeenCalledWith(
        "https://idp.example/realms/x",
        "postern",
        "gizli",
      ),
    );
  });

  /*
   * ⚠️ ULAŞILAMAYAN SAĞLAYICI, AYARLARIN KAYBOLMASINA YOL AÇMAMALI —
   * ve ekran farkı söylemeli: "kaydedildi ama ulaşılamıyor",
   * "kaydedilemedi"den bambaşka bir şey.
   */
  it("ulasilamayan saglayicida kaydedildigini ama calismadigini soyler", async () => {
    vi.spyOn(api, "setOIDCSettings").mockResolvedValue({
      ok: true,
      live: false,
      error: "dial tcp: i/o timeout",
    });
    vi.spyOn(api, "oidcSettings")
      .mockResolvedValueOnce({
        issuer_url: "",
        client_id: "",
        client_secret_set: false,
        managed_in_db: false,
        configured: false,
        live: false,
      })
      .mockResolvedValue({
        issuer_url: "https://idp.example/realms/x",
        client_id: "postern",
        client_secret_set: false,
        managed_in_db: true,
        configured: true,
        live: false,
      });

    render(<Setup meName="ops" />);
    await waitFor(() =>
      expect(screen.getByText(/Which source opens the panel/i)).toBeInTheDocument(),
    );
    await userEvent.click(screen.getByRole("radio", { name: /Identity provider/i }));
    await userEvent.click(screen.getByRole("button", { name: /Configure it/i }));
    await userEvent.type(
      screen.getByLabelText(/Issuer address/i),
      "https://idp.example/realms/x",
    );
    await userEvent.type(screen.getByLabelText(/Client id/i), "postern");
    await userEvent.click(
      screen.getByRole("button", { name: /save and contact the identity provider/i }),
    );

    await waitFor(() =>
      expect(screen.getByText(/i\/o timeout/i)).toBeInTheDocument(),
    );
  });
});

/*
 * ⚠️ BİTİŞ: "All is set", sonra uygulamaya geçiş.
 *
 * Sihirbaz bittiğinde arkasındaki adımlar dururken bir başarı satırı
 * göstermek, operatöre "bitti mi, devam mı" diye sordurur.
 */
describe("kurulumun bitisi", () => {
  it("kaynak cevrildikten sonra kurulumu tamamlar ve 'All is set' gosterir", async () => {
    vi.spyOn(api, "setAuthSource").mockResolvedValue({
      ok: true,
      source: "local",
      note: "done",
    });
    const complete = vi
      .spyOn(api, "completeSetup")
      .mockResolvedValue({ ok: true });

    render(<Setup meName="ops" />);
    await waitFor(() =>
      expect(screen.getByText(/Which source opens the panel/i)).toBeInTheDocument(),
    );
    await userEvent.click(
      screen.getByRole("button", { name: /Link yourself, then switch/i }),
    );
    await userEvent.click(
      screen.getByRole("button", { name: /switch the panel to this source/i }),
    );

    await waitFor(() => expect(complete).toHaveBeenCalled());
    expect(await screen.findByText(/All is set/i)).toBeInTheDocument();
  });
});
