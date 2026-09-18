import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import Settings from "./Settings";
import { api, type Setting, type SyncSettings } from "../api";

// Kurulu bir dizin: ekran sihirbaz yerine BEYAN kipinde açılsın.
const configured: Setting[] = [
  {
    key: "ldap.url",
    value: "ldaps://dizin.sirket.local:636",
    secret: false,
    updated_by: "yigit",
  },
  {
    key: "ldap.bind_dn",
    value: "cn=svc,dc=sirket,dc=local",
    secret: false,
    updated_by: "yigit",
  },
  {
    key: "ldap.bind_password",
    value: "********",
    secret: true,
    updated_by: "yigit",
  },
  {
    key: "ldap.user_base",
    value: "ou=people,dc=sirket,dc=local",
    secret: false,
    updated_by: "yigit",
  },
  {
    key: "ldap.user_filter",
    value: "(uid=%s)",
    secret: false,
    updated_by: "yigit",
  },
  {
    key: "ldap.group_attribute",
    value: "memberOf",
    secret: false,
    updated_by: "yigit",
  },
  {
    key: "ldap.group_base",
    value: "ou=groups,dc=sirket,dc=local",
    secret: false,
    updated_by: "yigit",
  },
  {
    key: "ldap.group_name_from",
    value: "cn",
    secret: false,
    updated_by: "yigit",
  },
];

const sync: SyncSettings = {
  enabled: false,
  dry_run: true,
  interval: "15m0s",
  grace: "1h0m0s",
  max_zero_fraction: 0.1,
  min_zero_floor: 3,
  max_unknown_fraction: 0.25,
  max_revoke_per_run: 25,
  overridden: [],
};

async function runLookup(name: string) {
  render(<Settings />);
  await waitFor(() =>
    expect(screen.getByLabelText(/Look up a user/i)).toBeInTheDocument(),
  );

  const box = screen.getByLabelText(/Look up a user/i);
  await userEvent.type(box, name);
  await userEvent.click(
    screen.getByRole("button", { name: /test the stored LDAP settings/i }),
  );
}

/*
 * Teşhis aracı, SORULAN soruyu cevaplamak zorunda.
 *
 * Ölçülmüş arıza: IdP kullanıcı adı "yigit", dizindeki kayıt
 * "yigit.basalma" olan bir kurulumda kullanıcı adı yazılıp test
 * çalıştırılınca ekranda yalnızca yeşil "connection and bind succeeded"
 * kalıyordu. Bağlantı gerçekten kurulmuştu; ama kullanıcının dizinde
 * OLMADIĞI hiçbir yerde yazmıyordu ve operatörün elinde herkesin
 * rolsüz kalmasını açıklayan tek ipucu yoktu.
 */
describe("LDAP kullanici sorgusu", () => {
  it("dizinde olmayan kullaniciyi ACIKCA soyler", async () => {
    vi.spyOn(api, "settings").mockResolvedValue(configured);
    vi.spyOn(api, "syncSettings").mockResolvedValue(sync);
    vi.spyOn(api, "testLDAP").mockResolvedValue({
      ok: true,
      presence: "absent",
    });

    await runLookup("yigit");

    await waitFor(() =>
      expect(screen.getByText(/has no user matching/i)).toBeInTheDocument(),
    );
    // Yeşil satır hâlâ doğru (bağ kuruldu) ama TEK BAŞINA kalmamalı.
    expect(
      screen.getByText(/connection and bind succeeded/i),
    ).toBeInTheDocument();
  });

  it("dizin cevap veremediginde bunu 'grubu yok' saymaz", async () => {
    vi.spyOn(api, "settings").mockResolvedValue(configured);
    vi.spyOn(api, "syncSettings").mockResolvedValue(sync);
    vi.spyOn(api, "testLDAP").mockResolvedValue({
      ok: true,
      presence: "unknown",
    });

    await runLookup("yigit");

    await waitFor(() =>
      expect(screen.getByText(/could not answer/i)).toBeInTheDocument(),
    );
  });

  it("bulunan ama grubu olmayan kullanici icin bos cevabi GOSTERIR", async () => {
    vi.spyOn(api, "settings").mockResolvedValue(configured);
    vi.spyOn(api, "syncSettings").mockResolvedValue(sync);
    vi.spyOn(api, "testLDAP").mockResolvedValue({
      ok: true,
      presence: "present",
      directory_groups: [],
      groups: [],
      unmapped: [],
    });

    await runLookup("ayse");

    // Boş cevap, cevapsızlık değil: satırlar çizilmeli ve "none" demeli.
    await waitFor(() =>
      expect(screen.getByText(/mapped to groups/i)).toBeInTheDocument(),
    );
    expect(screen.getAllByText("none").length).toBeGreaterThan(0);
  });
});

/*
 * Kapsam dışı kalan gruplar EKRANDA yazmalı.
 *
 * group_scope varsayılanı "direct" olduğu için, gruplarını bir OU daha
 * derinde tutan mevcut bir kurulum yükseltmeden sonra rol kaybediyor.
 * Bunu sessizce yapmak, operatörü kaybolan yetkinin sebebini arayarak
 * saatlerce dolaştırır — teşhis aracının söylemesi gereken tam olarak bu.
 */
describe("grup kapsami uyarisi", () => {
  it("kapsam disinda kalan gruplari sayar ve adlarini gosterir", async () => {
    vi.spyOn(api, "settings").mockResolvedValue(configured);
    vi.spyOn(api, "syncSettings").mockResolvedValue(sync);
    vi.spyOn(api, "testLDAP").mockResolvedValue({
      ok: true,
      presence: "present",
      directory_groups: ["dbas"],
      groups: ["dba"],
      unmapped: [],
      out_of_scope: ["cn=lab,ou=teams,ou=groups,dc=corp"],
    });

    await runLookup("ayse");

    await waitFor(() =>
      expect(
        screen.getByText(/not counted because they sit outside/i),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/cn=lab,ou=teams,ou=groups,dc=corp/),
    ).toBeInTheDocument();
  });

  it("kapsam disinda grup yoksa uyari cikmaz", async () => {
    vi.spyOn(api, "settings").mockResolvedValue(configured);
    vi.spyOn(api, "syncSettings").mockResolvedValue(sync);
    vi.spyOn(api, "testLDAP").mockResolvedValue({
      ok: true,
      presence: "present",
      directory_groups: ["dbas"],
      groups: ["dba"],
      unmapped: [],
      out_of_scope: [],
    });

    await runLookup("ayse");

    await waitFor(() =>
      expect(screen.getByText(/mapped to groups/i)).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/sit outside the group scope/i),
    ).not.toBeInTheDocument();
  });
});

/*
 * İPTAL EDİLEN KOŞU EKRANDA GÖRÜNMELİ.
 *
 * Patlama yarıçapı korumaları bir koşuyu durdurduğunda, bunun tek izi
 * sync_runs tablosuydu ve onu okuyan tek şey host üzerindeki bir
 * komuttu. Yani "hiç kimsenin yetkisi iptal edilmiyor" hâli panele
 * bakan operatör için tamamen görünmezdi — sessiz bir güvenlik
 * arızasının en pahalı biçimi.
 */
describe("senkronizasyon kosu gorunurlugu", () => {
  const run = (over: Partial<import("../api").SyncRun>) => ({
    id: 1,
    started_at: "2026-08-29T09:00:00Z",
    finished_at: "2026-08-29T09:00:01Z",
    trigger: "timer",
    outcome: "ok",
    reason: "",
    considered: 10,
    unknown: 0,
    revoked: 0,
    roles_changed: 0,
    dry_run: false,
    ...over,
  });

  it("iptal edilen kosuyu ve sebebini soyler", async () => {
    vi.spyOn(api, "settings").mockResolvedValue(configured);
    vi.spyOn(api, "syncSettings").mockResolvedValue(sync);
    vi.spyOn(api, "syncRuns").mockResolvedValue([
      run({
        outcome: "aborted",
        reason: "14 of 120 users would lose all SSO groups",
      }),
    ]);

    render(<Settings />);

    await waitFor(() =>
      expect(
        screen.getByText(/stopped by a safety ceiling/i),
      ).toBeInTheDocument(),
    );
    expect(screen.getByText(/nobody is being revoked/i)).toBeInTheDocument();
    // Sebep hem şeritte hem koşu listesinde geçiyor; ikisi de doğru.
    expect(
      screen.getAllByText(/14 of 120 users would lose all SSO groups/).length,
    ).toBeGreaterThan(0);
  });

  it("uc kosu ust uste kuruysa uyarir", async () => {
    vi.spyOn(api, "settings").mockResolvedValue(configured);
    vi.spyOn(api, "syncSettings").mockResolvedValue(sync);
    vi.spyOn(api, "syncRuns").mockResolvedValue([
      run({ id: 3, dry_run: true }),
      run({ id: 2, dry_run: true }),
      run({ id: 1, dry_run: true }),
    ]);

    render(<Settings />);

    await waitFor(() =>
      expect(
        screen.getByText(/last three runs were dry runs/i),
      ).toBeInTheDocument(),
    );
  });

  it("saglikli kosularda uyari cikmaz", async () => {
    vi.spyOn(api, "settings").mockResolvedValue(configured);
    vi.spyOn(api, "syncSettings").mockResolvedValue(sync);
    vi.spyOn(api, "syncRuns").mockResolvedValue([run({}), run({ id: 2 })]);

    render(<Settings />);

    await waitFor(() =>
      expect(screen.getByText(/Directory sync/i)).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/stopped by a safety ceiling/i),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/dry runs/i)).not.toBeInTheDocument();
  });
});

/*
 * ⚠️ EKRANIN NEDEN "KURULMADI" DEDİĞİ, İLK BAKIŞTA YAZILI OLMAK ZORUNDA.
 *
 * ÖLÇÜLDÜ: memberOf ile çalışan bir kurulumda artakalan bir grup süzgeci
 * %s taşımıyorsa, dizin kurulu SAYILMIYOR — ama sebep yalnızca dördüncü
 * adımın ("Review") içinde yazılıydı. Operatör ilk adımda duruyor, üstte
 * üç onay işareti görüyor ve neyin engellediğini bilmeden ekrandan
 * çıkıyor. Bitmiş görünen ama bitmeyen bir kurulum, ekranın verebileceği
 * en kötü cevap.
 */
describe("kurulumu engelleyen sebep", () => {
  // memberOf ile çalışan bir kurulumda ARTAKALAN grup süzgeci: %s yok,
  // dolayısıyla kullanılamaz — ve bu, kurulumun tamamını bloke ediyor.
  const blocked: Setting[] = [
    ...configured,
    {
      key: "ldap.group_filter",
      value: "(objectClass=group)",
      secret: false,
      updated_by: "ops",
    },
  ];

  it("sebebi adımların ÜSTÜNDE yazıyor ve engelli adımı işaretliyor", async () => {
    vi.spyOn(api, "settings").mockResolvedValue(blocked);
    vi.spyOn(api, "syncSettings").mockResolvedValue(sync);
    render(<Settings />);

    const banner = await screen.findByText(/Stored, but not in use yet/i);
    expect(banner).toBeTruthy();
    // Sebep, hangi alan ve neden olduğunu söylüyor.
    expect(screen.getByText(/Group filter: must contain %s/i)).toBeTruthy();

    // Ve engelli adım işaretli: sebebi okuyan kişi nereye gideceğini de
    // görmeli.
    const groupsStep = screen.getByRole("button", { name: /Groups/i });
    expect(groupsStep.className).toContain("step-blocked");
  });

  /*
   * ⚠️ HİÇ BAŞLANMAMIŞ KURULUMDA AFİŞ YOK. Boş bir kurulumda her zorunlu
   * alan "saklanmadı" diye listelenir; o liste "daha başlamadın"
   * demekten başka bir şey söylemez ve sihirbazın ilk adımı zaten onu
   * söylüyor.
   */
  it("hiçbir şey saklanmamışken afiş çıkmıyor", async () => {
    vi.spyOn(api, "settings").mockResolvedValue([]);
    vi.spyOn(api, "syncSettings").mockResolvedValue(sync);
    render(<Settings />);

    await screen.findByText(/Nothing stored yet/i);
    expect(screen.queryByText(/Stored, but not in use yet/i)).toBeNull();
  });
})
