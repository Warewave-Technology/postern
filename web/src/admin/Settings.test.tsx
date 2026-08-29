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
      groups: [],
      roles: [],
      unmapped: [],
    });

    await runLookup("ayse");

    // Boş cevap, cevapsızlık değil: satırlar çizilmeli ve "none" demeli.
    await waitFor(() =>
      expect(screen.getByText(/mapped to roles/i)).toBeInTheDocument(),
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
      groups: ["dbas"],
      roles: ["dba"],
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
      groups: ["dbas"],
      roles: ["dba"],
      unmapped: [],
      out_of_scope: [],
    });

    await runLookup("ayse");

    await waitFor(() =>
      expect(screen.getByText(/mapped to roles/i)).toBeInTheDocument(),
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
        reason: "14 of 120 users would lose all SSO roles",
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
      screen.getAllByText(/14 of 120 users would lose all SSO roles/).length,
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
