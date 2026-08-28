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
