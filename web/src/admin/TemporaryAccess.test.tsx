import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import TemporaryAccess, { commonGroups, grantState } from "./TemporaryAccess";
import { api, type Grant, type TargetGroups } from "../api";

const now = "2026-09-13T12:00:00Z";

const grant = (over: Partial<Grant> = {}): Grant => ({
  id: "g1",
  username: "ayse",
  target: "web-01",
  os_user: "ayse",
  groups: ["dba"],
  granted_by: "ops",
  granted_at: "2026-09-13T10:00:00Z",
  expires_at: "2026-09-13T18:00:00Z",
  applied_at: "2026-09-13T10:00:05Z",
  revoke_attempts: 0,
  ...over,
});

const inventory = (name: string): TargetGroups => ({
  target: name,
  min_gid: 1000,
  checked_at: now,
  groups: [
    { name: "docker", gid: 998, members: [], protected: true },
    { name: "dba", gid: 1001, members: ["ayse"], protected: false },
    ...(name === "web-01" ? [{ name: "web", gid: 1002, members: [], protected: false }] : []),
  ],
});

const step = { kind: "group.add", command: "sudo -n groupadd dba", why: "group dba is missing", outcome: "done" };

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, "users").mockResolvedValue([
    { name: "ayse", os_user: "ayse", admin: false, roles: [], keys: 1 } as never,
  ]);
  vi.spyOn(api, "targets").mockResolvedValue([
    { name: "web-01", host: "10.0.1.11", port: 22, fingerprint: "SHA256:a", labels: {} },
    { name: "db-01", host: "10.0.2.5", port: 22, fingerprint: "SHA256:b", labels: {} },
    { name: "cache-03", host: "10.0.3.3", port: 22, fingerprint: "SHA256:c", labels: {} },
  ]);
  vi.spyOn(api, "roles").mockResolvedValue([
    { name: "sre", targets: [] },
    { name: "developer", targets: [] },
  ]);
  vi.spyOn(window, "confirm").mockReturnValue(true);
});

/*
 * ⚠️ DURUM KAYDIN ALANLARINDAN TÜRETİLİYOR VE SIRA ÖNEMLİ. Geri alması
 * başarısız olan bir hak "vadesi doldu" değil "geri alma başarısız":
 * süresi dolmuş bir root hesabı makinede duruyor ve kırmızı olmalı. Geri
 * alınmış hak hiçbir vurgu taşımıyor: bitti.
 */
it("kaydın alanlarından doğru durumu türetiyor", () => {
  expect(grantState(grant(), now)).toEqual({ text: "active", cls: "" });
  expect(grantState(grant({ expires_at: "2026-09-13T11:00:00Z" }), now).text).toMatch(/expired/);
  expect(grantState(grant({ applied_at: undefined }), now)).toMatchObject({ cls: "warn" });
  expect(
    grantState(grant({ expires_at: "2026-09-13T11:00:00Z", revoke_error: "target unreachable", revoke_attempts: 3 }), now),
  ).toMatchObject({ cls: "bad", text: expect.stringMatching(/failing.*attempt 3.*unreachable/) });
  expect(grantState(grant({ revoked_at: "2026-09-13T12:30:00Z", revoke_error: "old" }), now)).toEqual({
    text: "revoked",
    cls: "",
  });
});

/*
 * ⚠️ ORTAK GRUPLAR KESİŞİM, SİSTEM GRUPLARI HİÇ YOK. "web" yalnızca
 * web-01'de: iki hedef seçiliyken aday değil — bir hedefte olmayan grubu
 * seçtirmek, o hedefte gizlice yeni bir grup açmak demek. docker (gid 998)
 * hiçbir listede yok, yalnızca sayısı var.
 */
it("ortak grupları kesişimle, sistem gruplarını sayıyla buluyor", () => {
  expect(commonGroups([])).toEqual({ names: [], hidden: 0, hosts: [] });
  expect(commonGroups([inventory("web-01")])).toEqual({ names: ["dba", "web"], hidden: 1, hosts: ["web-01"] });
  expect(commonGroups([inventory("web-01"), inventory("db-01")])).toEqual({
    names: ["dba"],
    hidden: 1,
    hosts: ["web-01", "db-01"],
  });
});

/*
 * ⚠️ LİSTE BÜTÜN HEDEFLERİ KAPSIYOR — sekmenin var olma sebebi — ve geri
 * alınmış hakka düğme çizmiyor. Düğmenin adı hedefi de söylüyor: aynı
 * kişinin iki hedefte hakkı olabilir ve "revoke ayse" hangisi olduğunu
 * söylemezdi.
 */
it("bütün hedeflerin haklarını listeler, geri alınmışa düğme çizmez", async () => {
  vi.spyOn(api, "allGrants").mockResolvedValue({
    grants: [
      grant(),
      grant({ id: "g2", username: "veli", os_user: "veli", target: "db-01", revoked_at: "2026-09-13T11:00:00Z" }),
    ],
    now,
  });
  render(<TemporaryAccess />);

  await screen.findAllByText("veli");
  expect(screen.getByRole("button", { name: /revoke ayse's temporary access to web-01/i })).toBeTruthy();
  expect(screen.queryByRole("button", { name: /revoke veli's/i })).toBeNull();
  expect(screen.getByText("db-01")).toBeTruthy();
});

/*
 * ⚠️ HEDEFLER VE GRUPLAR SEÇİM KUTUSU, HEDEF BAŞINA BİR İSTEK. Roller her
 * zaman aday (rol adı hedefte grup olur); hedeften yüklenen gruplar
 * yalnızca ortak olanlar ve sistem grupları listede yok. Süzgeç görüneni
 * daraltıyor, seçimi düşürmüyor.
 */
it("sihirbaz kişi, hedefler ve gruplarla hedef başına bir istek atıyor", async () => {
  const user = userEvent.setup();
  vi.spyOn(api, "allGrants").mockResolvedValue({ grants: [], now });
  vi.spyOn(api, "targetGroups").mockImplementation((name) => Promise.resolve(inventory(name)));
  const create = vi
    .spyOn(api, "createGrant")
    .mockResolvedValue({ grant: grant(), summary: "4 applied", steps: [step] });
  render(<TemporaryAccess />);
  await screen.findByText(/No temporary access has been granted/);

  fireEvent.click(screen.getByRole("button", { name: /new temporary access/i }));
  await waitFor(() => expect(screen.getByRole("option", { name: /ayse \(account ayse\)/ })).toBeTruthy());
  fireEvent.change(screen.getByLabelText(/^Person/), { target: { value: "ayse" } });

  const grantButton = screen.getByRole("button", { name: /^grant temporary access$/i }) as HTMLButtonElement;
  expect(grantButton.disabled).toBe(true); // hedef seçilmeden gitmez

  const hostBox = await screen.findByRole("combobox", { name: "Hosts" });
  fireEvent.focus(hostBox);
  await user.click(screen.getByRole("option", { name: /web-01/ }));
  await user.click(screen.getByRole("option", { name: /db-01/ }));
  expect(screen.getByRole("button", { name: "remove web-01" })).toBeTruthy();
  expect(screen.getByText(/2 host\(s\) selected/)).toBeTruthy();
  fireEvent.change(hostBox, { target: { value: "cache" } });
  expect(screen.queryByRole("option", { name: /web-01/ })).toBeNull();
  expect(screen.getByRole("button", { name: "remove web-01" })).toBeTruthy(); // süzgeç seçimi düşürmedi
  fireEvent.mouseDown(document.body); // listeyi kapat

  fireEvent.click(screen.getByRole("button", { name: /load groups from the selected hosts/i }));
  await screen.findByText(/Only the 1 group\(s\) present on all 2 selected hosts are offered; 1 system group\(s\) below gid 1000 are not/);
  const groupBox = screen.getByRole("combobox", { name: "Groups" });
  fireEvent.focus(groupBox);
  expect(screen.queryByRole("option", { name: "docker" })).toBeNull();
  expect(screen.queryByRole("option", { name: "web" })).toBeNull();
  expect(screen.getByRole("group", { name: "Common to web-01, db-01" })).toBeTruthy();
  await user.click(screen.getByRole("option", { name: "developer" }));
  await user.click(screen.getByRole("option", { name: "dba" }));
  expect(screen.getByText(/Will join: developer, dba\./)).toBeTruthy();

  fireEvent.click(grantButton);
  await screen.findAllByText(/4 applied/);
  expect(create).toHaveBeenCalledTimes(2);
  expect(create).toHaveBeenCalledWith("web-01", { username: "ayse", groups: ["developer", "dba"], duration: "4h" });
  expect(create).toHaveBeenCalledWith("db-01", { username: "ayse", groups: ["developer", "dba"], duration: "4h" });
});

/*
 * ⚠️ BİR HEDEF DÜŞÜNCE DİĞERLERİ YİNE AÇILIYOR ve her hedefin sonucu ayrı
 * yazılıyor. "db-01 ulaşılamadı" tek bir hata satırına indirgenseydi,
 * web-01'de açılmış hesap ekranda görünmezdi — oysa açık ve süpürücü onu
 * vadesinde toplayacak. Liste de tazeleniyor.
 */
it("bir hedef düşünce diğerleri açılır, sonuçlar hedef başına yazılır", async () => {
  const user = userEvent.setup();
  const list = vi.spyOn(api, "allGrants").mockResolvedValue({ grants: [], now });
  vi.spyOn(api, "createGrant").mockImplementation((name) =>
    name === "web-01"
      ? Promise.resolve({ grant: grant(), summary: "4 applied", steps: [step] })
      : Promise.reject(new Error("could not connect: no route to host")),
  );
  render(<TemporaryAccess />);
  await screen.findByText(/No temporary access/);
  fireEvent.click(screen.getByRole("button", { name: /new temporary access/i }));
  await waitFor(() => expect(screen.getByRole("option", { name: /ayse/ })).toBeTruthy());
  fireEvent.change(screen.getByLabelText(/^Person/), { target: { value: "ayse" } });
  fireEvent.focus(await screen.findByRole("combobox", { name: "Hosts" }));
  await user.click(screen.getByRole("option", { name: /web-01/ }));
  await user.click(screen.getByRole("option", { name: /db-01/ }));
  fireEvent.click(screen.getByRole("button", { name: /^grant temporary access$/i }));

  await screen.findByText(/no route to host/);
  expect(screen.getByText(/4 applied/)).toBeTruthy();
  await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
  expect(screen.queryByRole("button", { name: /^grant temporary access$/i })).toBeNull();
  expect(screen.getByRole("button", { name: /^done$/i })).toBeTruthy();
});

/*
 * ⚠️ TOPLU GERİ ALMA: seçilenler sırayla, biri düşünce durmadan, her hak
 * kendi satırında. Yüz hostta açık bir hakkı tek tek kapatmak yapılmıyor;
 * ama ulaşılamayan hedefin hakkı açık kalıyor ve operatör hangisi olduğunu
 * görmeli. Geri alınmış hak seçilemiyor; iş bitince liste tazeleniyor ve
 * seçim temizleniyor.
 */
it("seçilen hakları sırayla geri alır ve her birinin sonucunu yazar", async () => {
  const list = vi.spyOn(api, "allGrants").mockResolvedValue({
    grants: [
      grant({ id: "a", target: "web-01" }),
      grant({ id: "b", target: "db-01" }),
      grant({ id: "c", target: "cache-03", revoked_at: "2026-09-13T11:00:00Z" }),
    ],
    now,
  });
  const revoke = vi.spyOn(api, "revokeGrant").mockImplementation((id) =>
    id === "a"
      ? Promise.resolve({ grant: grant({ id: "a", revoked_at: now }), summary: "5 applied", steps: [step], sessions_closed: 1 })
      : Promise.reject(new Error("could not connect: no route to host")),
  );
  render(<TemporaryAccess />);
  await screen.findByText("cache-03");

  expect(screen.queryByRole("checkbox", { name: /select ayse on cache-03/ })).toBeNull();
  fireEvent.click(screen.getByRole("checkbox", { name: "select all grants" }));
  expect(screen.getByText("2 selected")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /revoke the selected grants/i }));

  await screen.findByText(/no route to host/);
  expect(screen.getByText(/5 applied — 1 open session\(s\) closed/)).toBeTruthy();
  expect(revoke).toHaveBeenCalledTimes(2);
  expect(revoke).toHaveBeenCalledWith("a");
  expect(revoke).toHaveBeenCalledWith("b");
  await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
  expect(screen.queryByText("2 selected")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: /dismiss these results/i }));
  expect(screen.queryByText(/no route to host/)).toBeNull();
});
