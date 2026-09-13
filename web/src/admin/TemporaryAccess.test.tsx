import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import TemporaryAccess, { grantState } from "./TemporaryAccess";
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
 * ⚠️ HEDEF BAŞINA BİR İSTEK, GRUPLAR TEK KÜME, KORUNAN GRUP SEÇİLEMEZ.
 * Yazılan "developer" ile envanterden seçilen "dba" aynı listeye giriyor;
 * docker (gid 998) kutusu kapalı — sunucu zaten reddederdi ama operatör
 * bunu "Grant"e basmadan görmeli. Bir hedefte olmayan grup "only on"
 * diye işaretli: seçilirse postern orada açacak, bilerek seçilsin.
 */
it("sihirbaz kişi, hedefler ve gruplarla hedef başına bir istek atıyor", async () => {
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

  const hosts = await screen.findByRole("group", { name: "Hosts" });
  fireEvent.click(within(hosts).getByLabelText(/web-01/));
  fireEvent.click(within(hosts).getByLabelText(/db-01/));
  fireEvent.click(screen.getByRole("button", { name: /load groups from the selected hosts/i }));

  const groups = await screen.findByRole("group", { name: /groups on the selected hosts/i });
  const docker = within(groups).getByLabelText(/docker/) as HTMLInputElement;
  expect(docker.disabled).toBe(true);
  expect(within(groups).getByText(/protected/)).toBeTruthy();
  expect(within(groups).getByText(/only on web-01/)).toBeTruthy();
  expect(screen.getByText(/below 1000 are system groups/)).toBeTruthy();
  fireEvent.click(within(groups).getByLabelText(/^dba/));
  fireEvent.change(screen.getByLabelText(/Groups \(typed/), { target: { value: "developer" } });
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
  const hosts = await screen.findByRole("group", { name: "Hosts" });
  fireEvent.click(within(hosts).getByLabelText(/web-01/));
  fireEvent.click(within(hosts).getByLabelText(/db-01/));
  fireEvent.click(screen.getByRole("button", { name: /^grant temporary access$/i }));

  await screen.findByText(/no route to host/);
  expect(screen.getByText(/4 applied/)).toBeTruthy();
  await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
  expect(screen.queryByRole("button", { name: /^grant temporary access$/i })).toBeNull();
  expect(screen.getByRole("button", { name: /^done$/i })).toBeTruthy();
});
