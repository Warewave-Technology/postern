import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import TemporaryAccess, { grantState } from "./TemporaryAccess";
import { api, type Grant } from "../api";

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

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, "users").mockResolvedValue([
    { name: "ayse", os_user: "ayse", admin: false, roles: [], keys: 1 } as never,
  ]);
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

it("liste boşken 'yok' diyor, doluyken geri alınmış hakka düğme çizmiyor", async () => {
  vi.spyOn(api, "grants").mockResolvedValue({
    grants: [grant(), grant({ id: "g2", username: "veli", os_user: "veli", revoked_at: "2026-09-13T11:00:00Z" })],
    now,
  });
  render(<TemporaryAccess name="web-01" />);

  await screen.findAllByText("veli");
  expect(screen.getByRole("button", { name: /revoke ayse's temporary access/i })).toBeTruthy();
  expect(screen.queryByRole("button", { name: /revoke veli's temporary access/i })).toBeNull();
});

it("kişi seçilmeden vermiyor, seçilince isteği doğru kuruyor", async () => {
  vi.spyOn(api, "grants").mockResolvedValue({ grants: [], now });
  const create = vi.spyOn(api, "createGrant").mockResolvedValue({
    grant: grant(),
    summary: "4 applied",
    steps: [{ kind: "group.add", command: "sudo -n groupadd dba", why: "group dba is missing", outcome: "done" }],
  });
  vi.spyOn(window, "confirm").mockReturnValue(true);
  render(<TemporaryAccess name="web-01" />);
  await screen.findByText(/No temporary access has been granted/);

  const button = screen.getByRole("button", { name: /grant temporary access on web-01/i }) as HTMLButtonElement;
  expect(button.disabled).toBe(true);

  await waitFor(() => expect(screen.getByRole("option", { name: /ayse \(account ayse\)/ })).toBeTruthy());
  fireEvent.change(screen.getByLabelText(/Person/), { target: { value: "ayse" } });
  fireEvent.change(screen.getByLabelText(/Groups/), { target: { value: "dba, docker" } });
  fireEvent.change(screen.getByLabelText(/^For/), { target: { value: "8h" } });
  fireEvent.change(screen.getByLabelText(/Commands the account may run/), {
    target: { value: "/usr/bin/systemctl restart nginx\n\n/usr/bin/journalctl -u nginx" },
  });
  fireEvent.click(screen.getByLabelText(/accept it/));
  fireEvent.click(button);

  await screen.findByText(/4 applied/);
  expect(create).toHaveBeenCalledWith("web-01", {
    username: "ayse",
    groups: ["dba", "docker"],
    duration: "8h",
    sudo: {
      commands: [
        { path: "/usr/bin/systemctl", args: ["restart", "nginx"] },
        { path: "/usr/bin/journalctl", args: ["-u", "nginx"] },
      ],
      acknowledged: true,
    },
  });
});

/*
 * ⚠️ BAŞARISIZ HAK DA LİSTEYE DÜŞÜYOR. Sunucu yarım kalan hesabı kaydediyor
 * ve süpürücü toplayacak; hata gösterilip liste tazelenmezse operatör o
 * satırı görmez ve makinede ne olduğunu bilmez.
 */
it("başarısız istekten sonra hatayı gösterip listeyi tazeliyor", async () => {
  const list = vi
    .spyOn(api, "grants")
    .mockResolvedValueOnce({ grants: [], now })
    .mockResolvedValueOnce({ grants: [grant({ applied_at: undefined, apply_report: "0 applied, 1 failed" })], now });
  vi.spyOn(api, "createGrant").mockRejectedValue(new Error("group.add: exited with status 127"));
  vi.spyOn(window, "confirm").mockReturnValue(true);
  render(<TemporaryAccess name="web-01" />);
  await screen.findByText(/No temporary access/);
  await waitFor(() => expect(screen.getByRole("option", { name: /ayse/ })).toBeTruthy());
  fireEvent.change(screen.getByLabelText(/Person/), { target: { value: "ayse" } });
  fireEvent.click(screen.getByRole("button", { name: /grant temporary access/i }));

  await screen.findByText(/exited with status 127/);
  await screen.findByText(/not fully applied/);
  expect(list).toHaveBeenCalledTimes(2);
});
