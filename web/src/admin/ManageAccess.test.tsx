import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import ManageAccess from "./ManageAccess";
import { api, type ManageCheck } from "../api";

const result = (over: Partial<ManageCheck> = {}): ManageCheck => ({
  target: "web-01",
  stage: "done",
  manageable: true,
  ca_fingerprint: "SHA256:bastionCA",
  family: "debian",
  missing: [],
  tools: {
    add_user: "/usr/sbin/useradd",
    add_group: "/usr/sbin/groupadd",
    mod_user: "/usr/sbin/usermod",
    del_user: "",
    del_group: "",
    visudo: "/usr/sbin/visudo",
  },
  checked_at: "2026-09-13T10:00:00Z",
  ...over,
});

beforeEach(() => vi.restoreAllMocks());

/*
 * ⚠️ KAPALIYKEN DÜĞME YOK. Sunucu manage.enabled kapalıyken ucu hiç
 * kurmuyor; düğmeyi çizmek operatörü bir 404'e bastırırdı. Kart bunun
 * yerine nasıl açılacağını söylüyor — boş bir kart kapalı bir özelliği
 * bozuk gösterirdi.
 */
it("kapalıyken düğme çizmiyor, nasıl açılacağını söylüyor", () => {
  const spy = vi.spyOn(api, "checkManagement");
  render(<ManageAccess name="web-01" enabled={false} />);

  expect(screen.getByText(/switched off on this bastion/i)).toBeTruthy();
  expect(screen.queryByRole("button")).toBeNull();
  expect(spy).not.toHaveBeenCalled();
});

it("yönetilebilir hedefte bulunan araçları ve bastion CA'sını gösteriyor", async () => {
  vi.spyOn(api, "checkManagement").mockResolvedValue(result());
  render(<ManageAccess name="web-01" enabled />);

  fireEvent.click(screen.getByRole("button", { name: /check management access to web-01/i }));

  await waitFor(() => expect(screen.getByText(/can manage this host/i)).toBeTruthy());
  // Yol değil ad: "useradd" ile busybox "adduser" farkı operatörün bilmesi
  // gereken şey, tam yol değil.
  expect(screen.getByText("useradd, groupadd, usermod, visudo")).toBeTruthy();
  expect(screen.getByText("SHA256:bastionCA")).toBeTruthy();
  expect(screen.getByRole("button", { name: /check management access/i }).textContent).toBe(
    "Check again",
  );
});

/*
 * ⚠️ REDDEDİLEN SERTİFİKA "EKSİK ARAÇ" GİBİ ÇİZİLMEMELİ. Bağlanılamadıysa
 * makinede ne olduğunu bilmiyoruz; "Found: none of the tools" yazmak,
 * ölçülmemiş bir şeyi ölçülmüş gibi gösterirdi. CA parmak izi ise tam da
 * bu durumda gerekli.
 */
it("bağlanılamayınca makineyi ölçülmüş gibi göstermiyor", async () => {
  vi.spyOn(api, "checkManagement").mockResolvedValue(
    result({
      stage: "connect",
      manageable: false,
      reason: "the target refused postern's management certificate.",
      detail: "upstream: target refused our certificate",
      family: undefined,
      tools: undefined,
    }),
  );
  render(<ManageAccess name="web-01" enabled />);

  fireEvent.click(screen.getByRole("button"));

  await waitFor(() => expect(screen.getByText(/refused postern's management certificate/i)).toBeTruthy());
  expect(screen.queryByText("Found")).toBeNull();
  expect(screen.queryByText("Family")).toBeNull();
  expect(screen.getByText("SHA256:bastionCA")).toBeTruthy();
});

it("eksik araçları vurguyla adlandırıyor", async () => {
  vi.spyOn(api, "checkManagement").mockResolvedValue(
    result({
      manageable: false,
      reason: "postern can sign in, but this machine lacks what it needs",
      missing: ["visudo"],
      tools: { add_user: "/usr/sbin/useradd", visudo: "" },
    }),
  );
  render(<ManageAccess name="web-01" enabled />);

  fireEvent.click(screen.getByRole("button"));

  const missing = await screen.findByText("visudo");
  expect(missing.className).toContain("bad");
  expect(screen.queryByText(/can manage this host/i)).toBeNull();
});

/*
 * ⚠️ BAŞARISIZ İSTEK ESKİ SONUCU EKRANDA BIRAKMAMALI. İkinci denetim 429
 * ya da 503 döndüğünde önceki "can manage" satırı kalsaydı, operatör onu
 * şimdiki cevap sanardı.
 */
it("başarısız ikinci denetimde eski sonucu siliyor", async () => {
  const spy = vi
    .spyOn(api, "checkManagement")
    .mockResolvedValueOnce(result())
    .mockRejectedValueOnce(new Error("another management check is already running"));
  render(<ManageAccess name="web-01" enabled />);

  fireEvent.click(screen.getByRole("button"));
  await screen.findByText(/can manage this host/i);

  fireEvent.click(screen.getByRole("button"));
  await screen.findByText(/already running/i);
  expect(screen.queryByText(/can manage this host/i)).toBeNull();
  expect(spy).toHaveBeenCalledTimes(2);
});
