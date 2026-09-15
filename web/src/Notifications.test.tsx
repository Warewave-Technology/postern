import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "./api";
import Notifications from "./Notifications";

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

const list = {
  count: 2,
  items: [
    {
      kind: "identity.pending",
      at: "2026-09-12T08:00:00Z",
      summary: "hasan.demir is waiting for approval",
      detail: "Signed in through dir and has no account here yet; approving one creates it.",
      section: "pending",
    },
    {
      kind: "grant.revoke_failed",
      at: "2026-09-14T18:00:00Z",
      summary: "ayse could not be removed from db-01",
      detail: "The access expired but the account is still there after 4 attempt(s): dial tcp: timeout",
      section: "jit",
    },
  ],
};

/*
 * ⚠️ ÇAN BİR YERE ATMIYOR, LİSTEYİ AÇIYOR — VE SATIR İŞİN YAPILACAĞI
 * YERE GÖTÜRÜYOR. Sayı üç kaynaktan besleniyorken doğrudan keşif
 * ekranına atmak, üçte ikisini görünmez yapardı: tıklayan kişi beklediği
 * şeyi bulamayınca rozete bir daha bakmaz.
 */
it("listeyi açıyor, satır kendi bölümüne götürüyor", async () => {
  vi.spyOn(api, "notifications").mockResolvedValue(list);
  const go = vi.fn();
  render(<Notifications onGo={go} />);

  const bell = await screen.findByRole("button", { name: /2 things waiting for you/i });
  expect(bell.textContent).toContain("2");
  expect(screen.queryByRole("menuitem")).toBeNull();

  fireEvent.click(bell);
  const rows = screen.getAllByRole("menuitem");
  expect(rows).toHaveLength(2);
  // Her satır: ne bekliyor, neden önemli, ne zamandan beri.
  expect(rows[0].textContent).toContain("hasan.demir is waiting for approval");
  expect(rows[0].textContent).toContain("approving one creates it");
  expect(rows[0].textContent).toMatch(/since/i);
  expect(rows[0].querySelector("time")?.getAttribute("datetime")).toBe("2026-09-12T08:00:00Z");

  fireEvent.click(rows[1]);
  expect(go).toHaveBeenCalledWith("jit");
  // Gidince liste kapanıyor: açık kalan bir panel, götürdüğü sayfanın
  // üstünde durur.
  expect(screen.queryByRole("menuitem")).toBeNull();
});

/*
 * ⚠️ BEKLEYEN YOKSA ÇAN DA YOK. Sıfır yazan bir rozet, bakılacak bir şey
 * olmadığında da göz çeken bir işaret bırakır ve bir süre sonra dolu
 * hâli de fark edilmez.
 */
it("bekleyen yokken hiç çizilmiyor", async () => {
  vi.spyOn(api, "notifications").mockResolvedValue({ items: [], count: 0 });
  render(<Notifications onGo={vi.fn()} />);

  await waitFor(() => expect(api.notifications).toHaveBeenCalled());
  expect(screen.queryByRole("button")).toBeNull();
});

/*
 * ⚠️ LİSTE ALINAMAZSA ÜST ÇUBUK SUSUYOR. Hiçbir şey yapamayacağın bir
 * yere konan kırmızı bir satır, her sayfada duran bir alarm olurdu;
 * okunamayan bir kaynağı sunucu zaten listenin İÇİNDE söylüyor.
 */
it("liste alınamazsa üst çubuğa hata basmıyor", async () => {
  vi.spyOn(api, "notifications").mockRejectedValue(new Error("database is down"));
  render(<Notifications onGo={vi.fn()} />);

  await waitFor(() => expect(api.notifications).toHaveBeenCalled());
  expect(screen.queryByRole("button")).toBeNull();
  expect(screen.queryByText(/database is down/)).toBeNull();
});

/*
 * ⚠️ ESC KAPATIR VE ODAK ÇANA DÖNER — kullanıcı menüsüyle aynı gerekçe:
 * odak belgenin başına düşerse klavyeyle gezen kişi en baştan başlar.
 */
it("Esc kapatıyor ve odağı çana veriyor", async () => {
  vi.spyOn(api, "notifications").mockResolvedValue(list);
  render(<Notifications onGo={vi.fn()} />);

  const bell = await screen.findByRole("button", { name: /waiting for you/i });
  fireEvent.click(bell);
  expect(screen.getAllByRole("menuitem")).toHaveLength(2);

  fireEvent.keyDown(bell, { key: "Escape" });
  expect(screen.queryByRole("menuitem")).toBeNull();
  expect(document.activeElement).toBe(bell);
});

/* Dakikada bir tazeliyor, bileşen kalkınca duruyor. */
it("dakikada bir tazeliyor, kalkınca duruyor", async () => {
  vi.useFakeTimers();
  const read = vi.spyOn(api, "notifications").mockResolvedValue(list);
  const { unmount } = render(<Notifications onGo={vi.fn()} />);

  expect(read).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(60_000);
  expect(read).toHaveBeenCalledTimes(2);

  unmount();
  await vi.advanceTimersByTimeAsync(180_000);
  expect(read).toHaveBeenCalledTimes(2);
});
