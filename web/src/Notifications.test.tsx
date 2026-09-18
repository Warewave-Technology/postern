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
  unread: 1,
  read_at: "2026-09-13T00:00:00Z",
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
 * ⚠️ ÇAN ARTIK BİR KAPI: BİLDİRİM SAYFASINA GÖTÜRÜYOR. Üst çubuktaki
 * açılır panel dar ve geçiciydi — kapanınca "bunu görmüştüm" diye bir
 * şey kalmıyordu ve aynı satırlar her açılışta aynı aciliyetle duruyordu.
 */
it("sayfaya götürüyor ve rozet yalnızca yenileri sayıyor", async () => {
  vi.spyOn(api, "notifications").mockResolvedValue(list);
  const mark = vi.spyOn(api, "markNotificationsRead").mockResolvedValue(undefined);
  const go = vi.fn();
  render(<Notifications onGo={go} />);

  const bell = await screen.findByRole("button", { name: /1 new notification/i });
  // İki iş bekliyor ama yalnızca biri son bakıştan sonra geldi.
  expect(bell.textContent).toContain("1");

  fireEvent.click(bell);
  expect(go).toHaveBeenCalledWith("notifications");
  expect(mark).toHaveBeenCalled();
  // Rozet beklemeden düşüyor: ağ yavaşken dolu kalsaydı kullanıcı
  // tıklamanın işe yaramadığını sanardı.
  await waitFor(() => expect(bell.textContent).not.toContain("1"));
});

/*
 * ⚠️ BEKLEYEN YOKKEN ÇAN DURUYOR, ROZET DURMUYOR. Çanın kaybolması,
 * okunmuş bildirimlere dönmenin yolunu da kapatırdı; sıfır yazan bir
 * rozet ise bakılacak bir şey olmadığında da göz çeker.
 */
it("bekleyen yokken çan duruyor ama rozet çizilmiyor", async () => {
  vi.spyOn(api, "notifications").mockResolvedValue({
    items: [],
    count: 0,
    unread: 0,
    read_at: "2026-09-13T00:00:00Z",
  });
  render(<Notifications onGo={vi.fn()} />);

  const bell = await screen.findByRole("button", { name: /notifications/i });
  await waitFor(() => expect(api.notifications).toHaveBeenCalled());
  expect(bell.querySelector(".bell-count")).toBeNull();
});

/*
 * ⚠️ HEPSİ OKUNMUŞSA SAYI DEĞİL, CÜMLE. "3 waiting, none new" ile "3 new"
 * aynı şey değil ve rozet ikisini ayırt edemezse bir süre sonra hiçbiri
 * bakılmaz.
 */
it("hepsi okunmuşsa rozet yok ama etiket bekleyeni söylüyor", async () => {
  vi.spyOn(api, "notifications").mockResolvedValue({ ...list, unread: 0 });
  render(<Notifications onGo={vi.fn()} />);

  const bell = await screen.findByRole("button", { name: /2 waiting, none new/i });
  expect(bell.querySelector(".bell-count")).toBeNull();
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
  expect(screen.queryByText(/database is down/)).toBeNull();
  expect(screen.getByRole("button").querySelector(".bell-count")).toBeNull();
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

/* Sayfa damgayı ileri alınca çan da tazeleniyor. */
it("refresh değişince sayıyı yeniden okuyor", async () => {
  const read = vi.spyOn(api, "notifications").mockResolvedValue(list);
  const { rerender } = render(<Notifications onGo={vi.fn()} refresh={0} />);

  await waitFor(() => expect(read).toHaveBeenCalledTimes(1));
  rerender(<Notifications onGo={vi.fn()} refresh={1} />);
  await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
});
