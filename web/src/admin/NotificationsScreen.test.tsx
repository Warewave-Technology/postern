import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import NotificationsScreen from "./NotificationsScreen";
import { api } from "../api";

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
      detail: "The access expired but the account is still there after 4 attempt(s): timeout",
      section: "jit",
    },
  ],
};

beforeEach(() => {
  vi.restoreAllMocks();
});

/*
 * ⚠️ HER SATIR NE ZAMANDAN BERİ BEKLEDİĞİNİ SÖYLÜYOR. "Bir şey var" ile
 * "bu üç gündür duruyor" aynı cümle değil; ikincisi bir karar gerektiriyor.
 * En eski üstte, çünkü en uzun süredir duran en çok unutulmuş olan.
 */
it("bekleyenleri zamanıyla listeliyor ve işin yapılacağı yere götürüyor", async () => {
  vi.spyOn(api, "notifications").mockResolvedValue(list);
  vi.spyOn(api, "markNotificationsRead").mockResolvedValue(undefined);
  const go = vi.fn();
  render(<NotificationsScreen onGo={go} />);

  expect(await screen.findByText(/hasan.demir is waiting for approval/)).toBeTruthy();
  expect(screen.getByText(/approving one creates it/)).toBeTruthy();
  const stamps = document.querySelectorAll("time");
  expect(stamps[0].getAttribute("datetime")).toBe("2026-09-12T08:00:00Z");

  fireEvent.click(screen.getAllByRole("button", { name: /go where this is handled/i })[1]);
  expect(go).toHaveBeenCalledWith("jit");
});

/*
 * ⚠️ AÇILINCA OKUNMUŞ SAYILIYOR. Her satıra ayrı ayrı tıklamasını
 * beklemek, rozeti hiç sıfırlanmayan bir sayaca çevirirdi.
 */
it("açılınca damgayı ileri alıyor ve çana haber veriyor", async () => {
  vi.spyOn(api, "notifications").mockResolvedValue(list);
  const mark = vi.spyOn(api, "markNotificationsRead").mockResolvedValue(undefined);
  const onRead = vi.fn();
  render(<NotificationsScreen onGo={vi.fn()} onRead={onRead} />);

  await waitFor(() => expect(mark).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(onRead).toHaveBeenCalled());
});

/*
 * ⚠️ BU ZİYARETTE "new" İŞARETİ HÂLÂ GÖRÜNÜYOR.
 *
 * Damga sayfa açıldıktan sonra ileri alınıyor ama ekranda GELEN değer
 * kullanılıyor: önce damgalayıp sonra okumak, yöneticinin tam da bakmaya
 * geldiği şeyi işaretsiz gösterirdi.
 */
it("son bakıştan sonra geleni işaretliyor", async () => {
  vi.spyOn(api, "notifications").mockResolvedValue(list);
  vi.spyOn(api, "markNotificationsRead").mockResolvedValue(undefined);
  render(<NotificationsScreen onGo={vi.fn()} />);

  await screen.findByText(/1 new since you last looked, of 2 waiting/);
  const marked = document.querySelectorAll("li.is-new");
  expect(marked).toHaveLength(1);
  expect(marked[0].textContent).toContain("ayse could not be removed");
});

/*
 * ⚠️ DAMGALAMA BİR KEZ KOŞUYOR — ÖLÇÜLDÜ.
 *
 * onRead satır içi bir ok fonksiyonu olarak geliyor, yani her render'da
 * yeni bir kimlik. Effect deps'ine konunca: damgala → onRead → üst
 * bileşen render → yeni onRead → yeniden damgala. Görsel tarama testi
 * 30 saniyede zaman aşımına uğradı; üretimde bu, sayfa açık kaldığı
 * sürece sunucuya kesintisiz istek demekti.
 */
it("üst bileşen yeniden çizilse de damgayı bir kez yazıyor", async () => {
  vi.spyOn(api, "notifications").mockResolvedValue(list);
  const mark = vi.spyOn(api, "markNotificationsRead").mockResolvedValue(undefined);

  const { rerender } = render(<NotificationsScreen onGo={vi.fn()} onRead={() => {}} />);
  await waitFor(() => expect(mark).toHaveBeenCalledTimes(1));

  // Her seferinde YENİ bir fonksiyon kimliği: üst bileşenin yaptığı şey.
  for (let i = 0; i < 5; i++) {
    rerender(<NotificationsScreen onGo={vi.fn()} onRead={() => {}} />);
  }
  await waitFor(() => expect(api.notifications).toHaveBeenCalledTimes(1));
  expect(mark).toHaveBeenCalledTimes(1);
});

/* Bekleyen yokken sayfa boş durumu söylüyor, hata değil. */
it("bekleyen yokken boş durumu anlatıyor", async () => {
  vi.spyOn(api, "notifications").mockResolvedValue({
    items: [],
    count: 0,
    unread: 0,
    read_at: "2026-09-13T00:00:00Z",
  });
  vi.spyOn(api, "markNotificationsRead").mockResolvedValue(undefined);
  render(<NotificationsScreen onGo={vi.fn()} />);

  expect(await screen.findByText(/nothing is waiting/i)).toBeTruthy();
});
