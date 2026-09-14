import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "./api";
import NewMachines from "./NewMachines";

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

/*
 * ⚠️ ROZET SAYIYI TAŞIYOR, KIRMIZI BİR NOKTA DEĞİL. "Bir şey var" ile
 * "yirmi iki makine bekliyor" aynı aciliyette değil; nokta ikisini de
 * aynı gösterir. Tıklayınca keşif ekranına götürüyor, çünkü çanın
 * söylediği şeyin yapılacağı yer orası.
 */
it("bekleyen makine sayısını gösteriyor ve keşif ekranına götürüyor", async () => {
  vi.spyOn(api, "discoveryNewCount").mockResolvedValue({ new: 22 });
  const open = vi.fn();
  render(<NewMachines onOpen={open} />);

  const bell = await screen.findByRole("button", {
    name: /22 discovered machines waiting to be registered/i,
  });
  expect(bell.textContent).toContain("22");

  fireEvent.click(bell);
  expect(open).toHaveBeenCalledTimes(1);
});

/*
 * ⚠️ BEKLEYEN YOKSA ÇAN DA YOK. Sıfır yazan bir rozet, bakılacak bir şey
 * olmadığında da göz çeken bir işaret bırakır ve bir süre sonra dolu
 * hâli de fark edilmez.
 */
it("bekleyen yokken hiç çizilmiyor", async () => {
  vi.spyOn(api, "discoveryNewCount").mockResolvedValue({ new: 0 });
  render(<NewMachines onOpen={vi.fn()} />);

  await waitFor(() => expect(api.discoveryNewCount).toHaveBeenCalled());
  expect(screen.queryByRole("button")).toBeNull();
});

/*
 * ⚠️ SAYI ALINAMIYORSA SESSİZ. Üst çubuk, hiçbir şey yapamayacağın bir
 * yer; oraya kırmızı bir hata satırı koymak, asıl ekranın (Discovery)
 * zaten söylediği şeyi her sayfaya taşımak olurdu.
 */
it("sayı alınamazsa üst çubuğa hata basmıyor", async () => {
  vi.spyOn(api, "discoveryNewCount").mockRejectedValue(new Error("database is down"));
  render(<NewMachines onOpen={vi.fn()} />);

  await waitFor(() => expect(api.discoveryNewCount).toHaveBeenCalled());
  expect(screen.queryByRole("button")).toBeNull();
  expect(screen.queryByText(/database is down/)).toBeNull();
});

/*
 * ⚠️ DAKİKADA BİR SORUYOR ve bileşen kalkınca duruyor: unutulan bir
 * zamanlayıcı, panel açık kaldıkça sunucuya sormaya devam eder.
 */
it("dakikada bir tazeliyor, kalkınca duruyor", async () => {
  vi.useFakeTimers();
  const read = vi.spyOn(api, "discoveryNewCount").mockResolvedValue({ new: 1 });
  const { unmount } = render(<NewMachines onOpen={vi.fn()} />);

  expect(read).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(60_000);
  expect(read).toHaveBeenCalledTimes(2);

  unmount();
  await vi.advanceTimersByTimeAsync(180_000);
  expect(read).toHaveBeenCalledTimes(2);
});
