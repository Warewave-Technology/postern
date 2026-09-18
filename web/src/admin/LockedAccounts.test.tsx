import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api, type LockedAccount } from "../api";
import LockedAccounts from "./LockedAccounts";

afterEach(() => vi.restoreAllMocks());

const acct = (over: Partial<LockedAccount> = {}): LockedAccount => ({
  target: "db01",
  username: "ayse",
  os_user: "ayse",
  origin: "created",
  locked_at: "2026-09-18T09:00:00Z",
  ...over,
});

/*
 * ⚠️ SATIR HESABI KİMİN AÇTIĞINI SÖYLÜYOR, VE SİLME ONAYI DA.
 *
 * postern'in açtığı bir hesabı silmek onu geri almak; başka bir aracın
 * açtığını silmek, o aracın sahibi olduğu bir şeyi yok etmek — ve postern
 * onu geri getiremez. İkisini aynı cümleyle onaylatan bir ekran,
 * ikincisini kazayla yaptırır.
 */
it("hesabı kimin açtığını gösteriyor ve silme onayında söylüyor", async () => {
  vi.spyOn(api, "lockedAccounts").mockResolvedValue({
    accounts: [acct({ origin: "adopted", os_user: "veli", username: "veli" })],
  });
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  render(<LockedAccounts />);

  await screen.findByText("veli");
  expect(screen.getByText("something else")).toBeTruthy();

  fireEvent.click(screen.getByRole("button", { name: /delete veli from db01/i }));
  expect(confirm).toHaveBeenCalledTimes(1);
  const asked = confirm.mock.calls[0][0] as string;
  expect(asked).toMatch(/already there when postern first saw it/i);
  expect(asked).toMatch(/cannot put them back/i);
});

/* postern'in açtığı hesapta cümle farklı: geri alınamaz ama postern'in. */
it("postern'in açtığı hesapta onay metni farklı", async () => {
  vi.spyOn(api, "lockedAccounts").mockResolvedValue({ accounts: [acct()] });
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  render(<LockedAccounts />);

  await screen.findByText("postern");
  fireEvent.click(screen.getByRole("button", { name: /delete ayse from db01/i }));
  const asked = confirm.mock.calls[0][0] as string;
  expect(asked).toMatch(/cannot be undone/i);
  expect(asked).not.toMatch(/something else/i);
});

/*
 * ⚠️ "KEEP LOCKED" ONAY İSTEMİYOR. Yıkıcı değil: hesap zaten kilitli ve
 * kalmaya devam ediyor; sorulan şey yalnızca listeden çıkması. Her düğmeye
 * onay koymak, onayı okunmaz yapar ve asıl yıkıcı olanı da sıradanlaştırır.
 */
it("kilitli bırakmak onay istemiyor ve listeyi tazeliyor", async () => {
  const list = vi
    .spyOn(api, "lockedAccounts")
    .mockResolvedValueOnce({ accounts: [acct()] })
    .mockResolvedValueOnce({ accounts: [] });
  const keep = vi.spyOn(api, "keepLockedAccount").mockResolvedValue(undefined);
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  render(<LockedAccounts />);

  await screen.findByText("ayse");
  fireEvent.click(screen.getByRole("button", { name: /keep ayse locked on db01/i }));

  await waitFor(() => expect(keep).toHaveBeenCalledWith("db01", "ayse"));
  expect(confirm).not.toHaveBeenCalled();
  await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
});

/*
 * ⚠️ BOŞ LİSTE, EKRANIN NE İÇİN OLDUĞUNU ANLATIYOR. "Hiçbir şey yok" tek
 * başına, buraya neden gelindiğini bilmeyen birine hiçbir şey söylemiyor.
 */
it("boşken ne beklediğini yazıyor", async () => {
  vi.spyOn(api, "lockedAccounts").mockResolvedValue({ accounts: [] });
  render(<LockedAccounts />);

  expect(await screen.findByText(/No account is waiting for a decision/i)).toBeTruthy();
  expect(screen.getByText(/until somebody says whether they go/i)).toBeTruthy();
});
