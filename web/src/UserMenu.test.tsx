import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import UserMenu from "./UserMenu";

const open = () => fireEvent.click(screen.getByRole("button", { name: /yigit/i }));

/*
 * ⚠️ MENÜ KAPALIYKEN İÇERİĞİ DOM'DA DA YOK. Gizlenmiş ama duran bir
 * menü, klavyeyle gezen kişiye görünmeyen duraklar verir ve ekran
 * okuyucuya olmayan bir menüyü okutur.
 */
it("kapalıyken maddeleri çizmiyor, açılınca çiziyor", () => {
  const profile = vi.fn();
  render(
    <UserMenu
      name="yigit.basalma"
      admin
      sections={[{ title: "Account", items: [{ label: "Profile", onClick: profile }] }]}
    />,
  );

  const button = screen.getByRole("button", { name: /yigit/i });
  expect(button.getAttribute("aria-expanded")).toBe("false");
  expect(screen.queryByRole("menuitem", { name: "Profile" })).toBeNull();

  open();
  expect(button.getAttribute("aria-expanded")).toBe("true");
  fireEvent.click(screen.getByRole("menuitem", { name: "Profile" }));
  expect(profile).toHaveBeenCalledTimes(1);
  // Seçim menüyü kapatıyor: açık kalan bir menü, gidilen sayfanın
  // üstünde durur ve bir daha tıklanana kadar orada kalır.
  expect(screen.queryByRole("menuitem", { name: "Profile" })).toBeNull();
});

/*
 * ⚠️ ESC KAPATIR VE ODAK DÜĞMEYE DÖNER. Odak belgenin başına düşerse,
 * klavyeyle gezen kişi sayfanın en üstünden yeniden başlar.
 */
it("Esc kapatıyor ve odağı düğmeye geri veriyor", () => {
  render(<UserMenu name="yigit.basalma" admin={false} sections={[]} />);
  const button = screen.getByRole("button", { name: /yigit/i });

  open();
  expect(screen.getByRole("menuitem", { name: /sign out/i })).toBeTruthy();

  fireEvent.keyDown(button, { key: "Escape" });
  expect(screen.queryByRole("menuitem", { name: /sign out/i })).toBeNull();
  expect(document.activeElement).toBe(button);
});

/*
 * ⚠️ ÇIKIŞ HÂLÂ FORM POST'U, BAĞLANTI DEĞİL. Menüye taşınırken bir
 * <a href> yapılsaydı, önceden getirilen bir bağlantı ya da başka bir
 * sitenin <img>'i kullanıcının oturumunu kapatabilirdi.
 */
it("çıkış POST ile gidiyor", () => {
  render(<UserMenu name="yigit.basalma" admin sections={[]} />);
  open();

  const form = screen.getByRole("menuitem", { name: /sign out/i }).closest("form");
  expect(form?.getAttribute("method")).toBe("post");
  expect(form?.getAttribute("action")).toBe("/auth/logout");
});

/** Rozet yalnızca yöneticide: olmayan bir yetkiyi ilan etmemeli. */
it("admin rozetini yalnızca yöneticide gösteriyor", () => {
  const { unmount } = render(<UserMenu name="yigit.basalma" admin sections={[]} />);
  expect(screen.getByText("admin")).toBeTruthy();
  unmount();

  render(<UserMenu name="veli" admin={false} sections={[]} />);
  expect(screen.queryByText("admin")).toBeNull();
});
