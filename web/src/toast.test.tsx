import { render, screen, act } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastHost, toast, dismissAllToasts } from "./toast";

beforeEach(() => {
  vi.useFakeTimers();
  dismissAllToasts();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("geçici bildirim", () => {
  it("görünüp kendiliğinden kayboluyor", () => {
    render(<ToastHost />);
    expect(screen.queryByText("Copied")).toBeNull();

    act(() => toast("Copied", 1000));
    expect(screen.getByText("Copied")).toBeTruthy();

    // Süresi dolmadan DURUYOR: hemen kaybolan bir onay, görülmeyen
    // bir onaydır.
    act(() => void vi.advanceTimersByTime(900));
    expect(screen.getByText("Copied")).toBeTruthy();

    act(() => void vi.advanceTimersByTime(200));
    expect(screen.queryByText("Copied")).toBeNull();
  });

  // Üst üste gelen bildirimler birbirini yemiyor: iki işlem yapan
  // kullanıcı ikisinin de olduğunu görmeli.
  it("birden çok bildirim aynı anda durabiliyor", () => {
    render(<ToastHost />);
    act(() => {
      toast("Copied", 1000);
      toast("Authenticator turned off", 1000);
    });
    expect(screen.getByText("Copied")).toBeTruthy();
    expect(screen.getByText("Authenticator turned off")).toBeTruthy();
  });

  /*
   * ⚠️ EKRAN OKUYUCUYA "polite" DUYURULUYOR.
   *
   * assertive olsaydı her "Copied" kullanıcının o anda okuduğu şeyi
   * böler; hiç duyurulmasaydı ekranı görmeyen kullanıcı işlemin olup
   * olmadığını bilemezdi.
   */
  it("ekran okuyucuya duyuruluyor ama sözünü kesmiyor", () => {
    render(<ToastHost />);
    act(() => toast("Copied", 1000));
    const host = screen.getByRole("status");
    expect(host.getAttribute("aria-live")).toBe("polite");
  });

  // Hiç bildirim yokken DOM'a hiçbir şey konmuyor: boş bir kutu,
  // altındaki arayüzün üstünde görünmez bir katman bırakır.
  it("bildirim yokken hiçbir şey çizmiyor", () => {
    const { container } = render(<ToastHost />);
    expect(container.firstChild).toBeNull();
  });
});
