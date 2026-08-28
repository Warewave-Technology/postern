import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import { ApiError, api, type Me } from "./api";

const me: Me = {
  name: "yigit",
  os_user: "yigit",
  admin: false,
  targets: ["web01"],
  terminal_enabled: true,
};

describe("App önyükleme", () => {
  // ⚠️ Eskiden HER hata "giriş yapmamışsın" ekranına düşüyordu. Yani
  // veritabanı çökmüşken kullanıcıya "oturum aç" deniyor, o da IdP'ye
  // gidip geri dönüyor ve aynı arızaya düşüyordu — çıkışı olmayan bir
  // döngü. 401 ile 500 ayrı ekranlar olmalı.
  it("401'de giris ekrani gosterir", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(401, "unauthenticated"));

    render(<App />);
    await waitFor(() => expect(screen.getByText(/Sign in with your identity provider/i)).toBeInTheDocument());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("500'de giris DEGIL 'ulasilamiyor' ekrani gosterir", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new ApiError(500, "internal error"));

    render(<App />);
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());

    expect(screen.queryByText(/Sign in with your identity provider/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });

  it("ag hatasinda da 'ulasilamiyor' ekrani", async () => {
    vi.spyOn(api, "me").mockRejectedValue(new TypeError("Failed to fetch"));

    render(<App />);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/reach postern/i));
  });

  it("Retry istegi yeniden gonderir", async () => {
    const spy = vi.spyOn(api, "me").mockRejectedValue(new ApiError(500, "boom"));

    render(<App />);
    await waitFor(() => expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument());

    spy.mockResolvedValue(me);
    await userEvent.click(screen.getByRole("button", { name: /retry/i }));

    await waitFor(() => expect(screen.getByText("web01")).toBeInTheDocument());
  });

  it("yuklenirken bos ekran degil 'Loading' gosterir", () => {
    vi.spyOn(api, "me").mockImplementation(() => new Promise(() => {}));

    render(<App />);
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });
});

describe("App gezinmesi", () => {
  // ⚠️ Bulunulan sekme disabled ile işaretleniyordu: bu onu sekme
  // sırasından ÇIKARIYOR ve ekran okuyucuya "kullanılamaz" dedirtiyor.
  // Klavye kullanıcısı olduğu yere odaklanamıyordu.
  it("secili ust sekme odaklanabilir kalir ve aria-current tasir", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ ...me, admin: true });

    render(<App />);
    const home = await screen.findByRole("button", { name: "Home" });

    expect(home).not.toBeDisabled();
    expect(home).toHaveAttribute("aria-current", "page");

    const settings = screen.getByRole("button", { name: "Settings" });
    expect(settings).not.toHaveAttribute("aria-current");
  });

  // Home HERKESİN ekranı; yönetim bölümlerinin tamamı Settings altında.
  // Admin olmayana Settings sekmesi HİÇ çizilmiyor: görünüp 403 vermek,
  // olmayan bir yetkiyi vaat etmektir.
  it("admin olmayana Settings sekmesi gosterilmez", async () => {
    vi.spyOn(api, "me").mockResolvedValue(me);

    render(<App />);
    await screen.findByRole("button", { name: "Home" });

    expect(screen.queryByRole("button", { name: "Settings" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Users" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Admin log" })).not.toBeInTheDocument();
  });

  it("Settings acilinca sol bolum listesi cikar ve secili bolum isaretli olur", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ ...me, admin: true });
    // Overview açılışta oturumları çekiyor; canlı akış jsdom'da yok ve
    // bileşen yoklamaya düşüyor (kendi hata yolu).
    vi.spyOn(api, "sessions").mockResolvedValue([]);

    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Settings" }));

    const overview = await screen.findByRole("button", { name: "Overview" });
    expect(overview).toHaveAttribute("aria-current", "page");
    expect(overview).not.toBeDisabled();

    // Bölümlerin tamamı burada; üst sekmelerde değil.
    for (const label of ["Users", "Roles", "Mappings", "Targets", "LDAP", "Sessions", "Admin log"]) {
      expect(screen.getByRole("button", { name: label })).toBeInTheDocument();
    }
  });
});

describe("App terminal düğmesi", () => {
  // Sunucuda rota yoksa düğme HİÇ gösterilmemeli: basan kullanıcı 404
  // alıp "[disconnected]" görüyor ve kapalı bir özelliğin BOZUK
  // olduğunu sanıyordu.
  it("terminal kapaliyken dugme yok, sebebi yazili", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ ...me, terminal_enabled: false });

    render(<App />);
    await screen.findByText("web01");

    expect(screen.queryByRole("button", { name: /open terminal/i })).not.toBeInTheDocument();
    expect(screen.getByText(/browser terminal is switched off/i)).toBeInTheDocument();
  });

  it("terminal aciksa dugme var", async () => {
    vi.spyOn(api, "me").mockResolvedValue(me);

    render(<App />);
    expect(await screen.findByRole("button", { name: /open terminal to web01/i })).toBeInTheDocument();
  });
});
