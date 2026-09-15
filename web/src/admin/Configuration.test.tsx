import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../api";
import Configuration from "./Configuration";

afterEach(() => vi.restoreAllMocks());

const view = {
  path: "/etc/postern/config.yaml",
  groups: [
    {
      title: "recording",
      entries: [
        { key: "recording.dir", value: "/var/lib/postern/recordings", note: "where session recordings are written" },
        { key: "recording.archive.endpoint", value: "(not set)", note: "where recordings are copied off the box" },
      ],
    },
  ],
  withheld: [
    { key: "database.dsn", value: "", note: "carries the database password" },
    { key: "oidc.client_secret", value: "", note: "is a secret" },
  ],
};

/*
 * ⚠️ EKRAN SALT-OKUNUR OLDUĞUNU GÖSTERMEK ZORUNDA. Değerleri bir forma
 * benzeyen kutularda göstermek, operatöre buradan değiştirilebileceğini
 * söylerdi; oysa dosya host'ta ve değişiklik yeniden başlatma istiyor.
 */
it("değerleri yazı olarak gösteriyor, hiçbir yazma alanı açmıyor", async () => {
  vi.spyOn(api, "config").mockResolvedValue(view);
  vi.spyOn(api, "archiveStatus").mockResolvedValue({ configured: false } as never);
  render(<Configuration />);

  expect(await screen.findByText("/etc/postern/config.yaml")).toBeTruthy();
  expect(screen.getByText("recording.dir")).toBeTruthy();
  expect(screen.getByText("/var/lib/postern/recordings")).toBeTruthy();
  // Yazılmamış ayar "boş" değil, "(not set)" diye okunuyor.
  expect(screen.getByText("(not set)")).toBeTruthy();

  expect(screen.queryByRole("textbox")).toBeNull();
  expect(screen.queryByRole("checkbox")).toBeNull();
});

/*
 * ⚠️ GİZLENEN ALAN ADIYLA VE SEBEBİYLE GÖRÜNÜYOR. Hiç görünmeseydi
 * operatör ayarın yazılmadığını sanıp ikinci kez yazmaya kalkardı;
 * değeri ise tarayıcıya hiç gelmiyor.
 */
it("gösterilmeyen alanları sebebiyle sayıyor", async () => {
  vi.spyOn(api, "config").mockResolvedValue(view);
  vi.spyOn(api, "archiveStatus").mockResolvedValue({ configured: false } as never);
  render(<Configuration />);

  await screen.findByText("Not shown");
  expect(screen.getByText("database.dsn")).toBeTruthy();
  expect(screen.getByText("carries the database password")).toBeTruthy();
});

/*
 * ⚠️ ARŞİV KARTI BU EKRANDA. LDAP ekranının altında duruyordu: yerel
 * kimlikle çalışan bir kurulum onu hiç görmüyordu, oysa kayıtlarını
 * dışarı yazması gereken de o kurulum.
 */
it("arşiv kimliği kartını da çiziyor", async () => {
  vi.spyOn(api, "config").mockResolvedValue(view);
  vi.spyOn(api, "archiveStatus").mockResolvedValue({ configured: false } as never);
  render(<Configuration />);

  expect(await screen.findByText("Recording archive")).toBeTruthy();
});

/* Okunamazsa sebebi ekranda; boş bir sayfa "ayar yok" diye okunurdu. */
it("okunamazsa sebebini yazıyor", async () => {
  vi.spyOn(api, "config").mockRejectedValue(new Error("forbidden"));
  vi.spyOn(api, "archiveStatus").mockResolvedValue({ configured: false } as never);
  render(<Configuration />);

  await waitFor(() => expect(screen.getByText(/forbidden/)).toBeTruthy());
});
