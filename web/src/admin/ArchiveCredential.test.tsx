import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import ArchiveCredential from "./ArchiveCredential";
import { api, type ArchiveStatus } from "../api";

const status = (over: Partial<ArchiveStatus> = {}): ArchiveStatus => ({
  configured: true,
  endpoint: "https://minio.internal:9000",
  bucket: "postern-kayitlar",
  prefix: "uretim",
  destination_managed_in: "config file",
  credential_source: "panel",
  access_key_id: "AKIAEXAMPLE",
  can_set_from_panel: true,
  ...over,
});

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal(
    "confirm",
    vi.fn((_m?: string) => true),
  );
});

/*
 * ⚠️ HEDEFİN BURADAN DEĞİŞTİRİLEMEDİĞİ YAZILI OLMALI.
 *
 * Panel admini hedefi kendi kovasına çevirebilseydi, bundan sonraki
 * her oturum kaydı oraya giderdi. Ekranın bunu söylemesi, birinin
 * ileride "kolaylık olsun" diye endpoint alanı eklemesini de
 * zorlaştırıyor.
 */
it("hedefin panelden degistirilemedigini yazar", async () => {
  vi.spyOn(api, "archiveStatus").mockResolvedValue(status());
  render(<ArchiveCredential />);
  await waitFor(() =>
    expect(
      screen.getByText(/cannot be changed from here/i),
    ).toBeInTheDocument(),
  );
  expect(screen.getByText(/redirect the audit trail/i)).toBeInTheDocument();
  // Ve endpoint için bir giriş alanı OLMAMALI.
  expect(screen.queryByLabelText(/endpoint/i)).toBeNull();
  expect(screen.queryByLabelText(/bucket/i)).toBeNull();
});

/*
 * ⚠️ HOST'TAN GELEN KİMLİK PANELDEN DEĞİŞTİRİLEMEZ — ve bu
 * SÖYLENMELİ, sessizce yok sayılmamalı.
 *
 * Kaydedilip yürürlüğe girmeyen bir ayar, bu depodaki en tanıdık
 * arıza: ekran "oldu" der, hiçbir şey olmaz.
 */
it("host kimligi kullaniliyorsa form cizmez ve sebebini soyler", async () => {
  vi.spyOn(api, "archiveStatus").mockResolvedValue(
    status({ credential_source: "host", can_set_from_panel: false }),
  );
  render(<ArchiveCredential />);
  await waitFor(() =>
    expect(screen.getByText(/takes its archive key from the host/i))
      .toBeInTheDocument(),
  );
  expect(screen.queryByRole("button", { name: /save the archive key/i })).toBeNull();
});

// Kimlik yokken sonucu söylenmeli: yükleme durmuş VE budama da durmuş.
it("kimlik yokken budamanin da durdugunu soyler", async () => {
  vi.spyOn(api, "archiveStatus").mockResolvedValue(
    status({ credential_source: "none", access_key_id: "" }),
  );
  render(<ArchiveCredential />);
  await waitFor(() =>
    expect(screen.getByText(/nothing can be pruned while it waits/i))
      .toBeInTheDocument(),
  );
});

/*
 * ⚠️ SIR HİÇ GÖSTERİLMİYOR — maskeli hâli bile.
 *
 * Panelin ihtiyacı alanı doğru çizmek; değeri göstermek değil.
 * Maskeli bir değer döndürmek, geri okunabilir olduğunu ima eder ve
 * gereksiz bir yüzey açardı.
 */
it("sirri hicbir bicimde gostermez", async () => {
  vi.spyOn(api, "archiveStatus").mockResolvedValue(status());
  render(<ArchiveCredential />);
  await waitFor(() =>
    expect(screen.getByText("AKIAEXAMPLE")).toBeInTheDocument(),
  );
  expect(screen.getByText(/never shown again/i)).toBeInTheDocument();
  // Sır kutusu BOŞ açılıyor: saklı değerin yer tutucusu bile yok.
  const secret = screen.getByLabelText(/secret access key/i) as HTMLInputElement;
  expect(secret.value).toBe("");
  expect(secret.placeholder).toBe("");
  expect(secret.type).toBe("password");
});

// Yarım kimlik gönderilemez: iki alan da dolmadan düğme kapalı.
it("yarim kimlik gonderilemez", async () => {
  vi.spyOn(api, "archiveStatus").mockResolvedValue(
    status({ credential_source: "none", access_key_id: "" }),
  );
  const set = vi.spyOn(api, "setArchiveCredential").mockResolvedValue({ ok: true });
  render(<ArchiveCredential />);

  const btn = await screen.findByRole("button", { name: /save the archive key/i });
  expect(btn).toBeDisabled();

  await userEvent.type(screen.getByLabelText(/access key id/i), "AKIANEW");
  expect(btn).toBeDisabled();

  await userEvent.type(screen.getByLabelText(/secret access key/i), "s3cret");
  expect(btn).toBeEnabled();
  await userEvent.click(btn);
  expect(set).toHaveBeenCalledWith("AKIANEW", "s3cret");
});

// Silme onayı, sonucunu söylemeli: disk büyümeye başlar.
it("silme onayi diskin buyuyecegini soyler", async () => {
  vi.spyOn(api, "archiveStatus").mockResolvedValue(status());
  vi.spyOn(api, "clearArchiveCredential").mockResolvedValue({ ok: true });
  const confirmSpy = vi.fn((_m?: string) => true);
  vi.stubGlobal("confirm", confirmSpy);

  render(<ArchiveCredential />);
  const btn = await screen.findByRole("button", { name: /remove the archive key/i });
  await userEvent.click(btn);

  const msg = String(confirmSpy.mock.calls[0]?.[0] ?? "");
  expect(msg).toMatch(/will not be pruned/i);
  expect(msg).toMatch(/disk will grow/i);
});
