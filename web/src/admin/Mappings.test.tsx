import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Mappings from "./Mappings";
import { api, type Mapping } from "../api";

const mapping = (over: Partial<Mapping> = {}): Mapping => ({
  group: "hr",
  role: "hr-read",
  created_by: "yigit",
  ...over,
});

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("grup eslemeleri", () => {
  /*
   * ⚠️ İKİ AYRI LİSTE, İKİ AYRI BAYRAK.
   *
   * Sayfada üstte eşlemeler, altta "görülüp eşlenmemiş gruplar" var.
   * Alttaki liste, ÜSTTEKİNİN failed bayrağını okuyordu: eşlenmemiş
   * grup sorgusu çökse bile ekran "Nothing unmapped so far — every
   * group seen in a login matched a role" yazıyordu.
   *
   * Bu cümle bir denetim iddiası: "gelen her grup bir rolle eşleşti".
   * Sorgu çökmüşken söylenince, tam olarak failed'ın önlemek için var
   * olduğu yalanı söylüyor — üstelik onu ekleyen sayfada.
   *
   * Test bu yüzden ÜSTTEKİNİ KASTEN BAŞARILI tutuyor: iki bayrak da
   * düşseydi, yanlış bayrağı okumak da doğru cevabı verirdi ve test
   * hiçbir şey ölçmezdi.
   */
  it("eslenmemis grup sorgusu cokunce 'eslenmemis yok' demez", async () => {
    vi.spyOn(api, "mappings").mockResolvedValue([mapping()]);
    vi.spyOn(api, "roles").mockResolvedValue([]);
    vi.spyOn(api, "unmappedGroups").mockRejectedValue(
      new Error("sorgu zaman aşımına uğradı"),
    );

    render(<Mappings />);

    await waitFor(() =>
      expect(
        screen.getByText(/this list could not be loaded/i),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByText(/nothing unmapped so far/i)).toBeNull();
  });

  // Karşı taraf: sorgu çalışıp gerçekten boş döndüğünde cümle
  // söylenmeli. Olmasaydı, ekranı hep "yüklenemedi" gösteren bir
  // düzeltme de testi geçerdi.
  it("sorgu calisip bos donunce 'eslenmemis yok' der", async () => {
    vi.spyOn(api, "mappings").mockResolvedValue([mapping()]);
    vi.spyOn(api, "roles").mockResolvedValue([]);
    vi.spyOn(api, "unmappedGroups").mockResolvedValue([]);

    render(<Mappings />);

    await waitFor(() =>
      expect(screen.getByText(/nothing unmapped so far/i)).toBeInTheDocument(),
    );
  });
});
