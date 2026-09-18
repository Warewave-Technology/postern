import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Mappings from "./Mappings";
import { api, type Mapping } from "../api";

const mapping = (over: Partial<Mapping> = {}): Mapping => ({
  group: "hr",
  directory_group: "hr-read",
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
   * group seen in a login matched a group" yazıyordu.
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
    vi.spyOn(api, "groups").mockResolvedValue([]);
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
    vi.spyOn(api, "groups").mockResolvedValue([]);
    vi.spyOn(api, "unmappedGroups").mockResolvedValue([]);

    render(<Mappings />);

    await waitFor(() =>
      expect(screen.getByText(/nothing unmapped so far/i)).toBeInTheDocument(),
    );
  });
});

/*
 * ⚠️ SATIRIN İKİ UCU AYRI DEĞERLER — ölçüldü, gözle yakalandı.
 *
 * Yeniden adlandırmadan sonra iki alan da "group" adını taşıyordu ve
 * satır çizimi ikisini de aynı alandan okuyordu: tablo "dba → dba"
 * gösteriyordu. Ekran doğru çalışıyormuş gibi duruyordu, çünkü
 * eşlemelerin çoğunda iki ad zaten aynı; farklı olduğu tek satırda
 * eşleme yanlış okunurdu. Testler bunu yakalamıyordu, bu yüzden bu test
 * var: iki uç FARKLI olduğunda ikisi de ekranda görünmeli.
 */
it("dizinin grubunu ve postern'in grubunu ayrı sütunlarda gösteriyor", async () => {
  vi.spyOn(api, "mappings").mockResolvedValue([
    mapping({ directory_group: "CN=Database Administrators,OU=Groups,DC=example,DC=com", group: "dba" }),
  ]);
  vi.spyOn(api, "unmappedGroups").mockResolvedValue([]);
  vi.spyOn(api, "groups").mockResolvedValue([{ name: "dba", targets: [] }]);
  render(<Mappings />);

  expect(
    await screen.findByText("CN=Database Administrators,OU=Groups,DC=example,DC=com"),
  ).toBeTruthy();
  // "dba" hem satırda hem seçim listesinde geçiyor; aranan şey SATIRDAKİ.
  const row = screen.getByText(
    "CN=Database Administrators,OU=Groups,DC=example,DC=com",
  ).closest("tr");
  expect(row?.textContent).toContain("dba");

  // Sütun başlıkları da hangi grubun hangisi olduğunu söylüyor.
  expect(screen.getByRole("columnheader", { name: /directory group/i })).toBeTruthy();
});
