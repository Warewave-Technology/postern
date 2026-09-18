import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, Group, Target } from "../api";
import Groups from "./Groups";

const groups: Group[] = [
  {
    name: "sre",
    // Yüz hedefli rol: listenin bunu SAYMASI gerekiyor, saymazsa tablo
    // okunmaz oluyor (bu ekranın var olma sebebi).
    targets: Array.from({ length: 100 }, (_, i) => `host-${String(i).padStart(3, "0")}`),
    sudo: {
      commands: [
        { command: "/usr/sbin/nginx -t", run_as: "root" },
        { command: "/usr/bin/pg_ctl reload", run_as: "postgres" },
      ],
      acknowledged: true,
      updated_by: "yigit",
      updated_at: "2026-09-14T10:00:00Z",
    },
  },
  { name: "kuralsiz", targets: [], sudo: undefined },
];

const targets: Target[] = [
  { name: "db-01", host: "db-01.internal", port: 22, labels: {} } as Target,
  { name: "host-000", host: "h0.internal", port: 22, labels: {} } as Target,
];

beforeEach(() => {
  vi.spyOn(api, "groups").mockResolvedValue(groups);
  vi.spyOn(api, "targets").mockResolvedValue(targets);
  vi.spyOn(api, "rolePaths").mockResolvedValue([]);
});

afterEach(() => vi.restoreAllMocks());

/*
 * ⚠️ LİSTE SAYIYOR, ADLARI DÖKMÜYOR. Yüz hedefi rozet rozet çizen bir
 * satır, tablonun cevaplaması gereken "hangi rol ağır" sorusunu
 * boğuyordu. Arama yine hedef adlarını kapsıyor: adlar satırda
 * görünmese de "db-01'e hangi rol eriyor" sorulabilmeli.
 */
it("rolleri sayılarıyla listeliyor ve aramayı hedef adına açıyor", async () => {
  render(<Groups />);
  const row = (await screen.findByRole("button", { name: "sre" })).closest("tr")!;

  expect(within(row).getByText("100 hosts")).toBeTruthy();
  expect(within(row).getByText("2 commands")).toBeTruthy();
  expect(within(row).getByText(/acknowledged root escape/i)).toBeTruthy();
  expect(row.textContent).not.toMatch(/host-042/);

  const kuralsiz = screen.getByRole("button", { name: "kuralsiz" }).closest("tr")!;
  expect(within(kuralsiz).getByText("no targets")).toBeTruthy();
  expect(within(kuralsiz).getByText("no rule")).toBeTruthy();

  fireEvent.change(screen.getByPlaceholderText("Search groups…"), {
    target: { value: "host-042" },
  });
  expect(screen.getByRole("button", { name: "sre" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "kuralsiz" })).toBeNull();
});

/*
 * ⚠️ AYRINTI SAYFADA: hedefler, sudo kuralı ve yol kuralları bir arada,
 * ve sayfa listeye dönebiliyor. Hepsi satırdayken yüz hedefli bir rol
 * tabloyu bozuyordu.
 */
it("ada tıklayınca rolün sayfasını açıyor", async () => {
  render(<Groups />);
  fireEvent.click(await screen.findByRole("button", { name: "sre" }));

  expect(await screen.findByRole("heading", { name: "sre" })).toBeTruthy();
  expect(screen.getByRole("heading", { name: /^targets$/i })).toBeTruthy();
  expect(screen.getByRole("heading", { name: /^sudo$/i })).toBeTruthy();
  expect(screen.getByRole("heading", { name: /^sftp paths$/i })).toBeTruthy();
  // Kural sayfada komutlarıyla duruyor (tabloda), listede yalnızca sayılıyordu.
  expect(screen.getByText("/usr/sbin/nginx -t")).toBeTruthy();
  expect(screen.getByPlaceholderText(/search commands/i)).toBeTruthy();
  // Rolü silmek de sayfada: liste satırında düğme kalabalığı yapıyordu.
  expect(screen.getByRole("button", { name: /delete group sre/i })).toBeTruthy();

  fireEvent.click(screen.getByRole("button", { name: /all groups/i }));
  expect(await screen.findByRole("heading", { name: "Groups" })).toBeTruthy();
});

/*
 * ⚠️ VERİLMİŞ HEDEF YENİDEN SUNULMUYOR: sunucu onu sessizce yutuyor
 * (ON CONFLICT DO NOTHING), yani hiçbir şeyi değiştirmeyen tıklama
 * başarı gibi görünürdü.
 */
it("sayfadan hedef veriyor ve geri alıyor", async () => {
  const grant = vi.spyOn(api, "grantTarget").mockResolvedValue(undefined);
  const revoke = vi.spyOn(api, "revokeTarget").mockResolvedValue(undefined);
  vi.stubGlobal("confirm", vi.fn(() => true));

  render(<Groups />);
  fireEvent.click(await screen.findByRole("button", { name: "sre" }));

  /*
   * ⚠️ VERME MODALDA VE ÇOKLU. Kart gövdesindeki tek seçimlik kutu yüz
   * hedefli bir envanterde aranamıyordu; modal kendi MultiSelect'imizi
   * taşıyor ve verilmiş hedefi hiç sunmuyor.
   */
  fireEvent.click(screen.getByRole("button", { name: /grant targets/i }));
  fireEvent.focus(await screen.findByRole("combobox", { name: /targets/i }));
  expect(screen.queryByRole("option", { name: /host-000/ })).toBeNull();
  fireEvent.click(screen.getByRole("option", { name: /db-01/ }));
  fireEvent.click(screen.getByRole("button", { name: /grant 1 target/i }));
  await waitFor(() => expect(grant).toHaveBeenCalledWith("sre", "db-01"));

  fireEvent.click(screen.getAllByRole("button", { name: /revoke host-000 from group sre/i })[0]);
  await waitFor(() => expect(revoke).toHaveBeenCalledWith("sre", "host-000"));
});
