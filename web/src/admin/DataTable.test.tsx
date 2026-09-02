import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import DataTable, { Column, compare } from "./DataTable";

type Row = { name: string; seen: number; note: string };

const rows: Row[] = [
  { name: "web-10", seen: 2, note: "env=prod" },
  { name: "web-2", seen: 30, note: "env=staging" },
  { name: "db-01", seen: 9, note: "env=prod team=data" },
];

const columns: Column<Row>[] = [
  { key: "name", header: "Name", value: (r) => r.name },
  { key: "seen", header: "Seen", className: "num", value: (r) => r.seen },
  { key: "note", header: "Note", value: (r) => r.note },
  {
    key: "actions",
    header: "Actions",
    srHeader: true,
    className: "actions",
    render: (r) => <button aria-label={`act on ${r.name}`}>Act</button>,
  },
];

const names = () =>
  screen
    .getAllByRole("row")
    .slice(1)
    .map((r) => within(r).getAllByRole("cell")[0].textContent);

function setup(extra?: Partial<React.ComponentProps<typeof DataTable<Row>>>) {
  return render(
    <DataTable
      rows={rows}
      columns={columns}
      rowKey={(r) => r.name}
      noun="target"
      searchLabel="search targets"
      {...extra}
    />,
  );
}

describe("DataTable sıralama", () => {
  it("baslik tiklaninca siralar ve yonu cevirir", async () => {
    setup();
    const header = screen.getByRole("button", { name: /sort by Name/i });

    await userEvent.click(header);
    expect(names()).toEqual(["db-01", "web-2", "web-10"]);

    await userEvent.click(header);
    expect(names()).toEqual(["web-10", "web-2", "db-01"]);
  });

  // ⚠️ SAYISAL SIRALAMA. Metin karşılaştırması "web-10"u "web-2"den önce
  // koyar; adları sayı ile biten hedeflerde (web-1 … web-10) liste
  // gözle yanlış görünür ve operatör aradığını olmayan yerde arar.
  it("ad icindeki sayilar dogru siralanir", async () => {
    setup();
    await userEvent.click(
      screen.getByRole("button", { name: /sort by Name/i }),
    );
    expect(names()).toEqual(["db-01", "web-2", "web-10"]);
  });

  it("sayi sutunu metin degil sayi olarak siralanir", async () => {
    setup();
    await userEvent.click(
      screen.getByRole("button", { name: /sort by Seen/i }),
    );
    // Metin sıralaması olsaydı "2, 30, 9" gelirdi.
    expect(names()).toEqual(["web-10", "db-01", "web-2"]);
  });

  // Ekran okuyucu sıralamayı aria-sort'tan okuyor; ok simgesi tek başına
  // yalnızca göreni bilgilendirir.
  it("siralanan sutun aria-sort tasir, digerleri tasimaz", async () => {
    setup();
    await userEvent.click(
      screen.getByRole("button", { name: /sort by Name/i }),
    );

    const headers = screen.getAllByRole("columnheader");
    const nameTh = headers.find((h) => h.textContent?.includes("Name"))!;
    const seenTh = headers.find((h) => h.textContent?.includes("Seen"))!;

    expect(nameTh).toHaveAttribute("aria-sort", "ascending");
    expect(seenTh).not.toHaveAttribute("aria-sort");
  });
});

describe("DataTable arama", () => {
  it("gorunmeyen sutunlarda da arar ve sayaci gunceller", async () => {
    setup();
    const box = screen.getByLabelText("search targets");

    await userEvent.type(box, "team=data");
    expect(names()).toEqual(["db-01"]);
    expect(screen.getByRole("status")).toHaveTextContent("1 of 3 targets");
  });

  // Terimler AYRI aranıyor: "prod web" yazan kişi iki alanda birden
  // eşleşme bekliyor, tek bir bitişik dize değil.
  it("bosluklu sorgu her terimi ayri arar", async () => {
    setup();
    await userEvent.type(screen.getByLabelText("search targets"), "prod web");
    expect(names()).toEqual(["web-10"]);
  });

  // ⚠️ "kayıt yok" ile "aramanla eşleşen yok" AYRI şeyler: ikisini aynı
  // ekranla göstermek, operatöre var olan bir kaydı yok saydırır.
  it("eslesme yoksa aramaya ozgu mesaj cikar", async () => {
    setup();
    await userEvent.type(screen.getByLabelText("search targets"), "yok-boyle");

    expect(names()).toEqual([]);
    expect(screen.getByText(/No target matches/i)).toBeInTheDocument();
  });

  it("temizleme dugmesi listeyi geri getirir", async () => {
    setup();
    const box = screen.getByLabelText("search targets");
    await userEvent.type(box, "db");
    expect(names()).toEqual(["db-01"]);

    await userEvent.click(
      screen.getByRole("button", { name: /clear the search/i }),
    );
    expect(names()).toHaveLength(3);
  });

  // Eylem sütunu görsel olarak başlıksız ama ADSIZ değil.
  it("eylem sutununun basligi ekran okuyucuda var", () => {
    setup();
    const headers = screen.getAllByRole("columnheader");
    expect(headers[headers.length - 1]).toHaveTextContent("Actions");
  });
});

describe("compare", () => {
  // Metinlerde numeric harmanlama: onsuz "web-10" < "web-2".
  it("metindeki sayilari sayi gibi siralar", () => {
    expect(compare("web-2", "web-10")).toBeLessThan(0);
    expect(compare("db-01", "web-2")).toBeLessThan(0);
  });

  // ⚠️ ÖLÇÜLDÜ: sayıyı metne çevirip harmanlamak bu iki çifti YANLIŞ
  // sıralıyor — numeric harmanlama ondalık noktayı ve eksiyi sayı
  // olarak okumuyor. Sayılar için ayrı yol bu yüzden var.
  it("kesirli ve negatif sayilari sayisal siralar", () => {
    expect(compare(0.5, 0.25)).toBeGreaterThan(0);
    expect(compare(-1, -2)).toBeGreaterThan(0);
    expect(compare(2, 30)).toBeLessThan(0);
  });
});
