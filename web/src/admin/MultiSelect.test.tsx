import { fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { expect, it } from "vitest";
import MultiSelect, { type MultiSelectOption } from "./MultiSelect";

const options: MultiSelectOption[] = [
  { value: "web-01", label: "web-01", hint: "10.0.1.11:22" },
  { value: "web-02", label: "web-02", hint: "10.0.1.12:22" },
  { value: "db-01", label: "db-01", hint: "10.0.2.5:22" },
  { value: "root", label: "root", disabled: true, group: "System" },
  { value: "dba", label: "dba", group: "Groups" },
];

/** Kontrollü bileşen: değer dışarıda tutuluyor, gerçek kullanımdaki gibi. */
function Harness({ initial = [] as string[] }) {
  const [value, setValue] = useState<string[]>(initial);
  return (
    <>
      <MultiSelect label="Hosts" options={options} value={value} onChange={setValue} />
      <output data-testid="value">{value.join(",")}</output>
    </>
  );
}

const value = () => screen.getByTestId("value").textContent;
const box = () => screen.getByRole("combobox", { name: "Hosts" });

it("odaklanınca listeyi açar, tıklayınca seçer ve etiket çizer", () => {
  render(<Harness />);
  expect(screen.queryByRole("listbox")).toBeNull();
  fireEvent.focus(box());
  fireEvent.click(screen.getByRole("option", { name: /web-01/ }));
  fireEvent.click(screen.getByRole("option", { name: /db-01/ }));
  expect(value()).toBe("web-01,db-01");
  expect(screen.getByRole("button", { name: "remove web-01" })).toBeTruthy();
  expect(screen.getByRole("option", { name: /web-01/ }).getAttribute("aria-selected")).toBe("true");

  fireEvent.click(screen.getByRole("button", { name: "remove web-01" }));
  expect(value()).toBe("db-01");
  fireEvent.click(screen.getByRole("button", { name: "clear Hosts" }));
  expect(value()).toBe("");
});

/*
 * ⚠️ SÜZGEÇ GÖRÜNENİ DARALTIR, SEÇİMİ DÜŞÜRMEZ; "tümünü seç" süzülmüş
 * listeye uygulanır — "web" yazıp tümünü seçmek web sunucularını seçer,
 * envanterin tamamını değil. Adres de aranıyor.
 */
it("arama süzer, tümünü seç süzülmüşe uygulanır, seçim korunur", () => {
  render(<Harness initial={["db-01"]} />);
  fireEvent.change(box(), { target: { value: "web" } });
  expect(screen.queryByRole("option", { name: /db-01/ })).toBeNull();
  expect(screen.getAllByRole("option")).toHaveLength(2);
  expect(screen.getByRole("button", { name: "remove db-01" })).toBeTruthy();

  fireEvent.click(screen.getByRole("button", { name: /select all 2 matching/i }));
  expect(value()).toBe("db-01,web-01,web-02");
  fireEvent.click(screen.getByRole("button", { name: /select all 2 matching/i }));
  expect(value()).toBe("db-01");

  fireEvent.change(box(), { target: { value: "10.0.2" } });
  expect(screen.getByRole("option", { name: /db-01/ })).toBeTruthy();
  fireEvent.change(box(), { target: { value: "zzz" } });
  expect(screen.getByText(/Nothing matches/)).toBeTruthy();
});

/*
 * ⚠️ DEVRE DIŞI SEÇENEK SEÇİLEMEZ — tıklayarak da, tümünü seçle de.
 * Korunan sistem grupları buradan geçmiyor ama bileşen yine de bunu
 * garanti etmeli: bir gün listelenirlerse seçilemesinler.
 */
it("devre dışı seçenek hiçbir yoldan seçilmez; öbekler adlı", () => {
  render(<Harness />);
  fireEvent.focus(box());
  const system = screen.getByRole("group", { name: "System" });
  const root = within(system).getByRole("option", { name: /root/ });
  expect(root.getAttribute("aria-disabled")).toBe("true");
  fireEvent.click(root);
  expect(value()).toBe("");
  fireEvent.click(screen.getByRole("button", { name: /^select all$/i }));
  expect(value()).toBe("web-01,web-02,db-01,dba");
  expect(screen.getByRole("group", { name: "Groups" })).toBeTruthy();
});

/*
 * Klavye: ok aşağı ile gez, Enter ile seç, Backspace boş kutuda son
 * etiketi kaldırır, Escape kapatır.
 */
it("klavyeyle gezilir ve seçilir", () => {
  render(<Harness />);
  const input = box();
  fireEvent.keyDown(input, { key: "ArrowDown" }); // açar
  fireEvent.keyDown(input, { key: "ArrowDown" }); // web-02
  fireEvent.keyDown(input, { key: "Enter" });
  expect(value()).toBe("web-02");
  expect(input.getAttribute("aria-activedescendant")).toMatch(/-opt-1$/);
  fireEvent.keyDown(input, { key: "Backspace" });
  expect(value()).toBe("");
  fireEvent.keyDown(input, { key: "Escape" });
  expect(screen.queryByRole("listbox")).toBeNull();
});

it("dışarı basınca kapanır, kutuya basınca açılır", () => {
  render(<Harness />);
  fireEvent.focus(box());
  expect(screen.getByRole("listbox")).toBeTruthy();
  fireEvent.mouseDown(document.body);
  expect(screen.queryByRole("listbox")).toBeNull();
  fireEvent.mouseDown(screen.getByRole("combobox", { name: "Hosts" }).parentElement!.parentElement!);
  expect(screen.getByRole("listbox")).toBeTruthy();
});
