import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import QRCode from "./QRCode";

describe("QR çizimi", () => {
  const tiny = ["101", "010", "101"];

  it("sessiz bölgeyi bırakıyor", () => {
    render(<QRCode rows={tiny} label="kurulum kodu" />);
    const svg = screen.getByRole("img", { name: "kurulum kodu" });
    /*
     * ⚠️ 3 modüllük kod + her yandan 4 modül = 11. Kenarsız bir kod,
     * arkasındaki sayfa desenini kodun parçası sanan tarayıcılarda
     * okunmaz ve kullanıcı bunu ancak telefonuyla deneyince anlar.
     */
    expect(svg).toHaveAttribute("viewBox", "0 0 11 11");
  });

  it("koyu modülleri çiziyor, açıkları çizmiyor", () => {
    const { container } = render(<QRCode rows={tiny} label="k" />);
    const path = container.querySelector("path")!;
    const d = path.getAttribute("d")!;
    // tiny'de 5 koyu modül var.
    expect(d.match(/M/g)).toHaveLength(5);
    // Sol üst koyu modül, sessiz bölge kadar kaymış olmalı.
    expect(d.startsWith("M4 4h1v1h-1z")).toBe(true);
  });

  /*
   * ⚠️ TEMA BELİRTECİ KULLANILMAMALI.
   *
   * Koyu temada belirteçler kodu tersine çevirir (açık modüller koyu
   * zeminde) ve tarayıcıların çoğu tersine dönmüş QR'ı okumaz. Bu,
   * kullanıcının ancak telefonunu tutup denerken fark edeceği bir
   * arıza — ve o noktada hesabına giremiyor olur.
   */
  it("renkleri temaya bırakmıyor: her zaman koyu üstüne açık", () => {
    const { container } = render(<QRCode rows={tiny} label="k" />);
    const bg = container.querySelector("rect")!;
    const path = container.querySelector("path")!;
    expect(bg.getAttribute("fill")).toBe("#ffffff");
    expect(path.getAttribute("fill")).toBe("#000000");
    for (const el of [bg, path]) {
      expect(el.getAttribute("fill")).not.toContain("var(");
    }
  });

  it("boş matriste hiçbir şey çizmiyor", () => {
    const { container } = render(<QRCode rows={[]} label="k" />);
    expect(container.querySelector("svg")).toBeNull();
  });
});
