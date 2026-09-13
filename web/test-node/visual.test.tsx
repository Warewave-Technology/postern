import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";
import SecurityKeys from "../src/SecurityKeys";
import { api } from "../src/api";

/*
 * GÖRSEL KONTROL — birim testlerinin ölçmediği şey.
 *
 * ⚠️ NEDEN VAR: bu panelde üst üste kozmetik hata yapıldı ve hepsinin
 * ortak sebebi aynıydı — ekranı hiç görmeden yazmak. Birim testleri
 * yapıyı ölçüyor ("düğme var mı", "metin geçiyor mu") ve yerleşimi
 * ÖLÇMÜYOR: var olmayan bir CSS sınıfı, yanlış başlık seviyesi ya da
 * yan yana düşen bir etiket–düğme çifti testleri hiç bozmuyor.
 *
 * Bu dosya bileşenin ÜRETTİĞİ HTML'i alıp GERÇEK stil dosyasıyla
 * birleştiriyor ve diske yazıyor. Çıktı bir tarayıcıda açılıp
 * bakılabiliyor; yani "baktım" demek ölçülebilir bir adım oluyor.
 *
 * ⚠️ BU BİR TEST DEĞİL, BİR ARAÇ. Hiçbir şey iddia etmiyor —
 * yalnızca bakılabilir bir çıktı bırakıyor. Sınıfın var olup
 * olmadığını denetleyen kontrol ayrı (classes.test.tsx).
 */
describe("görsel kontrol çıktısı", () => {
  it("kartı gerçek stille birlikte diske yazıyor", async () => {
    vi.spyOn(api, "webauthnList").mockResolvedValue({
      credentials: [
        {
          id: "k1",
          name: "iş dizüstü",
          created_at: "2026-09-01T10:00:00Z",
          last_used_at: "2026-09-12T08:30:00Z",
        },
        { id: "k2", name: "yedek anahtar", created_at: "2026-09-05T10:00:00Z" },
      ],
      only: false,
    });
    (window as any).PublicKeyCredential = function () {};
    Object.defineProperty(navigator, "credentials", {
      configurable: true,
      value: { create: vi.fn(), get: vi.fn() },
    });

    const { container, findByText } = render(<SecurityKeys />);
    await findByText(/iş dizüstü/);

    const css = fs.readFileSync(path.resolve(process.cwd(), "src/styles.css"), "utf8");
    const out = path.resolve(process.cwd(), ".visual");
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(
      path.join(out, "security-keys.html"),
      `<style>${css}</style>
<body class="app" style="padding:2rem;max-width:64rem">
${container.innerHTML}
</body>`,
    );

    expect(container.innerHTML).toContain("card-head");
  });
});
