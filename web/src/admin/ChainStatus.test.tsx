import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ChainStatus from "./ChainStatus";
import { api, type VerifyResult } from "../api";

const result = (over: Partial<VerifyResult> = {}): VerifyResult => ({
  local: "verified",
  off_box: { state: "unchecked", detail: "archiving is not configured" },
  ...over,
});

beforeEach(() => {
  vi.restoreAllMocks();
});

/*
 * ⚠️ BU DOSYANIN EN ÖNEMLİ İDDİASI.
 *
 * Veritabanında bir zincir başı olması, dosyanın o başla TUTTUĞU anlamına
 * gelmiyor — bunu ancak sunucu dosyayı baştan sona okuyarak söyler. Panel
 * "baş kayıtlı" durumunu yeşil bir onay gibi çizerse, hiç doğrulanmamış
 * bir kaydı doğrulanmış gösterir. Göç 034'ün engellemek istediği şey tam
 * olarak bu ve o hâl, hiçbir şey göstermemekten kötüdür.
 */
describe("doğrulamadan önce", () => {
  it("zincir kayıtlıyken onay VERMİYOR, doğrulama teklif ediyor", () => {
    render(<ChainStatus sessionId="s1" chain="abc123" />);

    // Yeşil rozet YOK.
    expect(document.querySelector(".badge-ok")).toBeNull();
    expect(screen.queryByText(/verified/i)).toBeNull();

    // Ne bilindiği ve ne bilinmediği açıkça yazılı.
    expect(screen.getByText(/has not been checked/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Verify/i })).toBeTruthy();
  });

  /*
   * ⚠️ ZİNCİRİ OLMAYAN KAYIT BİR ALARM DEĞİL. Göç 034'ten önce kapanmış
   * her oturum böyle görünür; ilk yükseltmede bu geçmişin TAMAMI demek.
   * Kırmızı bir rozet, kimsenin yapmadığı bir şey için alarm üretirdi.
   */
  it("zincirsiz oturumda düğme yok ve alarm yok", () => {
    render(<ChainStatus sessionId="s1" />);

    expect(screen.queryByRole("button", { name: /Verify/i })).toBeNull();
    expect(document.querySelector(".badge-danger")).toBeNull();
    expect(screen.getByText(/before chains existed/i)).toBeTruthy();
  });
});

describe("doğrulamadan sonra", () => {
  it("yalnızca gerçekten doğrulanınca yeşil çiziyor", async () => {
    vi.spyOn(api, "verifyRecording").mockResolvedValue(
      result({ local: "verified" }),
    );
    render(<ChainStatus sessionId="s1" chain="abc" />);

    await userEvent.click(screen.getByRole("button", { name: /Verify/i }));

    await waitFor(() => expect(screen.getByText("verified")).toBeTruthy());
    expect(document.querySelector(".badge-ok")).toBeTruthy();
  });

  it("değişmiş kaydı kırmızı ve sebebiyle gösteriyor", async () => {
    vi.spyOn(api, "verifyRecording").mockResolvedValue(
      result({ local: "changed", detail: "it is short by 2 lines" }),
    );
    render(<ChainStatus sessionId="s1" chain="abc" />);

    await userEvent.click(screen.getByRole("button", { name: /Verify/i }));

    await waitFor(() => expect(screen.getByText("changed")).toBeTruthy());
    expect(screen.getByText(/short by 2 lines/)).toBeTruthy();
    expect(document.querySelector(".badge-danger")).toBeTruthy();
  });

  /*
   * ⚠️ İKİ EKSEN AYRI SATIRDA. "Yerel tuttu ama arşiv çelişiyor" en güçlü
   * kurcalama işareti; tek bir rozette birleştirmek onu yeşilin arkasına
   * saklardı.
   */
  it("arşiv çelişirken yerel yeşil olsa bile çelişkiyi gösteriyor", async () => {
    vi.spyOn(api, "verifyRecording").mockResolvedValue(
      result({
        local: "verified",
        off_box: { state: "mismatch", chain: "baska-bas", object: "kova/x" },
      }),
    );
    render(<ChainStatus sessionId="s1" chain="abc" />);

    await userEvent.click(screen.getByRole("button", { name: /Verify/i }));

    await waitFor(() =>
      expect(screen.getByText("archive disagrees")).toBeTruthy(),
    );
    // Ve hangisine güvenileceğini söylüyor.
    expect(screen.getByText(/host as compromised/i)).toBeTruthy();
    expect(screen.getByText(/baska-bas/)).toBeTruthy();
  });

  /*
   * ⚠️ "BAKILMADI" HER ZAMAN YAZILIYOR. Sessizlik, bakılmadığını
   * bakılmış gibi okutur — ve zincirin değerini abartan varsayım budur.
   */
  it("arşive bakılmadıysa bunu ve sebebini yazıyor", async () => {
    vi.spyOn(api, "verifyRecording").mockResolvedValue(
      result({
        local: "verified",
        off_box: {
          state: "unchecked",
          detail: "this recording has not been archived yet",
        },
      }),
    );
    render(<ChainStatus sessionId="s1" chain="abc" />);

    await userEvent.click(screen.getByRole("button", { name: /Verify/i }));

    await waitFor(() =>
      expect(screen.getByText("archive not checked")).toBeTruthy(),
    );
    expect(screen.getByText(/has not been archived yet/)).toBeTruthy();
  });

  /*
   * ⚠️ YEREL "GEÇTİ" TEK BAŞINA DAR BİR İDDİA. Arşiv onaylamadıysa
   * yeşil rozetin yanında sınırın yazılı olması gerekiyor, yoksa fazla
   * okunur: bu makinede root olan biri dosyayı ve başı BİRLİKTE yeniden
   * yazabilir.
   */
  it("arşiv onaylamadan yeşil çizerken sınırı yazıyor", async () => {
    vi.spyOn(api, "verifyRecording").mockResolvedValue(
      result({
        local: "verified",
        off_box: { state: "unchecked", detail: "kapalı" },
      }),
    );
    render(<ChainStatus sessionId="s1" chain="abc" />);

    await userEvent.click(screen.getByRole("button", { name: /Verify/i }));

    await waitFor(() => expect(screen.getByText("verified")).toBeTruthy());
    expect(
      screen.getByText(/rewrite the file and the stored chain together/i),
    ).toBeTruthy();
  });

  // Arşiv ONAYLADIYSA o uyarı GEREKSİZ: kapatan şey zaten devrede.
  it("arşiv onayladığında sınır uyarısını tekrarlamıyor", async () => {
    vi.spyOn(api, "verifyRecording").mockResolvedValue(
      result({
        local: "verified",
        off_box: { state: "match", object: "kova/x" },
      }),
    );
    render(<ChainStatus sessionId="s1" chain="abc" />);

    await userEvent.click(screen.getByRole("button", { name: /Verify/i }));

    await waitFor(() =>
      expect(screen.getByText("archive confirms")).toBeTruthy(),
    );
    expect(
      screen.queryByText(/rewrite the file and the stored chain together/i),
    ).toBeNull();
  });

  /*
   * ⚠️ DOĞRULAMA SONUCU "MÜHÜRSÜZ" ÇIKARSA DA ALARM DEĞİL.
   *
   * İlk sınamam yalnızca doğrulama ÖNCESİ görünümü kontrol ediyordu ve
   * mutasyon (rozeti kırmızıya çevirmek) hayatta kaldı — çünkü rozet
   * ancak doğrulamadan SONRA çiziliyor. Göç 034 öncesi kapanmış her
   * oturum bu yolu izler; kırmızı bir rozet geçmişin tamamını suçlardı.
   */
  it("mühürsüz sonuç kırmızı çizilmiyor", async () => {
    vi.spyOn(api, "verifyRecording").mockResolvedValue(
      result({ local: "unsealed", detail: "no chain was stored" }),
    );
    render(<ChainStatus sessionId="s1" chain="abc" />);

    await userEvent.click(screen.getByRole("button", { name: /Verify/i }));

    await waitFor(() => expect(screen.getByText("not sealed")).toBeTruthy());
    const badge = screen.getByText("not sealed");
    expect(badge.className).not.toContain("badge-danger");
    expect(badge.className).toContain("badge-info");
  });

  it("sunucunun retini olduğu gibi gösteriyor", async () => {
    vi.spyOn(api, "verifyRecording").mockRejectedValue(
      new Error("another recording is being verified right now"),
    );
    render(<ChainStatus sessionId="s1" chain="abc" />);

    await userEvent.click(screen.getByRole("button", { name: /Verify/i }));

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/being verified/),
    );
  });
});

/*
 * Durum adı ROZETTE yazılı: rengi ayırt edemeyen biri de sonucu
 * okuyabilmeli. Depo kalıbı bu (PathRules'daki denied/read-only rozetleri).
 */
describe("erişilebilirlik", () => {
  it("her durum metinle de ayırt ediliyor", async () => {
    for (const [local, label] of [
      ["verified", "verified"],
      ["changed", "changed"],
      ["no_local_copy", "not on this host"],
      ["in_progress", "in progress"],
    ] as const) {
      vi.spyOn(api, "verifyRecording").mockResolvedValue(result({ local }));
      const { unmount } = render(<ChainStatus sessionId="s1" chain="abc" />);

      await userEvent.click(screen.getByRole("button", { name: /Verify/i }));
      await waitFor(() => expect(screen.getByText(label)).toBeTruthy());

      unmount();
    }
  });
});
