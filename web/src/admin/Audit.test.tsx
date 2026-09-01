import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Sessions } from "./Audit";
import { api, type Session } from "../api";

const session = (over: Partial<Session> = {}): Session => ({
  id: "s1",
  user: "ayse",
  target: "web-01",
  os_user: "ayse",
  src_ip: "10.0.0.9",
  started_at: "2026-08-31T10:00:00Z",
  ended_at: "2026-08-31T10:05:00Z",
  ...over,
});

beforeEach(() => vi.restoreAllMocks());

/*
 * ⚠️ "KAYIT TUTULMADI" İLE "DOSYA KAYIP" AYRI ŞEYLER.
 *
 * Düğme koşulsuz oynatıcıyı açıyordu ve kaydı olmayan oturumda oynatıcı
 * boş açılıp hata veriyordu: denetçi ikisini de bozuk bir oynatıcı
 * sanıyordu. Biri politikanın sonucu, öbürü KAYBOLMUŞ KANIT — ve
 * ikincisi araştırılması gereken bir şey.
 *
 * Sunucu bu ayrımı ilk günden veriyordu; onu soran yoktu.
 */
describe("kayıt izleme", () => {
  const show = () => {
    vi.spyOn(api, "sessions").mockResolvedValue([session()]);
    return render(<Sessions theme="dark" />);
  };

  it("kayıt hiç tutulmadıysa oynatıcıyı açmıyor, sebebini söylüyor", async () => {
    vi.spyOn(api, "sessionDetail").mockResolvedValue({
      ...session(),
      recording: { state: "none", size: 0 },
    });
    show();

    await userEvent.click(
      await screen.findByRole("button", { name: /watch/i }),
    );
    await waitFor(() =>
      expect(screen.getByText(/no recording was kept/i)).toBeTruthy(),
    );
  });

  /*
   * ⚠️ KAYIP DOSYA AYRI BİR CÜMLE HAK EDİYOR — ve nereye bakılacağını
   * söylemeli. Kaybolan kanıt, "kayıt tutulmadı"dan çok farklı bir şey.
   */
  it("dosya kayıpsa nereye bakılacağını söylüyor", async () => {
    vi.spyOn(api, "sessionDetail").mockResolvedValue({
      ...session(),
      recording: { state: "missing", size: 0 },
    });
    show();

    await userEvent.click(
      await screen.findByRole("button", { name: /watch/i }),
    );
    await waitFor(() =>
      expect(screen.getByText(/no longer on disk/i)).toBeTruthy(),
    );
    expect(screen.getByText(/admin log says which/i)).toBeTruthy();
  });

  // Yarım kayıt YİNE DE oynatılıyor: elde olanı göstermemek, hiç
  // olmamasından iyi değil.
  it("yarım kaydı uyarıyla birlikte oynatıyor", async () => {
    vi.spyOn(api, "sessionDetail").mockResolvedValue({
      ...session(),
      recording: { state: "partial", size: 10 },
    });
    show();

    await userEvent.click(
      await screen.findByRole("button", { name: /watch/i }),
    );
    await waitFor(() => expect(screen.getByText(/incomplete/i)).toBeTruthy());
  });
});
