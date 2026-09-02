import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Pending from "./Pending";
import { api, type PendingUser } from "../api";

const row = (over: Partial<PendingUser> = {}): PendingUser => ({
  id: "p1",
  subject: "f74a3e90-373a-1041-92eb-dbd441920715",
  source: "dir",
  username: "ayse.yilmaz",
  email: "",
  seen_groups: ["hr"],
  state: "waiting",
  first_seen: "2026-08-30T10:00:00Z",
  last_seen: "2026-08-30T10:05:00Z",
  ...over,
});

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal(
    "confirm",
    vi.fn((_m?: string) => true),
  );
});

describe("onay kuyrugu", () => {
  /*
   * ⚠️ "ONAYLADIM AMA HİÇBİR YERE GİREMİYOR" ŞAŞKINLIĞI.
   *
   * Onay rol vermiyor; roller bir sonraki girişte canlı kaynaktan
   * çözülüyor. Ekran bunu söylemezse operatör onaydan sonra bir arıza
   * arar ve bulamaz.
   */
  it("onayin rol vermedigini soyler", async () => {
    vi.spyOn(api, "pending").mockResolvedValue([row()]);
    render(<Pending />);
    await waitFor(() =>
      expect(screen.getByText(/grants no roles/i)).toBeInTheDocument(),
    );
  });

  // ⚠️ Gerekçe zorunlu: sebepsiz bir red, altı ay sonra bakan kişinin
  // üzerine hareket edemeyeceği bir karardır.
  it("gerekce yazilmadan reddettirmez", async () => {
    vi.spyOn(api, "pending").mockResolvedValue([row()]);
    render(<Pending />);

    const decline = await screen.findByRole("button", {
      name: /decline ayse.yilmaz/i,
    });
    expect(decline).toBeDisabled();

    await userEvent.type(
      screen.getByLabelText(/Reason for declining/i),
      "ayrilan taseron",
    );
    expect(decline).toBeEnabled();
  });

  it("gerekceyi sunucuya gonderir", async () => {
    vi.spyOn(api, "pending").mockResolvedValue([row()]);
    const reject = vi
      .spyOn(api, "rejectPending")
      .mockResolvedValue({ ok: true });

    render(<Pending />);
    await userEvent.type(
      await screen.findByLabelText(/Reason for declining/i),
      "ayrilan taseron",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /decline ayse.yilmaz/i }),
    );
    await waitFor(() =>
      expect(reject).toHaveBeenCalledWith("p1", "ayrilan taseron"),
    );
  });

  /*
   * ⚠️ KARARIN ADA DEĞİL KİMLİĞE VERİLDİĞİ EKRANDA YAZMALI.
   *
   * Yazmazsa operatör, reddettiği kişinin adını değiştirip yeniden
   * başvurabileceğini sanır — ve o varsayımla gereksiz iş yapar.
   */
  it("reddin ad degisikligiyle asilamayacagini soyler", async () => {
    vi.spyOn(api, "pending").mockResolvedValue([
      row({ state: "rejected", reason: "ayrilan taseron", decided_by: "ops" }),
    ]);
    render(<Pending />);
    await waitFor(() =>
      expect(
        screen.getByText(/not even under a different name/i),
      ).toBeInTheDocument(),
    );
  });

  // Yapışkan red, geri alınabilir olmalı: aksi hâlde tek tık kalıcı
  // bir kilit koyar.
  it("reddi geri almanin yolunu gosterir", async () => {
    vi.spyOn(api, "pending").mockResolvedValue([
      row({ state: "rejected", reason: "yanlislikla", decided_by: "ops" }),
    ]);
    const forget = vi
      .spyOn(api, "forgetPending")
      .mockResolvedValue({ ok: true });

    render(<Pending />);
    await userEvent.click(
      await screen.findByRole("button", {
        name: /let ayse.yilmaz apply again/i,
      }),
    );
    await waitFor(() => expect(forget).toHaveBeenCalledWith("p1"));
  });

  // Kimlik gösterilmeli: operatör "bu gerçekten o kişi mi" sorusunu
  // ancak kaynakta aynı değeri görerek cevaplayabilir.
  it("kararin verildigi kimligi gosterir", async () => {
    vi.spyOn(api, "pending").mockResolvedValue([row()]);
    render(<Pending />);
    await waitFor(() =>
      expect(
        screen.getByText("f74a3e90-373a-1041-92eb-dbd441920715"),
      ).toBeInTheDocument(),
    );
  });

  it("bos kuyrukta nereye bakilacagini soyler", async () => {
    vi.spyOn(api, "pending").mockResolvedValue([]);
    render(<Pending />);
    await waitFor(() =>
      expect(screen.getByText(/Nobody is waiting/i)).toBeInTheDocument(),
    );
  });
});
