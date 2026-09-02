import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import TargetDetail from "./TargetDetail";
import { api, type TargetDetail as Detail } from "../api";

const detail = (over: Partial<Detail> = {}): Detail => ({
  name: "web-01",
  host: "10.0.0.4",
  port: 22,
  fingerprint: "SHA256:abc",
  labels: {},
  facts: {},
  granted_by: ["ops"],
  recent_sessions: [],
  ...over,
});

beforeEach(() => vi.restoreAllMocks());

/*
 * ⚠️ "BAKAMADIK", "HİÇ OLMAMIŞ" DEĞİLDİR.
 *
 * Sunucuda bu dalın `else`i hiç yoktu: sorgu çökünce `recent_sessions:
 * []` gidiyor, hata alanı olmuyor ve panel "No session has been opened
 * to this host." yazıyordu. Bir denetim ekranında olumlu cümle bir olgu
 * gibi okunur; bu, ekranın verebileceği en pahalı yanlış cevap.
 */
it("geçmiş okunamadıysa 'hiç oturum açılmamış' demiyor", async () => {
  vi.spyOn(api, "targetDetail").mockResolvedValue(detail({ recent_error: true }));
  render(<TargetDetail name="web-01" onBack={() => {}} />);

  await waitFor(() =>
    expect(screen.getByText(/could not be read/i)).toBeTruthy(),
  );
  expect(screen.queryByText(/No session has been opened/i)).toBeNull();
});

// Gerçekten boşken olumlu cümle duruyor: iki durumu ayırmak, birini
// susturmak değil.
it("gerçekten boşken hâlâ 'hiç oturum açılmamış' diyor", async () => {
  vi.spyOn(api, "targetDetail").mockResolvedValue(detail());
  render(<TargetDetail name="web-01" onBack={() => {}} />);

  await waitFor(() =>
    expect(screen.getByText(/No session has been opened/i)).toBeTruthy(),
  );
});
