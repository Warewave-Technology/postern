import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import FileHistory from "./FileHistory";
import { api, type FileTouch } from "../api";

const touch = (over: Partial<FileTouch> = {}): FileTouch => ({
  id: "f1",
  session_id: "0193aa11-2b3c-4d5e-8f90-abcdef012345",
  at: "2026-08-31T10:00:00Z",
  op: "transfer",
  path: "/etc/shadow",
  read: 4196,
  wrote: 0,
  ok: true,
  user: "ayse",
  target: "web-01",
  // ⚠️ user ile AYNI DEĞİL ve bilerek: oturumun açıldığı hesaba policy
  // karar veriyor. İkisini aynı yazan bir fikstür, iki sütunun
  // karıştığını göremezdi.
  os_user: "deploy",
  src_ip: "10.0.0.9",
  ...over,
});

const search = async (path = "/etc/shadow") => {
  render(<FileHistory />);
  await userEvent.type(screen.getByLabelText(/full path/i), path);
  await userEvent.click(screen.getByRole("button", { name: /search/i }));
};

beforeEach(() => vi.restoreAllMocks());

/*
 * ⚠️ EKRANIN EN ÖNEMLİ CÜMLESİ BU.
 *
 * Tablo YALNIZCA SFTP olaylarını biliyor. Kabukta `cat /etc/shadow`
 * yazan biri buraya hiçbir satır bırakmaz — o iz terminal kaydında
 * durur. Uyarı olmasa, boş bir sonuç "kimse almamış" diye okunurdu ve
 * bu, ekranın verebileceği en pahalı yanlış cevap: denetçinin en çok
 * güvendiği anda gelir.
 */
it("aramadan önce bile kapsamın SFTP ile sınırlı olduğunu söylüyor", () => {
  render(<FileHistory />);
  const warn = screen.getByText(/sftp file events only/i);
  expect(warn).toBeTruthy();
  expect(warn.textContent).toMatch(/not that\s+nobody read the file/i);
});

/*
 * ⚠️ "HENÜZ ARANMADI" İLE "BULUNAMADI" AYRI ŞEYLER.
 *
 * Açılışta boş sonuç metni gösteren bir ekran, sorulmamış bir soruyu
 * cevaplanmış gibi okutur.
 */
it("açılışta bir şey bulunamadığını söylemiyor", () => {
  render(<FileHistory />);
  expect(screen.queryByText(/nothing found/i)).toBeNull();
});

describe("sonuçlar", () => {
  it("dosyaya kimin dokunduğunu isimle gösteriyor", async () => {
    vi.spyOn(api, "fileHistory").mockResolvedValue({
      path: "/etc/shadow",
      events: [touch()],
      limit: 200,
      truncated: false,
    });
    await search();

    await waitFor(() => expect(screen.getByText("ayse")).toBeTruthy());
    expect(screen.getByText("web-01")).toBeTruthy();
    expect(screen.getByText("10.0.0.9")).toBeTruthy();
    // Kişi ile oturumun açıldığı hesap AYRI sütunlar: denetçinin
    // sorduğu "kim", policy'nin verdiği hesap değil.
    expect(screen.getByText("deploy")).toBeTruthy();
  });

  /*
   * ⚠️ BOŞ SONUÇ, "KİMSE ALMAMIŞ" DEMEK DEĞİL.
   *
   * Metin bunu açıkça söylemeli; söylemezse ekranın kendisi yanlış bir
   * sonuca kefil olur.
   */
  it("boş sonucu 'dokunulmadı' diye sunmuyor", async () => {
    vi.spyOn(api, "fileHistory").mockResolvedValue({
      path: "/etc/shadow",
      events: [],
      limit: 200,
      truncated: false,
    });
    await search();

    await waitFor(() => expect(screen.getByText(/nothing found/i)).toBeTruthy());
    expect(
      screen.getByText(/not the same\s+as saying the file was never read/i),
    ).toBeTruthy();
  });

  /*
   * ⚠️ DOSYA ORAYA BİR RENAME İLE GELMİŞ OLABİLİR.
   *
   * O satırda aranan yol `path`te değil `new_path`te durur ve satırın
   * `path`i bambaşka bir yol gösterir. İşaretlenmeseydi, denetçi
   * aradığı dosyayı hiç görünmeyen bir satır sanırdı — sızdırmanın en
   * ucuz biçimi görünmez olurdu.
   */
  it("dosyanın oraya rename ile geldiğini işaretliyor", async () => {
    vi.spyOn(api, "fileHistory").mockResolvedValue({
      path: "/tmp/exfil",
      events: [
        touch({ op: "rename", path: "/etc/shadow", new_path: "/tmp/exfil" }),
      ],
      limit: 200,
      truncated: false,
    });
    await search("/tmp/exfil");

    await waitFor(() => expect(screen.getByText(/moved here/i)).toBeTruthy());
    expect(screen.getByText("/etc/shadow")).toBeTruthy();
  });

  /*
   * ⚠️ KESİLDİYSE SÖYLE. Sessizce ilk N'i göstermek, denetçinin "olan
   * biten bu" sanması demek — ve burada o yanlış anlama, görülmemiş bir
   * transferin hiç olmamış sayılmasıyla biter.
   */
  it("liste sunucuda kesildiyse bunu yazıyor", async () => {
    vi.spyOn(api, "fileHistory").mockResolvedValue({
      path: "/etc/shadow",
      events: [touch()],
      limit: 200,
      truncated: true,
    });
    await search();

    await waitFor(() =>
      expect(screen.getByText(/may not be the whole history/i)).toBeTruthy(),
    );
  });

  /*
   * ⚠️ ARAMA BAŞARISIZSA BOŞ TABLO ÇİZİLMİYOR. "Bakamadık"ı
   * "dokunulmadı" gibi göstermek, bu ekranın tam olarak kaçındığı şey.
   */
  it("arama başarısızsa boş sonuç değil hata gösteriyor", async () => {
    vi.spyOn(api, "fileHistory").mockRejectedValue(new Error("database is down"));
    await search();

    await waitFor(() => expect(screen.getByText(/database is down/i)).toBeTruthy());
    expect(screen.queryByText(/nothing found/i)).toBeNull();
  });
});
