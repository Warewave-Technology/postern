import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import TargetPage, { targetFromPath, targetURL } from "./TargetPage";
import { api, type Me, type MyTargetDetail } from "./api";

const me: Me = {
  name: "yigit",
  os_user: "yigit",
  admin: false,
  targets: [],
  terminal_enabled: true,
  public_key_login: true,
  ssh_host: "bastion.io",
  ssh_port: 2222,
};

const detail = (over: Partial<MyTargetDetail> = {}): MyTargetDetail => ({
  name: "web-01",
  labels: {},
  sessions: [],
  ...over,
});

beforeEach(() => vi.restoreAllMocks());

describe("yol ayrıştırma", () => {
  it("hedefi çıkarıyor ve geri kuruyor", () => {
    expect(targetFromPath("/target/web-01")).toBe("web-01");
    expect(targetFromPath("/target/web-01/")).toBe("web-01");
    expect(targetURL("web 01")).toBe("/target/web%2001");
    expect(targetFromPath(targetURL("web 01"))).toBe("web 01");
  });

  it("hedef olmayan yollarda null", () => {
    for (const p of ["/", "/shell/web-01", "/target/", "/target/a/b"]) {
      expect(targetFromPath(p)).toBeNull();
    }
  });

  // Bozuk yüzde kaçışı: adres uydurulmuş demektir, sayfa açılmamalı.
  it("bozuk kaçışta null", () => {
    expect(targetFromPath("/target/%E0%A4%A")).toBeNull();
  });
});

describe("hedef sayfası", () => {
  it("bilinenleri ve kendi oturumlarını gösteriyor", async () => {
    vi.spyOn(api, "myTarget").mockResolvedValue(
      detail({
        labels: { env: "prod" },
        server_version: "OpenSSH_9.9",
        last_seen_at: "2026-09-01T19:00:00Z",
        sessions: [
          {
            id: "s1",
            started: "2026-09-01T18:00:00Z",
            ended: "2026-09-01T18:20:00Z",
            os_user: "deploy",
          },
        ],
      }),
    );
    render(<TargetPage me={me} name="web-01" />);

    expect(await screen.findByText("web-01")).toBeTruthy();
    expect(screen.getByText("OpenSSH_9.9")).toBeTruthy();
    expect(screen.getByText("env")).toBeTruthy();
    // Hedefte AÇILAN hesap: kullanıcı adıyla aynı olmak zorunda değil.
    expect(screen.getByText("deploy")).toBeTruthy();
  });

  /*
   * ⚠️ ADRES HİÇBİR YERDE GÖRÜNMEMELİ.
   *
   * Sunucu host/port göndermiyor ve bu bir bastion'ın varlık sebebi:
   * kullanıcı hedefe postern üzerinden bağlanıyor, ağ topolojisini
   * bilmesi gerekmiyor. Sayfanın kazara sızdırmadığını burada
   * sabitliyoruz.
   */
  it("hedefin adresini göstermiyor", async () => {
    vi.spyOn(api, "myTarget").mockResolvedValue(detail());
    const { container } = render(<TargetPage me={me} name="web-01" />);
    await screen.findByText("web-01");
    // Kopyalanan ssh komutu BASTION'ın adresini taşıyor, hedefinkini
    // değil — metinde 192.168 ya da :22 gibi bir hedef adresi olmamalı.
    expect(container.textContent).not.toMatch(/192\.168|10\.\d+\.\d+\.\d+/);
  });

  // Hiç bağlanmamış olmak boş bir tablo değil, bir cümle: boş tablo
  // "veri gelmedi" gibi de okunur.
  it("hiç oturum yoksa bunu söylüyor", async () => {
    vi.spyOn(api, "myTarget").mockResolvedValue(detail());
    render(<TargetPage me={me} name="web-01" />);
    expect(
      await screen.findByText(/have not connected to this host yet/i),
    ).toBeTruthy();
  });

  // Bitmemiş oturum "—" değil: hâlâ açık olduğunu söylemek gerekiyor.
  it("süren oturumu açık diye gösteriyor", async () => {
    vi.spyOn(api, "myTarget").mockResolvedValue(
      detail({
        sessions: [
          { id: "s1", started: "2026-09-01T18:00:00Z", os_user: "yigit" },
        ],
      }),
    );
    render(<TargetPage me={me} name="web-01" />);
    expect(await screen.findByText("still open")).toBeTruthy();
  });

  /*
   * ⚠️ ERİŞİLEMEYEN HEDEF, OLMAYAN HEDEFLE AYNI GÖRÜNMELİ.
   *
   * Sunucu ikisine de 404 dönüyor; ekran "sana kapalı" gibi bir şey
   * söylerse, adları tek tek deneyen biri envanteri çıkarabilir.
   */
  it("erişim yokken varlığı ele vermiyor", async () => {
    vi.spyOn(api, "myTarget").mockRejectedValue(new Error("no such target"));
    const { container } = render(<TargetPage me={me} name="gizli-01" />);
    expect(await screen.findByText(/no such target/i)).toBeTruthy();
    expect(container.textContent).not.toMatch(
      /permission|denied|not allowed|forbidden/i,
    );
  });

  // Kabuk menüsü burada da olmalı: sayfaya gelen kişi bağlanmak için
  // ana ekrana dönmek zorunda kalmasın.
  it("kabuk menüsünü taşıyor", async () => {
    vi.spyOn(api, "myTarget").mockResolvedValue(detail());
    render(<TargetPage me={me} name="web-01" />);
    expect(
      await screen.findByRole("button", { name: /shell options for web-01/i }),
    ).toBeTruthy();
  });
});

/*
 * ⚠️ "GEÇMİŞ OKUNAMADI", "HİÇ BAĞLANMADIN" DEĞİLDİR.
 *
 * Sunucu bu ayrımı zaten log'a yazıyordu ve yorumu kuralı doğru
 * söylüyordu — ama cevap gövdesi yine boş listeden kuruluyordu, yani
 * ekranda görünen tek şey olumlu cümleydi. Log'daki bir uyarıyı
 * kullanıcı görmüyor.
 */
describe("oturum geçmişi okunamadığında", () => {
  it("'hiç bağlanmadın' demiyor", async () => {
    vi.spyOn(api, "myTarget").mockResolvedValue(
      detail({ sessions_error: true }),
    );
    render(<TargetPage me={me} name="web-01" />);

    await waitFor(() =>
      expect(screen.getByText(/could not be read/i)).toBeTruthy(),
    );
    expect(
      screen.queryByText(/have not connected to this host yet/i),
    ).toBeNull();
  });

  // Gerçekten boşken olumlu cümle DURUYOR: düzeltme boş durumu
  // susturmak değil, iki durumu ayırmak.
  it("gerçekten boşken hâlâ 'hiç bağlanmadın' diyor", async () => {
    vi.spyOn(api, "myTarget").mockResolvedValue(detail());
    render(<TargetPage me={me} name="web-01" />);

    await waitFor(() =>
      expect(
        screen.getByText(/have not connected to this host yet/i),
      ).toBeTruthy(),
    );
  });

  /*
   * ⚠️ TARAMA PENCERESİ DOLDUYSA "HİÇ BAĞLANMADIN" DEME.
   *
   * Tarama tüm hedeflerin son N oturumuna bakıp süzüyor; bu hedefin
   * oturumları pencerenin dışında kalmış olabilir. Boş liste + partial
   * bayrağı "hiç bağlanmadın" değil "son N'de yok" demeli.
   */
  it("pencere dolduysa 'hiç bağlanmadın' demez", async () => {
    vi.spyOn(api, "myTarget").mockResolvedValue(
      detail({ sessions_partial: true, sessions_scanned: 200 }),
    );
    render(<TargetPage me={me} name="web-01" />);

    await waitFor(() =>
      expect(screen.getByText(/among your last 200/i)).toBeTruthy(),
    );
    expect(
      screen.queryByText(/have not connected to this host yet/i),
    ).toBeNull();
  });
});
