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

      files: [],
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

      files: [],
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

      files: [],
    });
    show();

    await userEvent.click(
      await screen.findByRole("button", { name: /watch/i }),
    );
    await waitFor(() => expect(screen.getByText(/incomplete/i)).toBeTruthy());
  });
});

/*
 * ⚠️ SFTP OTURUMUNUN TERMİNAL KAYDI BOŞTUR.
 *
 * Protokol ham ikili aktığı için kayda hiç yazılmıyor — kanalın yıllarca
 * kapalı kalma sebebi zaten şişen ve oynatılamayan kayıtlardı
 * (proxy/sftp.go). Ama bu, denetçinin boş bir oynatıcıya bakıp "bu
 * oturumda bir şey olmamış" demesi anlamına GELMEMELİ: dosya olayları
 * elde kalan tek kanıt ve görünür olmak zorunda.
 */
describe("SFTP dosya olayları", () => {
  const openSession = async () => {
    vi.spyOn(api, "sessions").mockResolvedValue([session()]);
    render(<Sessions theme="dark" />);
    await userEvent.click(
      await screen.findByRole("button", { name: /watch/i }),
    );
  };

  it("kaydı olmayan oturumda bile dosya olaylarını gösteriyor", async () => {
    vi.spyOn(api, "sessionDetail").mockResolvedValue({
      ...session(),
      recording: { state: "none", size: 0 },
      files: [
        {
          id: "f1",
          at: "2026-08-31T10:01:00Z",
          op: "transfer",
          path: "/etc/shadow",
          flags: "read",
          read: 4196,
          wrote: 0,
          ok: true,
        },
      ],
    });
    await openSession();

    expect(await screen.findByText("/etc/shadow")).toBeInTheDocument();
    // Bayt sayısı okunur olmalı: denetçi "4,1 KB" ile karşılaştırma yapar.
    expect(screen.getByText("4.1 KB")).toBeInTheDocument();
    // ...ve "hiç kayıt yok" cümlesi, elde kanıt VARKEN kurulmamalı.
    expect(
      screen.getByText(/file events below show what it did/i),
    ).toBeInTheDocument();
  });

  it("reddedilen işlemi gizlemiyor, reddedildi diye gösteriyor", async () => {
    vi.spyOn(api, "sessionDetail").mockResolvedValue({
      ...session(),
      recording: { state: "complete", size: 120 },
      files: [
        {
          id: "f1",
          at: "2026-08-31T10:01:00Z",
          op: "remove",
          path: "/etc/passwd",
          read: 0,
          wrote: 0,
          ok: false,
          detail: "permission denied",
        },
      ],
    });
    await openSession();

    expect(await screen.findByText("/etc/passwd")).toBeInTheDocument();
    // Başarısız satır SİLİNMEZ: engelin çalıştığının kanıtı.
    expect(screen.getByText(/denied — permission denied/i)).toBeInTheDocument();
  });

  /*
   * ⚠️ "DOKUNULMADI" İLE "BAKAMADIK" AYNI ŞEY DEĞİL.
   *
   * Olay listesi okunamadığında boş tablo göstermek, denetçiye
   * "bu oturumda dosyaya dokunulmadı" dedirtirdi.
   */
  it("olaylar okunamadıysa bunu boş liste gibi göstermiyor", async () => {
    vi.spyOn(api, "sessionDetail").mockResolvedValue({
      ...session(),
      recording: { state: "complete", size: 120 },
      files: [],
      files_error: true,
    });
    await openSession();

    expect(
      await screen.findByText(/not a statement that no files were touched/i),
    ).toBeInTheDocument();
  });

  /*
   * ⚠️ KISA BİR LİSTE, TAM BİR LİSTEDEN AYIRT EDİLEMEZ.
   *
   * Kaydın mühür satırı oturumun kaç dosya olayı ürettiğini söylüyor
   * (proxy/sftpcast.go). Defterden düşen ya da sonradan silinen bir
   * satır, bu ekranda yalnızca daha kısa bir tablo olarak görünüyordu
   * ve onu yalanlayacak hiçbir cümle yoktu.
   */
  it("defter eksikse listeyi eksiksizmiş gibi göstermiyor", async () => {
    vi.spyOn(api, "sessionDetail").mockResolvedValue({
      ...session(),
      recording: { state: "complete", size: 120 },
      files: [
        {
          id: "f1",
          at: "2026-08-31T10:01:00Z",
          op: "open",
          path: "/etc/shadow",
          read: 0,
          wrote: 0,
          ok: true,
          in_recording: true,
        },
      ],
      journal: {
        state: "missing",
        events: 3,
        rows: 1,
        lost: 0,
        detail: "the journal has no row for 2 events the recording's seal counts",
        digest_checked: false,
      },
    });
    await openSession();

    expect(await screen.findByText(/NOT the whole story/i)).toBeInTheDocument();
    // Gerekçe SUNUCUDAN geliyor: aynı cümleyi `postern session verify`
    // de basıyor ve ikisi ayrışmamalı.
    expect(
      screen.getByText(/has no row for 2 events/i),
    ).toBeInTheDocument();
  });

  /*
   * ⚠️ EN TEHLİKELİ HÂL BOŞ TABLO. Bütün satırları silinmiş bir oturum
   * bu ekranda "hiçbir dosyaya dokunulmamış" gibi görünüyordu; uyarı
   * tablonun içinde olsaydı tam da o oturumda gizlenirdi.
   */
  it("bütün satırlar gitmişse boş ekran değil uyarı gösteriyor", async () => {
    vi.spyOn(api, "sessionDetail").mockResolvedValue({
      ...session(),
      recording: { state: "complete", size: 120 },
      files: [],
      journal: {
        state: "missing",
        events: 4,
        rows: 0,
        lost: 0,
        detail: "the journal has no row for 4 events the recording's seal counts",
        digest_checked: false,
      },
    });
    await openSession();

    expect(await screen.findByText(/NOT the whole story/i)).toBeInTheDocument();
  });

  /*
   * ⚠️ DEĞİŞTİRİLMİŞ SATIR, EKSİK SATIRDAN BAŞKA BİR CÜMLE.
   *
   * Burada liste TAM: satır sayısı doğru, satırlar yerinde. Değişen şey
   * satırların ne SÖYLEDİĞİ. "Hepsi burada değil" demek, denetçiyi
   * olmayan bir eksiği aramaya gönderirdi.
   */
  it("değiştirilmiş satırı eksik satırdan ayırıyor", async () => {
    vi.spyOn(api, "sessionDetail").mockResolvedValue({
      ...session(),
      recording: { state: "complete", size: 120 },
      files: [
        {
          id: "f1",
          at: "2026-08-31T10:01:00Z",
          op: "open",
          path: "/tmp/notlar",
          read: 0,
          wrote: 0,
          ok: true,
          in_recording: true,
        },
      ],
      journal: {
        state: "altered",
        events: 1,
        rows: 1,
        lost: 0,
        detail:
          "the journal has a row for each of the 1 event the seal counts, " +
          "but their digest does not match the recording",
        digest_checked: true,
      },
    });
    await openSession();

    expect(
      await screen.findByText(/do not say what the recording says/i),
    ).toBeInTheDocument();
    // ⚠️ EKSİK SATIR CÜMLESİ ÇIKMAMALI: burada eksik bir şey yok.
    expect(screen.queryByText(/NOT the whole story/i)).toBeNull();
  });

  /*
   * ⚠️ ÖLÇÜLMEMİŞ OTURUM ALARM ÜRETMEMELİ — yükseltmeden önce kapanmış
   * her oturum burada. Onları uyarıyla göstermek, ilk günden itibaren
   * geçmişin tamamını suçlamak olurdu.
   */
  it("ölçülmemiş oturumda uyarı çıkarmıyor", async () => {
    vi.spyOn(api, "sessionDetail").mockResolvedValue({
      ...session(),
      recording: { state: "complete", size: 120 },
      files: [],
      journal: {
        state: "unmeasured",
        events: 0,
        rows: 0,
        lost: 0,
        detail: "this session has no seal to compare the journal against",
        digest_checked: false,
      },
    });
    await openSession();

    await waitFor(() =>
      expect(screen.queryByText(/NOT the whole story/i)).toBeNull(),
    );
  });
});
