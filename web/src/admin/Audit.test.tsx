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

/*
 * ⚠️ BU BÖLÜMÜN TAMAMI TEK BİR RİSKİN ETRAFINDA: HAK EDİLMEMİŞ ONAY.
 *
 * "İlk bakışta hızlı özet" istemek makul, ama bu üründe özetin özel bir
 * tuzağı var: bakılması gereken satırı sakinleştirebilir. Sütun bu
 * yüzden TEK YÖNLÜ — en fazla dikkat çeker, asla "tamam" demez.
 */
describe("kanıt sütunu", () => {
  const show = (rows: Session[]) => {
    vi.spyOn(api, "sessions").mockResolvedValue(rows);
    return render(<Sessions theme="dark" />);
  };

  it("postern'in kendi kaybını işaretliyor", async () => {
    show([session({ lost: 3 })]);

    await waitFor(() => expect(screen.getByText("3 events lost")).toBeTruthy());
    expect(screen.getByText("3 events lost").className).toContain("badge-warn");
  });

  // "1 events lost" bir sayı değil, dikkatsizlik izlenimi verir.
  it("tek olayda tekil yazıyor", async () => {
    show([session({ lost: 1 })]);

    await waitFor(() => expect(screen.getByText("1 event lost")).toBeTruthy());
  });

  it("reddedilen istekleri sayıyor", async () => {
    show([session({ denied: 4, lost: 0 })]);

    await waitFor(() => expect(screen.getByText("4 refused")).toBeTruthy());

    /*
     * ⚠️ KIRMIZI DEĞİL. Bu panelde badge-danger ÇELİŞKİYE ayrılmış
     * (dosya tutuyor ama arşiv tutmuyor). Reddedilen bir istek kuralın
     * ÇALIŞTIĞI anlamına da geliyor; kırmızı çizmek onu arıza gibi
     * okuturdu ve gerçek çelişkinin rengini ucuzlatırdı.
     */
    expect(screen.getByText("4 refused").className).not.toContain("badge-danger");
  });

  /*
   * ⚠️ HÜCREDE EN FAZLA BİR ROZET. İkisini yan yana çizmek, satırı
   * okunur kılmak yerine kalabalıklaştırırdı; kayıp daha ağır bulgu
   * olduğu için önce o.
   */
  it("kayıp varken retleri öne almıyor", async () => {
    show([session({ lost: 2, denied: 7 })]);

    await waitFor(() => expect(screen.getByText("2 events lost")).toBeTruthy());
    expect(screen.queryByText("7 refused")).toBeNull();
  });

  /*
   * ⚠️ BU DOSYADAKİ EN ÖNEMLİ İDDİA.
   *
   * İşaretsiz satır BOŞ kalıyor — yeşil bir rozet, "verified" ya da
   * "clean" yazmıyor. Çünkü listeden hesaplanabilen tek şey iki sayı;
   * defterin İÇERİĞİNİN tutup tutmadığını ancak sunucu satırları
   * yeniden mühürleyerek söyler. Boş hücreye onay yüklemek, yapılmamış
   * bir kontrolü yapılmış saymak olurdu.
   *
   * Ve boşluğun ne demek OLMADIĞI yazılı olmak zorunda: sessizlik,
   * okuyanın kendi varsayımıyla dolar.
   */
  it("işaretsiz satıra onay vermiyor ve boşluğun ne demek olmadığını yazıyor", async () => {
    show([session({ lost: 0, denied: 0 })]);

    await waitFor(() => expect(screen.getByText("ayse")).toBeTruthy());

    expect(screen.queryByText(/verified|clean|ok\b/i)).toBeNull();
    expect(document.querySelector(".badge-ok")).toBeNull();

    // Etek, boş hücrenin bir hüküm OLMADIĞINI söylüyor.
    expect(screen.getByText(/It is not a verdict/i)).toBeTruthy();
  });

  /*
   * ⚠️ "AÇIK" İLE "AKIYOR" AYNI ŞEY DEĞİL — ve rozet ikisini
   * karıştırıyordu: yeşil "running", ended_at'in BOŞLUĞUNDAN
   * çiziliyordu. postern çöktüğünde aynı oturum Overview'de "sahipsiz",
   * burada yeşil görünüyordu; yeşil, olmayan bir sağlık iddiasıydı.
   */
  it("akmayan açık oturumu yeşil çizmiyor", async () => {
    show([session({ ended_at: null, running: false })]);

    await waitFor(() =>
      expect(screen.getByText("open, not streaming")).toBeTruthy(),
    );
    expect(document.querySelector(".badge-ok")).toBeNull();
  });

  /*
   * ⚠️ İDDİANIN İKİNCİ YARISI. Arama bulması yetmiyor: satırı AÇAN
   * denetçi de o alanları görmeli, yoksa "sadeleştirme" bilgi kaybı
   * olur. Sütunu kaldırıp başlığı eklemeyi tek işlem saymak, tam da
   * bu testin tuttuğu şey.
   */
  it("açılan oturumun başlığı kaldırılan alanları geri veriyor", async () => {
    vi.spyOn(api, "sessionDetail").mockResolvedValue({
      ...session({ os_user: "root", src_ip: "10.0.0.9" }),
      recording: { state: "none", size: 0 },
      files: [],
    });
    show([session({ os_user: "root", src_ip: "10.0.0.9" })]);

    await userEvent.click(
      await screen.findByRole("button", { name: /watch/i }),
    );

    await waitFor(() => expect(screen.getByText("root")).toBeTruthy());
    expect(screen.getByText("10.0.0.9")).toBeTruthy();
    // Kısaltılmamış kimlik: sunucu günlüğünde aratacak olan için.
    expect(screen.getByText("s1")).toBeTruthy();
  });

  // Karşı kanıt: gerçekten akan oturum yeşil kalıyor.
  it("akan oturumu yeşil çiziyor", async () => {
    show([session({ ended_at: null, running: true })]);

    await waitFor(() => expect(screen.getByText("running")).toBeTruthy());
    expect(screen.getByText("running").className).toContain("badge-ok");
  });

  /*
   * ⚠️ SÜTUNDAN ÇIKAN ALAN VERİDEN ÇIKMADI. "OS user" ve "Src" ilk
   * bakışın sorusuna ait değil, ama onları arayan denetçi yine
   * bulabilmeli — yoksa sadeleştirme, bilgi kaybı olur.
   */
  it("kaldırılan sütunlar hâlâ aranabiliyor", async () => {
    show([
      session({ id: "s1", user: "ayse", src_ip: "10.0.0.9" }),
      session({ id: "s2", user: "veli", src_ip: "10.0.0.7" }),
    ]);

    await waitFor(() => expect(screen.getByText("veli")).toBeTruthy());

    // Sütun yok…
    expect(screen.queryByRole("columnheader", { name: /Src/i })).toBeNull();

    // …ama arama buluyor.
    await userEvent.type(
      screen.getByLabelText(/search sessions/i),
      "10.0.0.7",
    );
    await waitFor(() => expect(screen.queryByText("ayse")).toBeNull());
    expect(screen.getByText("veli")).toBeTruthy();
  });
});
