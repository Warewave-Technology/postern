import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import FileHistory from "./FileHistory";
import { api, type FileHistory as FileHistoryT, type FileTouch } from "../api";

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

const result = (over: Partial<FileHistoryT> = {}): FileHistoryT => ({
  path: "/etc/shadow",
  under: false,
  user: "",
  target: "",
  events: [touch()],
  limit: 200,
  truncated: false,
  ...over,
});

const search = async (path = "/etc/shadow") => {
  render(<FileHistory />);
  await userEvent.type(screen.getByLabelText(/^path$/i), path);
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
 * ⚠️ KART İÇERİĞİ DOLGUSUZ KALMAMALI.
 *
 * `.card`ın kendi dolgusu yok (styles.css: yalnızca yüzey, kenarlık,
 * yuvarlatma); dolguyu `.card-head` ve `.card-body` veriyor.
 * Sarmalayıcı unutulduğunda ekran ÇALIŞMAYA DEVAM EDİYOR — yalnızca
 * etiket kartın üst kenarına yapışıyor ve alan kenardan kenara
 * uzuyor. Bu ekran tam da öyle çıktı ve hiçbir davranış testi
 * görmedi; kusuru panele bakan bir insan buldu.
 */
it("form alanları kartın dolgulu gövdesinde duruyor", () => {
  const { container } = render(<FileHistory />);
  const field = container.querySelector(".wfield");
  expect(field).toBeTruthy();
  expect(field!.closest(".card-body")).toBeTruthy();
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
      under: false,
      user: "",
      target: "",
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
      under: false,
      user: "",
      target: "",
      path: "/etc/shadow",
      events: [],
      limit: 200,
      truncated: false,
    });
    await search();

    await waitFor(() =>
      expect(screen.getByText(/nothing found/i)).toBeTruthy(),
    );
    expect(
      screen.getByText(/not the\s+same as saying the file was never read/i),
    ).toBeTruthy();
    // Boş sonuç kartı da dolgulu gövdede — aynı kusur oraya da düşebilir.
    expect(
      screen.getByText(/nothing found/i).closest(".card-body"),
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
      under: false,
      user: "",
      target: "",
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
      under: false,
      user: "",
      target: "",
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
    vi.spyOn(api, "fileHistory").mockRejectedValue(
      new Error("database is down"),
    );
    await search();

    await waitFor(() =>
      expect(screen.getByText(/database is down/i)).toBeTruthy(),
    );
    expect(screen.queryByText(/nothing found/i)).toBeNull();
  });
});

describe("ölçütler", () => {
  /*
   * ⚠️ YOL ZORUNLU DEĞİL: "ayse ne aldı" kendi başına bir soru.
   *
   * Soruşturmanın ikinci sorusu bu ve bir yol aramasının süzgeci
   * olarak sorulamaz — hangi dosyaya bakacağını bilmiyorsun, zaten onu
   * arıyorsun. Yolu zorunlu tutan bir form o soruyu sordurmaz.
   */
  it("yol boşken kişiyle arama yapılabiliyor", async () => {
    const spy = vi
      .spyOn(api, "fileHistory")
      .mockResolvedValue(result({ path: "", user: "ayse" }));

    render(<FileHistory />);
    await userEvent.type(screen.getByLabelText(/person/i), "ayse");
    await userEvent.click(screen.getByRole("button", { name: /search/i }));

    await waitFor(() => expect(spy).toHaveBeenCalled());
    expect(spy.mock.calls[0][0]).toMatchObject({ path: "", user: "ayse" });
  });

  /*
   * ⚠️ ÜÇÜ DE BOŞKEN ARAMA YOK.
   *
   * "Her şeyi göster", sorulmamış bir soruya dolu bir ekranla cevap
   * vermek olurdu — bu ekranın kaçındığı şeyin ta kendisi.
   */
  it("hiçbir ölçüt yokken arama düğmesi kapalı", () => {
    render(<FileHistory />);
    const btn = screen.getByRole("button", { name: /search/i });
    expect(btn.hasAttribute("disabled")).toBe(true);
  });

  // Ağaç kipi sunucuya gerçekten gidiyor: kutuyu işaretleyip aynı
  // sonucu almak, kipin hiç uygulanmadığını gizlerdi.
  it("ağaç kipi sunucuya iletiliyor", async () => {
    const spy = vi
      .spyOn(api, "fileHistory")
      .mockResolvedValue(result({ path: "/etc", under: true }));

    render(<FileHistory />);
    await userEvent.type(screen.getByLabelText(/^path$/i), "/etc");
    await userEvent.click(screen.getByLabelText(/everything under/i));
    await userEvent.click(screen.getByRole("button", { name: /search/i }));

    await waitFor(() => expect(spy).toHaveBeenCalled());
    expect(spy.mock.calls[0][0]).toMatchObject({ path: "/etc", under: true });
  });

  /*
   * ⚠️ NE ARANDIĞI EKRANDA YAZIYOR.
   *
   * Üç kutulu bir formda, kutuya yazıp aramayı unutan biri önceki
   * aramanın sonucunu yenisi sanabilir. Gösterilen ölçütler sunucunun
   * CEVABINDAN geliyor, formun o anki hâlinden değil.
   */
  it("çalıştırılan aramanın ölçütlerini yazıyor", async () => {
    vi.spyOn(api, "fileHistory").mockResolvedValue(
      result({ path: "/etc", under: true, user: "ayse", target: "web01" }),
    );
    render(<FileHistory />);
    await userEvent.type(screen.getByLabelText(/^path$/i), "/etc");
    await userEvent.click(screen.getByRole("button", { name: /search/i }));

    const foot = await screen.findByText(/Events matching/i);
    expect(foot.textContent).toMatch(/under\s*\/etc/);
    expect(foot.textContent).toMatch(/by\s*ayse/);
    expect(foot.textContent).toMatch(/on\s*web01/);
  });

  /*
   * ⚠️ AĞAÇ KİPİNDE DE "moved here".
   *
   * Aranan "/tmp" iken dosya "/tmp/exfil"e rename ile geldiyse eşleşme
   * yine new_path'te. Rozeti yalnızca tam eşleşmeye bağlamak,
   * sızdırmanın en ucuz biçimini tam da onu arayan kipte işaretsiz
   * bırakırdı.
   */
  it("ağaç kipinde de rename hedefini işaretliyor", async () => {
    vi.spyOn(api, "fileHistory").mockResolvedValue(
      result({
        path: "/tmp",
        under: true,
        events: [
          touch({ op: "rename", path: "/etc/shadow", new_path: "/tmp/exfil" }),
        ],
      }),
    );
    render(<FileHistory />);
    await userEvent.type(screen.getByLabelText(/^path$/i), "/tmp");
    await userEvent.click(screen.getByRole("button", { name: /search/i }));

    await waitFor(() => expect(screen.getByText(/moved here/i)).toBeTruthy());
  });
});

/*
 * ⚠️ YOL SİLİNDİĞİNDE AĞAÇ KİPİ DE GİTMELİ.
 *
 * Onay kutusu yol boşken devre dışı ama DURUMU KALICI. Yol yazıp
 * kutuyu işaretleyen, sonra yolu silip kişi yazan biri
 * "under=1&user=ayse" gönderiyordu; sunucu bunu doğru biçimde 400'le
 * reddediyor, ama panel gönderdiği anda geçersiz olduğunu bildiği bir
 * isteği yollamamalı — operatöre çıkışsız bir hata gösterirdi.
 */
it("yol silinince ağaç kipi de gönderilmiyor", async () => {
  const spy = vi
    .spyOn(api, "fileHistory")
    .mockResolvedValue(result({ path: "", user: "ayse" }));

  render(<FileHistory />);
  const pathBox = screen.getByLabelText(/^path$/i);
  await userEvent.type(pathBox, "/etc");
  await userEvent.click(screen.getByLabelText(/everything under/i));
  await userEvent.clear(pathBox);
  await userEvent.type(screen.getByLabelText(/person/i), "ayse");
  await userEvent.click(screen.getByRole("button", { name: /search/i }));

  await waitFor(() => expect(spy).toHaveBeenCalled());
  expect(spy.mock.calls[0][0]).toMatchObject({ path: "", under: false });
});

/*
 * ⚠️ KÖK ALTINDA DA "moved here" ÇİZİLİYOR.
 *
 * "/" + "/" iki eğik çizgi eder ve hiçbir yol öyle başlamaz: sunucu
 * kökün altındaki her şeyi döndürürken panel hiçbirini işaretlemezdi.
 */
it("kök ağacında da rename hedefini işaretliyor", async () => {
  vi.spyOn(api, "fileHistory").mockResolvedValue(
    result({
      path: "/",
      under: true,
      events: [
        touch({ op: "rename", path: "/etc/shadow", new_path: "/tmp/exfil" }),
      ],
    }),
  );
  render(<FileHistory />);
  await userEvent.type(screen.getByLabelText(/^path$/i), "/");
  await userEvent.click(screen.getByRole("button", { name: /search/i }));

  await waitFor(() => expect(screen.getByText(/moved here/i)).toBeTruthy());
});
