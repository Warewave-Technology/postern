import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import Overview from "./Overview";
import { api, type Session } from "../api";

const session = (over: Partial<Session> = {}): Session => ({
  id: "s1",
  user: "suheda",
  target: "web-01",
  os_user: "suheda",
  src_ip: "10.0.0.4",
  started_at: "2026-09-02T08:00:00Z",
  ended_at: null,
  running: true,
  ...over,
});

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal(
    "confirm",
    vi.fn((_m?: string) => true),
  );
  // EventSource yok: bileşen anket kipine düşüyor, test için yeterli.
  vi.stubGlobal("EventSource", undefined);
});

/*
 * ⚠️ KAPATMA DÜĞMESİ YALNIZCA AKAN OTURUMA ÇİZİLİR.
 *
 * ended_at'in boş olması "bitişini kaydetmedik" demek; postern çökerse o
 * satır sonsuza dek boş kalıyor. Düğmeyi ona da çizmek, yöneticiye var
 * olmayan bir oturumu kapatmayı teklif etmek olurdu.
 */
it("akan oturuma kapatma dugmesi cizer", async () => {
  vi.spyOn(api, "sessions").mockResolvedValue([session()]);
  render(<Overview />);
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: /close suheda's session on web-01/i }),
    ).toBeInTheDocument(),
  );
});

it("acik ama akmayan satira dugme cizmez", async () => {
  vi.spyOn(api, "sessions").mockResolvedValue([session({ running: false })]);
  render(<Overview />);
  await waitFor(() =>
    expect(
      screen.getByText(/still open but nothing here is carrying/i),
    ).toBeInTheDocument(),
  );
  expect(screen.queryByRole("button", { name: /close .*session/i })).toBeNull();
});

/*
 * ⚠️ EKRAN, DÜĞMENİN YAPMADIĞINI SÖYLEMELİ.
 *
 * Kapatma erişimi almıyor: roller bağlanma anında çözülüyor ve hesaba
 * dokunulmuyor, yani kişi hemen yeniden bağlanabiliyor. Olay anındaki
 * bir yönetici "kestim, artık dışarıda" diye okursa ekran yalan söylemiş
 * olur. Bu test o cümlenin silinmesini engelliyor.
 */
it("erisimi almadigini yaziyor", async () => {
  vi.spyOn(api, "sessions").mockResolvedValue([session()]);
  render(<Overview />);
  await waitFor(() =>
    expect(screen.getByText(/does not take access away/i)).toBeInTheDocument(),
  );
});

/*
 * ⚠️ ONAY METNİ YENİDEN BAĞLANILABİLECEĞİNİ SÖYLEMELİ — AMA ÇARE ADI
 * VERMEMELİ.
 *
 * İlk metin "hesabı pasifleştirmek bunu durdurur" diyordu ve bu YANLIŞ:
 * dört giriş yolunun dördü de ConfirmAccount çağırıyor, o da 'inactive'i
 * 'active'e geri çeviriyor. Bu test hem cümlenin silinmesini hem de o
 * yarı doğru vaadin geri gelmesini engelliyor.
 */
it("onay metni yeniden baglanmayi soyler, yanlis care vermez", async () => {
  vi.spyOn(api, "sessions").mockResolvedValue([session()]);
  const terminate = vi
    .spyOn(api, "terminateSession")
    .mockResolvedValue({ ok: true });
  const confirmSpy = vi.fn((_m?: string) => true);
  vi.stubGlobal("confirm", confirmSpy);

  render(<Overview />);
  const btn = await screen.findByRole("button", {
    name: /close suheda's session on web-01/i,
  });
  await userEvent.click(btn);

  const msg = String(confirmSpy.mock.calls[0]?.[0] ?? "");
  expect(msg).toMatch(/can reconnect/i);
  expect(msg).not.toMatch(/deactivat/i);
  expect(terminate).toHaveBeenCalledWith("s1");
});

/*
 * ⚠️ İYİMSER SİLME YOK: başarısız kapatma satırı GİZLEMEMELİ.
 *
 * Aksi hâlde akan bir oturum listeden düşer ve operatör onu kapanmış
 * sanardı — bu özelliğin en kolay yalan söyleme biçimi.
 */
it("kapatma basarisiz olursa satir durur ve hata gorunur", async () => {
  vi.spyOn(api, "sessions").mockResolvedValue([session()]);
  vi.spyOn(api, "terminateSession").mockRejectedValue(
    new Error("that session ended on its own before it could be closed"),
  );

  render(<Overview />);
  const btn = await screen.findByRole("button", {
    name: /close suheda's session on web-01/i,
  });
  await userEvent.click(btn);

  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(/ended on its own/i),
  );
  expect(
    screen.getByRole("button", { name: /close suheda's session on web-01/i }),
  ).toBeInTheDocument();
});

/*
 * ⚠️ "Active sessions" SAYACI DA HAYALETLERİ SAYMAMALI.
 *
 * Sayaç ended_at'e göre süzseydi, çökmeden kalmış satırlar operatöre
 * "3 kişi bağlı" diye görünürdü — bastion'da olup biteni gösteren tek
 * rakamın yanlış olması, listedeki yanlış satırdan daha kötü.
 */
it("sayac yalnizca akan oturumlari sayar", async () => {
  vi.spyOn(api, "sessions").mockResolvedValue([
    session({ id: "a", running: true }),
    session({ id: "b", user: "hayalet", running: false }),
    session({ id: "c", user: "hayalet2", running: false }),
  ]);
  render(<Overview />);
  await waitFor(() => {
    const stat = screen.getByText("Active sessions", {
      selector: "span.k",
    }).parentElement!;
    expect(stat.querySelector("span.n")!.textContent).toBe("1");
  });
});

/*
 * ⚠️ "ÖLÇEMEDİM" SIFIR DİYE GÖSTERİLEMEZ.
 *
 * Dizini okuyamayan bir kurulumu "0 dosya" diye göstermek, her şeyin
 * yolunda olduğunu söylemek olurdu. Arşivleme geldiğinden beri bu
 * daha da keskin: yüklenemeyen kayıt budanmıyor, yani sessizce dolan
 * bir diskin tek erken işareti bu kartlar.
 */
it("olculemeyen degeri sifir gostermez", async () => {
  vi.spyOn(api, "sessions").mockResolvedValue([]);
  vi.spyOn(api, "storage").mockResolvedValue({
    recordings_error: true,
    archive_error: true,
  });
  render(<Overview />);
  await waitFor(() =>
    expect(screen.getByText(/could not be measured/i)).toBeInTheDocument(),
  );
  expect(screen.getByText(/could not be read/i)).toBeInTheDocument();
  // Ve hiçbir yerde sahte bir sıfır olmamalı.
  expect(screen.queryByText("0 files")).toBeNull();
});

/*
 * ⚠️ BEKLEYEN İŞİN YAŞI GÖRÜNMELİ — ve budanamadığı söylenmeli.
 *
 * Sayı tek başına yeterli değil: sabit bir sayı da hiçbir şeyin
 * ilerlemediği anlamına gelebilir. Yaşlanan "en eski", diskin
 * dolacağını haftalar öncesinden söyleyen tek işaret.
 */
it("bekleyen arsiv isinin yasini ve sonucunu yazar", async () => {
  vi.spyOn(api, "sessions").mockResolvedValue([]);
  vi.spyOn(api, "storage").mockResolvedValue({
    recordings: { files: 42, bytes: 1024 * 1024 * 3 },
    archive: {
      pending: 7,
      oldest_at: "2026-08-30T00:00:00Z",
      oldest_age_seconds: 3 * 86400 + 4 * 3600,
    },
  });
  render(<Overview />);
  await waitFor(() => expect(screen.getByText("7")).toBeInTheDocument());
  expect(screen.getByText(/oldest 3d 4h/i)).toBeInTheDocument();
  expect(
    screen.getByText(/cannot be pruned while they wait/i),
  ).toBeInTheDocument();
  expect(screen.getByText("42 files")).toBeInTheDocument();
});

// Depolama okunamazsa oturum listesi ÇALIŞMAYA DEVAM etmeli.
it("depolama hatasi oturum listesini dusurmez", async () => {
  vi.spyOn(api, "sessions").mockResolvedValue([session()]);
  vi.spyOn(api, "storage").mockRejectedValue(new Error("kapali"));
  render(<Overview />);
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: /close suheda's session/i }),
    ).toBeInTheDocument(),
  );
});

/*
 * ⚠️ "BUGÜN" SAYISI TAM MI, ALT SINIR MI.
 *
 * Sayım sunucuda değil panelde yapılıyor ve sunucu en fazla 200 oturum
 * döndürüyor. Yoğun bir günde rakam sessizce doyuyordu; ekranda bunu
 * söyleyen hiçbir şey yoktu. Tamlık ölçülebilir: liste gece yarısının
 * ötesine uzanıyorsa bugünün tamamı elde demektir.
 */
it("liste gece yarısına ulaşmıyorsa sayının alt sınır olduğunu söylüyor", async () => {
  const now = new Date();
  const afterMidnight = new Date(now);
  afterMidnight.setHours(23, 30, 0, 0);
  // En eski satır bile bugüne ait: demek ki daha eskisi kesilmiş.
  vi.spyOn(api, "sessions").mockResolvedValue([
    session({ id: "a", started_at: afterMidnight.toISOString() }),
    session({ id: "b", started_at: afterMidnight.toISOString() }),
  ]);
  render(<Overview />);

  await waitFor(() =>
    expect(screen.getByText(/the list stops before midnight/i)).toBeTruthy(),
  );
});

// Liste düne uzanıyorsa sayı TAM: her rakama "+" koymak, işareti
// anlamsızlaştırırdı.
it("liste düne uzanıyorsa sayıyı kesin veriyor", async () => {
  const yesterday = new Date(Date.now() - 36 * 60 * 60 * 1000);
  vi.spyOn(api, "sessions").mockResolvedValue([
    session({ id: "a", started_at: new Date().toISOString() }),
    session({ id: "b", started_at: yesterday.toISOString() }),
  ]);
  render(<Overview />);

  await waitFor(() =>
    expect(screen.getByText(/since midnight, your time/i)).toBeTruthy(),
  );
  expect(screen.queryByText(/the list stops before midnight/i)).toBeNull();
});

/*
 * ⚠️ "KISMEN ÖLÇTÜK", "ÖLÇTÜK" DEĞİLDİR.
 *
 * record.Usage okunamayan alt ağaçları atlayıp devam ediyor — kasıtlı,
 * eksik sayı hiç sayı olmamasından iyi. Ama eksik bir toplamı tam gibi
 * göstermek, "5 GB" diyen bir rapora bakıp saklama süresi seçtirmek
 * demek; gerçekte 40 GB olabilir.
 */
it("disk ölçümü eksikse rakamın alt sınır olduğunu söylüyor", async () => {
  vi.spyOn(api, "sessions").mockResolvedValue([]);
  vi.spyOn(api, "storage").mockResolvedValue({
    recordings: { files: 3, bytes: 1024, skipped: 2 },
  } as never);
  render(<Overview />);

  await waitFor(() =>
    expect(screen.getByText(/could not be read/i)).toBeTruthy(),
  );
  expect(screen.getByText(/at least 3 files/i)).toBeTruthy();
});
