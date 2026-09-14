import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, RoleSudoRule } from "../api";
import RoleSudo from "./RoleSudo";

afterEach(() => vi.restoreAllMocks());

const rule: RoleSudoRule = {
  commands: [
    { command: "/usr/sbin/nginx -t", run_as: "root" },
    // ⚠️ İKİNCİ KOMUT BAŞKA HESAPLA: sütunun ve kaydetmenin hesabı komut
    // başına taşıdığı buradan ölçülüyor.
    { command: "/usr/bin/pg_ctl reload", run_as: "postgres" },
  ],
  acknowledged: false,
  updated_by: "yigit",
  updated_at: "2026-09-14T10:00:00Z",
};

describe("RoleSudo", () => {
  /*
   * ⚠️ KOMUTLAR TABLODA VE ARANABİLİR. İlk hâl tek bir yazım kutusuydu:
   * iki yüz komutlu bir kuralda aradığın satırı bulmanın yolu yoktu
   * (kullanıcı söyledi).
   */
  it("komutları aranabilir tabloda listeliyor", async () => {
    render(<RoleSudo role="dba" rule={rule} onChanged={vi.fn()} />);

    expect(screen.getByText("/usr/sbin/nginx -t")).toBeTruthy();
    expect(screen.getByText("/usr/bin/pg_ctl reload")).toBeTruthy();

    fireEvent.change(screen.getByPlaceholderText(/search commands/i), {
      target: { value: "pg_ctl" },
    });
    expect(screen.queryByText("/usr/sbin/nginx -t")).toBeNull();
    expect(screen.getByText("/usr/bin/pg_ctl reload")).toBeTruthy();
  });

  /*
   * ⚠️ EKLEME KURALIN TAMAMINI YAZIYOR. Uç PUT, yani yama değil; yeni
   * komutu var olanlara EKLEYİP göndermezsek "bir komut ekledim" tıklaması
   * kuralın geri kalanını sessizce silerdi.
   */
  it("komut ekleyince var olanları koruyor", async () => {
    const set = vi.spyOn(api, "setRoleSudo").mockResolvedValue({ ok: true });
    const onChanged = vi.fn().mockResolvedValue(undefined);
    render(<RoleSudo role="dba" rule={rule} onChanged={onChanged} />);

    fireEvent.click(screen.getByRole("button", { name: /add command/i }));
    await userEvent.type(await screen.findByLabelText(/^command$/i), "/bin/systemctl reload nginx");
    fireEvent.click(screen.getAllByRole("button", { name: /add command/i }).at(-1)!);

    await waitFor(() => expect(set).toHaveBeenCalledTimes(1));
    // ⚠️ HESAP KOMUT BAŞINA GİDİYOR: postgres olan komut postgres kalıyor,
    // yenisi kutudaki hesabı alıyor. Kural başına tek hesap olsaydı,
    // bir komut eklemek diğerinin hesabını sessizce değiştirirdi.
    expect(set.mock.calls[0][1]).toMatchObject({
      commands: [
        { path: "/usr/sbin/nginx", args: ["-t"], run_as: "root" },
        { path: "/usr/bin/pg_ctl", args: ["reload"], run_as: "postgres" },
        { path: "/bin/systemctl", args: ["reload", "nginx"], run_as: "root" },
      ],
    });
    expect(onChanged).toHaveBeenCalled();
  });

  /*
   * ⚠️ SON KOMUTU SİLMEK KURALI KALDIRIYOR. Sunucu komutsuz kuralı
   * reddediyor; onu yazmaya çalışmak, operatöre "silemedin" diyen bir
   * hata olurdu. Onay metni de bunu söylüyor.
   */
  it("son komut silinince kuralı kaldırıyor", async () => {
    const del = vi.spyOn(api, "deleteRoleSudo").mockResolvedValue({ ok: true });
    const confirmSpy = vi.fn((_msg?: string) => true);
    vi.stubGlobal("confirm", confirmSpy);
    render(
      <RoleSudo
        role="dba"
        rule={{ ...rule, commands: [{ command: "/usr/sbin/nginx -t", run_as: "root" }] }}
        onChanged={vi.fn().mockResolvedValue(undefined)}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: /remove command \/usr\/sbin\/nginx -t from role dba/i }),
    );
    await waitFor(() => expect(del).toHaveBeenCalledWith("dba"));
    expect(confirmSpy.mock.calls[0][0]).toMatch(/only command in the rule/i);
  });

  /*
   * ⚠️ SUNUCUNUN RET CÜMLESİ EKRANDA DURUYOR ve modal AÇIK kalıyor.
   * Operatör onay kutusunu işaretleyecekse neyi onayladığını okumak
   * zorunda; kapanan bir modal onu körlemesine onaylatır.
   */
  /*
   * ⚠️ ONAY KUTUSU RET GELENE KADAR YOK VE HER RETTE DE GELMİYOR.
   *
   * Her komut zaten root olarak çalışıyor; hep duran bir kutu, kabul
   * edilen şeyin ne olduğunu anlamsızlaştırıyordu (kullanıcı sordu).
   * Kabul edilen şey dar yetkiden KAÇIŞ. Joker ya da göreli yol taşıyan
   * bir ret onayla da geçmiyor, o yüzden orada kutu belirmemeli — karar
   * sunucunun (acknowledgeable), ekranın ret metnini tahmin etmesi
   * değil.
   */
  it("onay kutusunu yalnızca kabul edilebilir rette gösteriyor", async () => {
    const ackLabel = /i understand this command can start another program/i;
    const set = vi
      .spyOn(api, "setRoleSudo")
      .mockRejectedValueOnce(new ApiError(422, "/usr/bin/vim escapes to a shell", true));

    render(<RoleSudo role="ops" onChanged={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: /add command/i }));
    const box = await screen.findByLabelText(/^command$/i);
    expect(screen.queryByLabelText(ackLabel)).toBeNull();

    await userEvent.type(box, "/usr/bin/vim");
    fireEvent.click(screen.getAllByRole("button", { name: /add command/i }).at(-1)!);

    expect(await screen.findByText(/escapes to a shell/i)).toBeTruthy();
    expect(screen.getByLabelText(ackLabel)).not.toBeChecked();
    // Modal açık kalıyor ve yazılan duruyor.
    expect(screen.getByLabelText(/^command$/i)).toBeTruthy();
    expect(set).toHaveBeenCalledTimes(1);
  });

  it("onayla geçmeyen rette kutu belirmiyor", async () => {
    vi.spyOn(api, "setRoleSudo").mockRejectedValue(
      new ApiError(422, "/usr/bin/* is a wildcard: it matches commands nobody listed", false),
    );
    render(<RoleSudo role="ops" onChanged={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: /add command/i }));
    await userEvent.type(await screen.findByLabelText(/^command$/i), "/usr/bin/*");
    fireEvent.click(screen.getAllByRole("button", { name: /add command/i }).at(-1)!);

    expect(await screen.findByText(/is a wildcard/i)).toBeTruthy();
    expect(
      screen.queryByLabelText(/i understand this command can start another program/i),
    ).toBeNull();
  });

  /*
   * ⚠️ DÜZENLEME SATIR BAZINDA VE HESAP KENDİ ALANINDA — ÖLÇÜLEN ARIZA
   * BURADAN GELDİ. Kuralın tamamı tek bir yazım kutusundayken komutun
   * hesabı satır başındaki "(postgres)" önekinde taşınıyordu; öneki elle
   * düşüren bir düzenleme komutu sessizce ROOT'a çeviriyordu. Ölçüldü:
   * kutuya "(postgres) /usr/bin/pg_ctl reload" yerine öneksiz satır
   * yazıldığında istek run_as=root gidiyordu.
   *
   * Şimdi bir satırı düzenlemek yalnızca o satırı değiştiriyor; öbür
   * komutların hesabı elle korunmuyor, hiç dokunulmuyor.
   */
  it("bir satırı düzenlerken öbür komutların hesabını bozmuyor", async () => {
    const set = vi.spyOn(api, "setRoleSudo").mockResolvedValue({ ok: true });
    render(<RoleSudo role="dba" rule={rule} onChanged={vi.fn().mockResolvedValue(undefined)} />);

    fireEvent.click(
      screen.getByRole("button", { name: /edit command \/usr\/sbin\/nginx -t of role dba/i }),
    );
    const box = await screen.findByLabelText(/^command$/i);
    expect((box as HTMLInputElement).value).toBe("/usr/sbin/nginx -t");
    expect((screen.getByRole("textbox", { name: /runs as/i }) as HTMLInputElement).value).toBe("root");

    await userEvent.clear(box);
    await userEvent.type(box, "/usr/sbin/nginx -s reload");
    fireEvent.click(screen.getByRole("button", { name: /save command/i }));

    await waitFor(() => expect(set).toHaveBeenCalledTimes(1));
    expect(set.mock.calls[0][1].commands).toEqual([
      { path: "/usr/sbin/nginx", args: ["-s", "reload"], run_as: "root" },
      // ⚠️ postgres KALDI: düzenlenmeyen satıra dokunulmadı.
      { path: "/usr/bin/pg_ctl", args: ["reload"], run_as: "postgres" },
    ]);
  });

  // Satırın hesabı da düzenlenebiliyor, kendi alanından.
  it("bir satırın hesabını değiştirebiliyor", async () => {
    const set = vi.spyOn(api, "setRoleSudo").mockResolvedValue({ ok: true });
    render(<RoleSudo role="dba" rule={rule} onChanged={vi.fn().mockResolvedValue(undefined)} />);

    fireEvent.click(
      screen.getByRole("button", { name: /edit command \/usr\/bin\/pg_ctl reload of role dba/i }),
    );
    const runAs = await screen.findByRole("textbox", { name: /runs as/i });
    expect((runAs as HTMLInputElement).value).toBe("postgres");
    await userEvent.clear(runAs);
    await userEvent.type(runAs, "pgbouncer");
    fireEvent.click(screen.getByRole("button", { name: /save command/i }));

    await waitFor(() => expect(set).toHaveBeenCalledTimes(1));
    expect(set.mock.calls[0][1].commands[1]).toEqual({
      path: "/usr/bin/pg_ctl",
      args: ["reload"],
      run_as: "pgbouncer",
    });
  });

  /*
   * ⚠️ SİLME "YETKİ KALKTI" DEMİYOR. Kural postern'den gidiyor;
   * hedeflerdeki dosya postern oraya bir daha dokunana kadar duruyor ve
   * ekran sunucunun bu cümlesini olduğu gibi gösteriyor.
   */
  it("kuralı kaldırırken hedeflerdeki dosyanın kaldığını söylüyor", async () => {
    const del = vi.spyOn(api, "deleteRoleSudo").mockResolvedValue({
      ok: true,
      note: "On hosts that already have /etc/sudoers.d/postern-ops, the file stays until postern next works on them.",
    });
    vi.stubGlobal("confirm", vi.fn(() => true));
    render(<RoleSudo role="ops" rule={rule} onChanged={vi.fn().mockResolvedValue(undefined)} />);

    fireEvent.click(screen.getByRole("button", { name: /remove the sudo rule from role ops/i }));

    await waitFor(() => expect(del).toHaveBeenCalledWith("ops"));
    expect((await screen.findByText(/the file stays until postern/i)).textContent).toBeTruthy();
  });

  /*
   * ⚠️ RİSK SATIRIN KENDİSİNDE İŞARETLİ. Tablonun altındaki "burada bir
   * komut riskli" notu, altı komutluk bir kuralda hangisinin olduğunu
   * söylemiyordu (kullanıcı ekrana bakıp söyledi): işaret riskli satırda,
   * sebebi de ekran okuyucuya açık metinde.
   */
  it("kaçış yolu olan komutu satırında işaretliyor", () => {
    render(
      <RoleSudo
        role="ops"
        rule={{
          ...rule,
          acknowledged: true,
          commands: [
            { command: "/usr/sbin/nginx -t", run_as: "root" },
            { command: "/usr/bin/vim", run_as: "root", escape: "escapes to a shell" },
          ],
        }}
        onChanged={vi.fn()}
      />,
    );

    const marks = screen.getAllByText(/warning: \/usr\/bin\/vim escapes to a shell/i);
    expect(marks).toHaveLength(1);
    // Risksiz komutun satırında işaret yok.
    const safeRow = screen.getByText("/usr/sbin/nginx -t").closest("tr")!;
    expect(safeRow.querySelector(".risk")).toBeNull();
    const riskyRow = screen.getByText("/usr/bin/vim").closest("tr")!;
    expect(riskyRow.querySelector(".risk")).toBeTruthy();
  });
});