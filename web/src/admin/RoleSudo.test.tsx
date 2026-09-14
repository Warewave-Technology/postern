import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api, RoleSudoRule } from "../api";
import RoleSudo from "./RoleSudo";

afterEach(() => vi.restoreAllMocks());

const rule: RoleSudoRule = {
  commands: ["/usr/sbin/nginx -t", "/usr/bin/pg_ctl reload"],
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
    expect(set.mock.calls[0][1]).toMatchObject({
      run_as: "root",
      commands: [
        { path: "/usr/sbin/nginx", args: ["-t"] },
        { path: "/usr/bin/pg_ctl", args: ["reload"] },
        { path: "/bin/systemctl", args: ["reload", "nginx"] },
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
        rule={{ ...rule, commands: ["/usr/sbin/nginx -t"] }}
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
  it("kaçış riski reddini sebebiyle gösteriyor", async () => {
    vi.spyOn(api, "setRoleSudo").mockRejectedValue(
      new Error("/usr/bin/vim opens an editor, so this grant is root"),
    );
    render(<RoleSudo role="ops" onChanged={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: /write the rule/i }));
    await userEvent.type(await screen.findByLabelText(/commands, one per line/i), "/usr/bin/vim");
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));

    expect(await screen.findByText(/opens an editor/i)).toBeTruthy();
    expect(
      screen.getByLabelText(/i accept that a command here may open a root shell/i),
    ).not.toBeChecked();
    expect(screen.getByLabelText(/commands, one per line/i)).toBeTruthy();
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
});
