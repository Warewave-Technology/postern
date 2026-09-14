import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api";
import RoleSudo from "./RoleSudo";

afterEach(() => vi.restoreAllMocks());

describe("RoleSudo", () => {
  /*
   * ⚠️ KUTUDAKİ SATIRLAR KOMUTA ÇEVRİLİYOR: ilk kelime yol, kalanı
   * argüman — geçici erişim sihirbazındaki kutunun aynısı. İki ekranda
   * iki farklı yazım biçimi, kuralı yanlış yazdıran en ucuz yol.
   */
  it("satırları komut listesine çeviriyor ve kaydettiğini söylüyor", async () => {
    const set = vi.spyOn(api, "setRoleSudo").mockResolvedValue({ ok: true });
    const onChanged = vi.fn().mockResolvedValue(undefined);
    render(<RoleSudo role="dba" onChanged={onChanged} />);

    await userEvent.type(
      screen.getByLabelText(/commands, one per line/i),
      "/usr/sbin/nginx -t\n/usr/bin/pg_ctl reload",
    );
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));

    await waitFor(() => expect(set).toHaveBeenCalledTimes(1));
    expect(set.mock.calls[0][0]).toBe("dba");
    expect(set.mock.calls[0][1]).toMatchObject({
      acknowledged: false,
      commands: [
        { path: "/usr/sbin/nginx", args: ["-t"] },
        { path: "/usr/bin/pg_ctl", args: ["reload"] },
      ],
    });
    expect(onChanged).toHaveBeenCalled();
    // ⚠️ "Kaydedildi" DEMİYOR, "bir sonraki dokunuşta iner" diyor: kural
    // bütün makinelere anında gitmiyor ve tersini sanmak koyulmamış bir
    // yetkiye güvenmek olurdu.
    expect((await screen.findByRole("status")).textContent).toMatch(
      /next time postern works on it/i,
    );
  });

  // Komut yoksa kaydedecek bir şey yok: boş kural hiçbir şey vermiyor.
  it("komutsuz kaydı kapatıyor", () => {
    render(<RoleSudo role="dba" onChanged={vi.fn()} />);
    expect(screen.getByRole("button", { name: /save rule/i })).toBeDisabled();
  });

  /*
   * ⚠️ SUNUCUNUN RET CÜMLESİ EKRANDA DURUYOR. Operatör onay kutusunu
   * işaretleyecekse neyi onayladığını okumak zorunda; "invalid value"
   * diyen bir ekran onu körlemesine onaylatır.
   */
  it("kaçış riski reddini sebebiyle gösteriyor", async () => {
    vi.spyOn(api, "setRoleSudo").mockRejectedValue(
      new Error("/usr/bin/vim opens an editor, so this grant is root"),
    );
    render(<RoleSudo role="ops" onChanged={vi.fn()} />);

    await userEvent.type(screen.getByLabelText(/commands, one per line/i), "/usr/bin/vim");
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));

    expect(await screen.findByText(/opens an editor/i)).toBeTruthy();
    expect(screen.getByLabelText(/i accept that a command here may open a root shell/i)).not.toBeChecked();
  });

  /*
   * ⚠️ SİLME "YETKİ KALKTI" DEMİYOR. Kural postern'den gidiyor;
   * hedeflerdeki dosya postern oraya bir daha dokunana kadar duruyor ve
   * ekran sunucunun bu cümlesini olduğu gibi gösteriyor.
   */
  it("silmede hedeflerdeki dosyanın kaldığını söylüyor", async () => {
    const del = vi.spyOn(api, "deleteRoleSudo").mockResolvedValue({
      ok: true,
      note: "On hosts that already have /etc/sudoers.d/postern-ops, the file stays until postern next works on them.",
    });
    render(
      <RoleSudo
        role="ops"
        rule={{
          commands: ["/usr/sbin/nginx -t"],
          acknowledged: false,
          updated_by: "yigit",
          updated_at: "2026-09-14T10:00:00Z",
        }}
        onChanged={vi.fn().mockResolvedValue(undefined)}
      />,
    );

    // Onay kutusu (window.confirm) hangi cümleyi gösteriyor, o da ölçülüyor:
    // "emin misin" demek, hedeflerdeki dosyanın kaldığını söylemiyor.
    const confirmSpy = vi.fn((_msg?: string) => true);
    vi.stubGlobal("confirm", confirmSpy);
    fireEvent.click(screen.getByRole("button", { name: /remove the sudo rule from role ops/i }));

    await waitFor(() => expect(del).toHaveBeenCalledWith("ops"));
    expect(confirmSpy.mock.calls[0][0]).toMatch(/keep it until postern next works on them/i);
    expect((await screen.findByRole("status")).textContent).toMatch(/the file stays until postern/i);
  });
});
