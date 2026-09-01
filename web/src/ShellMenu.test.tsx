import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ShellMenu, { sshCommand } from "./ShellMenu";

const writeText = vi.fn(() => Promise.resolve());

beforeEach(() => {
  writeText.mockClear();
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText },
    configurable: true,
    writable: true,
  });
});

describe("ssh komutu", () => {
  /*
   * ⚠️ POSTERN'İN KULLANICI KALIBI "kullanıcı:hedef".
   *
   * Hedef, host değil kullanıcı adının parçası — bastion yönlendirmeyi
   * oradan okuyor (sshd.ParseUsername). Bunu "ssh hedef@bastion" diye
   * yazmak, bastion'a hedefi hiç söylememek demek.
   */
  it("hedefi kullanıcı adına koyuyor", () => {
    expect(sshCommand("yigit", "web-01", "bastion.io", 22)).toBe(
      "ssh yigit:web-01@bastion.io",
    );
  });

  // Port yalnızca 22 değilse yazılıyor: gereksiz bir -p, okuyana özel
  // bir şey yapıldığını düşündürür.
  it("varsayılan olmayan portu yazıyor, 22'yi yazmıyor", () => {
    expect(sshCommand("yigit", "web-01", "bastion.io", 2222)).toBe(
      "ssh -p 2222 yigit:web-01@bastion.io",
    );
    expect(sshCommand("yigit", "web-01", "bastion.io", 22)).not.toContain("-p");
  });
});

describe("shell menüsü", () => {
  const open = async () => {
    await userEvent.click(
      screen.getByRole("button", { name: /shell options/i }),
    );
  };

  it("iki seçeneği de sunuyor", async () => {
    render(
      <ShellMenu
        target="web-01"
        user="yigit"
        sshHost="bastion.io"
        sshPort={2222}
        connectHref="/shell/web-01"
      />,
    );
    await open();
    expect(screen.getByRole("menuitem", { name: /connect/i })).toBeTruthy();
    expect(
      screen.getByRole("menuitem", { name: /copy ssh command/i }),
    ).toBeTruthy();
  });

  it("komutu panoya yazıyor", async () => {
    render(
      <ShellMenu
        target="web-01"
        user="yigit"
        sshHost="bastion.io"
        sshPort={2222}
        connectHref="/shell/web-01"
      />,
    );
    await open();
    await userEvent.click(
      screen.getByRole("menuitem", { name: /copy ssh command/i }),
    );
    expect(writeText).toHaveBeenCalledWith(
      "ssh -p 2222 yigit:web-01@bastion.io",
    );
  });

  /*
   * ⚠️ WEB TERMİNALİ KAPALIYKEN DE MENÜ VAR.
   *
   * Eskiden düğme tamamen terminale bağlıydı: terminali kapatan
   * kurulumda kartta hiçbir eylem kalmıyordu — oysa ssh komutu o
   * kurulumda da geçerli, hatta tek yol o.
   */
  it("terminal kapalıyken kopyalamayı yine sunuyor", async () => {
    render(
      <ShellMenu
        target="web-01"
        user="yigit"
        sshHost="bastion.io"
        sshPort={22}
      />,
    );
    await open();
    expect(screen.queryByRole("menuitem", { name: /connect/i })).toBeNull();
    expect(
      screen.getByRole("menuitem", { name: /copy ssh command/i }),
    ).toBeTruthy();
  });

  /*
   * ⚠️ ADRES BİLİNMİYORSA KOPYALAMA HİÇ ÇİZİLMİYOR.
   *
   * Yer tutuculu ("<bastion>") bir komut, yapıştırıldığı anda bozuktur
   * ve kullanıcı hatayı postern'de arar. Hiç vermemek dürüst olan.
   */
  it("adres yoksa kopyalama seçeneği yok", async () => {
    render(
      <ShellMenu target="web-01" user="yigit" connectHref="/shell/web-01" />,
    );
    await open();
    expect(screen.queryByRole("menuitem", { name: /copy/i })).toBeNull();
    expect(screen.getByRole("menuitem", { name: /connect/i })).toBeTruthy();
  });

  // İkisi de yoksa düğme hiç çizilmiyor: basınca boş menü açan bir
  // düğme, bozuk bir düğmedir.
  it("hiçbir seçenek yoksa düğme de yok", () => {
    const { container } = render(<ShellMenu target="web-01" user="yigit" />);
    expect(container.querySelector("button")).toBeNull();
  });

  /*
   * ⚠️ PANO YOKSA KOMUT EKRANDA GÖSTERİLİYOR.
   *
   * navigator.clipboard yalnızca güvenli bağlamda var; düz http
   * üzerinden açılan panelde hiç tanımlı değil. Sessizce hiçbir şey
   * yapmak, kullanıcıya yapıştıracak bir şey olduğunu sandırırdı.
   */
  it("pano kullanılamıyorsa komutu ekranda veriyor", async () => {
    Object.defineProperty(navigator, "clipboard", {
      value: undefined,
      configurable: true,
      writable: true,
    });
    render(
      <ShellMenu
        target="web-01"
        user="yigit"
        sshHost="bastion.io"
        sshPort={22}
      />,
    );
    await open();
    await userEvent.click(
      screen.getByRole("menuitem", { name: /copy ssh command/i }),
    );
    expect(screen.getByText("ssh yigit:web-01@bastion.io")).toBeTruthy();
    // "Kopyalandı" demek yalan olurdu.
    expect(screen.queryByText(/^Copied$/)).toBeNull();
  });

  // Escape menüyü kapatır: açık kalan bir menü kartların üstünü örter
  // ve kullanıcı bunu arayüzün donması sanır.
  it("Escape ile kapanıyor", async () => {
    render(
      <ShellMenu
        target="web-01"
        user="yigit"
        sshHost="bastion.io"
        connectHref="/shell/web-01"
      />,
    );
    await open();
    expect(screen.getByRole("menu")).toBeTruthy();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).toBeNull();
  });
});
