import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AdminGroup from "./AdminGroup";
import { api, type AdminGroupPreview, type AdminGroupStatus } from "../api";

const status = (over: Partial<AdminGroupStatus> = {}): AdminGroupStatus => ({
  group: "eski-yoneticiler",
  holders: [
    { username: "ops", via: "cli" },
    { username: "yigit", via: "group" },
  ],
  enumerable: true,
  ...over,
});

const preview = (over: Partial<AdminGroupPreview> = {}): AdminGroupPreview => ({
  ok: true,
  group: "sysadmins",
  admins: ["ayse", "mehmet"],
  no_account: [],
  skipped: [],
  truncated: false,
  ...over,
});

async function openForm() {
  render(<AdminGroup meName="yigit" />);
  await waitFor(() =>
    expect(screen.getByRole("button", { name: /change group/i })).toBeEnabled(),
  );
  await userEvent.click(screen.getByRole("button", { name: /change group/i }));
  const box = screen.getByLabelText(/group name/i);
  await userEvent.clear(box);
  await userEvent.type(box, "sysadmins");
  return box;
}

const seeWho = () =>
  userEvent.click(screen.getByRole("button", { name: /see who this group/i }));

const saveBtn = () =>
  screen.getByRole("button", { name: /confirm and save the administrator/i });

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal("confirm", vi.fn(() => true));
  vi.spyOn(api, "adminGroup").mockResolvedValue(status());
});

describe("yonetici grubu onayi", () => {
  /*
   * ⚠️ Onayın var olma sebebi: LİSTEYE BAKMADAN kaydedilememesi.
   * Asıl koruma sunucuda (gördüğün listeyi geri istiyor), ama ekranın
   * da kaydettirmemesi gerekiyor — yoksa kullanıcı her denemede 409
   * yiyip sebebini anlamaz.
   */
  it("liste gorulmeden kaydettirmez", async () => {
    await openForm();
    expect(saveBtn()).toBeDisabled();

    vi.spyOn(api, "previewAdminGroup").mockResolvedValue(preview());
    await seeWho();

    await waitFor(() => expect(saveBtn()).toBeEnabled());
  });

  /*
   * ⚠️ AD DEĞİŞİNCE ONAY DÜŞMELİ.
   *
   * Düşmeseydi: "sysadmins" için listeye bakıp, kutuya "domain admins"
   * yazıp kaydetmek mümkün olurdu — ekranda bir kümenin listesi
   * dururken bambaşka bir kümeye yetki verilirdi. (Sunucu bunu yine
   * reddeder; ama ekran, reddedileceğini bilerek kaydettirmemeli.)
   */
  it("grup adi degisince onceki onizlemeyi gecersiz sayar", async () => {
    const box = await openForm();
    vi.spyOn(api, "previewAdminGroup").mockResolvedValue(preview());
    await seeWho();
    await waitFor(() => expect(saveBtn()).toBeEnabled());

    await userEvent.clear(box);
    await userEvent.type(box, "domain admins");

    expect(saveBtn()).toBeDisabled();
    expect(screen.queryByText(/You are giving administrator/i)).toBeNull();
  });

  // Kaydetme, EKRANDA GÖRÜLEN listeyi gönderiyor — sunucunun
  // karşılaştırdığı şey bu.
  it("gorulen listeyi onay olarak gonderir", async () => {
    await openForm();
    vi.spyOn(api, "previewAdminGroup").mockResolvedValue(preview());
    const set = vi
      .spyOn(api, "setAdminGroup")
      .mockResolvedValue({ ok: true, group: "sysadmins", granted: [], revoked: [] });

    await seeWho();
    await waitFor(() => expect(saveBtn()).toBeEnabled());
    await userEvent.click(saveBtn());

    await waitFor(() =>
      expect(set).toHaveBeenCalledWith("sysadmins", ["ayse", "mehmet"]),
    );
  });

  /*
   * Yetkinin NE OLDUĞU ekranda yazmak zorunda. "Admin" kelimesi, bu
   * yetkinin denetim günlüğünü ve oturum KAYITLARINI — yani geçmişi —
   * açtığını söylemiyor.
   */
  it("denetim gunlugu ve kayit erisimini soyler", async () => {
    await openForm();
    vi.spyOn(api, "previewAdminGroup").mockResolvedValue(preview());
    await seeWho();

    await waitFor(() =>
      expect(screen.getByText(/audit log/i)).toBeInTheDocument(),
    );
    expect(screen.getByText(/session recordings/i)).toBeInTheDocument();
  });

  // Onay bir FOTOĞRAFIN değil, GRUBUN onayı: sonradan eklenen de
  // yönetici olur ve bunu ekran söylemezse onay yanlış anlaşılır.
  it("uyeligin surekli oldugunu soyler", async () => {
    await openForm();
    vi.spyOn(api, "previewAdminGroup").mockResolvedValue(preview());
    await seeWho();

    await waitFor(() =>
      expect(screen.getByText(/whoever is added to/i)).toBeInTheDocument(),
    );
  });

  // Yeni grupta olmayan eski grup yöneticileri KAYBEDİYOR — ve bu,
  // kaydetmeden önce görünmeli.
  it("yetkiyi kaybedecekleri sayar", async () => {
    await openForm();
    vi.spyOn(api, "previewAdminGroup").mockResolvedValue(preview());
    await seeWho();

    const line = await screen.findByText(/Losing it:/i);
    // ⚠️ Satırın KENDİSİNE bakıyoruz: "yigit" ekranın başındaki
    // yönetici listesinde de geçiyor ve sayfa geneline bakan bir
    // arama, satır hiç çizilmese bile geçerdi.
    expect(line.parentElement?.textContent).toMatch(/yigit/);
    // ops CLI'dan geliyor: kaybetmiyor, bu satırda olmamalı.
    expect(line.parentElement?.textContent).not.toMatch(/ops/);
  });

  /*
   * ⚠️ Kendi yetkisini kaybeden kişi bunu KAYDETMEDEN ÖNCE görmeli.
   * Kaydettikten sonra öğrenmesi, ekranın bir daha açılmaması demek.
   */
  it("kaydeden kisi kendi yetkisini kaybediyorsa uyarir", async () => {
    await openForm();
    vi.spyOn(api, "previewAdminGroup").mockResolvedValue(preview());
    await seeWho();

    await waitFor(() =>
      expect(
        screen.getByText(/removes your own administrator access/i),
      ).toBeInTheDocument(),
    );
  });

  // Kendisi yeni gruptaysa o uyarı ÇIKMAMALI: her kaydetmede korkutmak,
  // uyarıyı okunmaz hâle getirir.
  it("kendisi yeni gruptaysa kendini uyarmaz", async () => {
    await openForm();
    vi.spyOn(api, "previewAdminGroup").mockResolvedValue(
      preview({ admins: ["ayse", "yigit"] }),
    );
    await seeWho();

    await waitFor(() =>
      expect(screen.getByText(/You are giving administrator/i)).toBeInTheDocument(),
    );
    expect(screen.queryByText(/removes your own administrator access/i)).toBeNull();
  });

  // Hesabı olmayan üye: yetkisi ancak ilk girişinde oluşur. "Şimdi
  // yönetici oldu" demek yalan olurdu.
  it("postern hesabi olmayani ayirir", async () => {
    await openForm();
    vi.spyOn(api, "previewAdminGroup").mockResolvedValue(
      preview({ no_account: ["mehmet"] }),
    );
    await seeWho();

    await waitFor(() =>
      expect(screen.getByText(/gets it at first sign-in/i)).toBeInTheDocument(),
    );
  });

  // Kimsenin çözülmediği grup: kaydedilebilir ama SESSİZ kalmamalı —
  // yazım hatası, kimsenin fark etmediği bir yetki kapısı demek.
  it("kimseyi cozmeyen grubu uyararak gosterir", async () => {
    await openForm();
    vi.spyOn(api, "previewAdminGroup").mockResolvedValue(
      preview({ admins: [], note: "no group by that name was found in scope" }),
    );
    await seeWho();

    await waitFor(() =>
      expect(screen.getByText(/Nobody resolves in that group/i)).toBeInTheDocument(),
    );
  });
});

describe("uyeligin sayilamadigi kurulumlar", () => {
  /*
   * OIDC claim'i grubun ÜYELERİNİ listeleyemez. Ekran o kurulumda
   * sayabiliyormuş gibi davranırsa, güvenilecek en kötü şeyi yapmış
   * olur: boş bir listeyi "kimse yok" diye gösterir.
   */
  it("claim modunda formu hic acmaz", async () => {
    vi.spyOn(api, "adminGroup").mockResolvedValue(
      status({ enumerable: false, group: "" }),
    );
    render(<AdminGroup meName="yigit" />);

    await waitFor(() =>
      expect(screen.getByText(/cannot be listed here/i)).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: /change group/i })).toBeNull();
  });

  // ⚠️ "LDAP kurulmamış" ile "LDAP bozuk" AYNI cümleye düşerse yanlış
  // teşhis konur: operatör claim modunda olduğunu sanıp arızayı aramaz.
  it("bozuk yapilandirmayi claim moduyla karistirmaz", async () => {
    vi.spyOn(api, "adminGroup").mockResolvedValue(
      status({ enumerable: false, enumerable_error: "ldap: group_base is required" }),
    );
    render(<AdminGroup meName="yigit" />);

    await waitFor(() =>
      expect(
        screen.getByText(/LDAP is configured but postern could not/i),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByText(/coming from the identity provider/i)).toBeNull();
  });
});

describe("gruptan vazgecme", () => {
  // Grubu bırakmak, gruptan gelen yöneticileri düşürür — kaç kişi
  // olduğu onay metninde yazmalı.
  it("kimlerin kaybedecegini onay metninde sayar", async () => {
    const confirmSpy = vi.fn((_msg?: string) => true);
    vi.stubGlobal("confirm", confirmSpy);
    const set = vi
      .spyOn(api, "setAdminGroup")
      .mockResolvedValue({ ok: true, group: "", granted: [], revoked: ["yigit"] });

    render(<AdminGroup meName="ops" />);
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /stop granting administrator/i }),
      ).toBeEnabled(),
    );
    await userEvent.click(
      screen.getByRole("button", { name: /stop granting administrator/i }),
    );

    expect(confirmSpy.mock.calls[0][0]).toMatch(/yigit/);
    await waitFor(() => expect(set).toHaveBeenCalledWith("", ["yigit"]));
  });
});

/*
 * ⚠️ KARTIN SORUSU "BU GRUP KİMİ YÖNETİCİ YAPIYOR".
 *
 * CLI'dan gelen yöneticileri aynı listeye koymak o soruyu bulandırıyordu:
 * operatör, bu grubu değiştirerek etkileyemeyeceği isimleri listede
 * görüyor ve grubu boşaltmanın onları da düşüreceğini sanıyordu.
 *
 * Ama varlıkları kaybolmamalı: bu grubu bırakmanın postern'i yöneticisiz
 * bırakıp bırakmayacağının cevabı o sayıda.
 */
describe("liste kapsami", () => {
  it("yalnizca gruptan gelenleri listeler, digerlerini SAYAR", async () => {
    vi.spyOn(api, "adminGroup").mockResolvedValue(
      status({
        holders: [
          { username: "ops", via: "cli" },
          { username: "sre", via: "cli" },
          { username: "yigit", via: "group" },
        ],
      }),
    );
    render(<AdminGroup meName="yigit" />);

    const label = await screen.findByText(/administrators from this group/i);
    const cell = label.nextElementSibling as HTMLElement;
    expect(cell.textContent).toMatch(/yigit/);
    // CLI'dan gelenler LİSTEDE değil...
    expect(cell.querySelector("ul")?.textContent).not.toMatch(/ops|sre/);
    // ...ama sayıları söyleniyor.
    expect(cell.textContent).toMatch(/2 more administrators come from the bastion host/i);
  });

  it("gruptan kimse gelmiyorsa bunu soyler", async () => {
    vi.spyOn(api, "adminGroup").mockResolvedValue(
      status({ holders: [{ username: "ops", via: "cli" }] }),
    );
    render(<AdminGroup meName="ops" />);

    const label = await screen.findByText(/administrators from this group/i);
    expect((label.nextElementSibling as HTMLElement).textContent).toMatch(
      /nobody yet/i,
    );
  });
});
