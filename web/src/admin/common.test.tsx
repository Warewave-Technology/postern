import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api";
import { ActionButton, ErrorLine, ListState, useList } from "./common";

// useList'i sınamak için ince bir kabuk.
function Probe({ load }: { load: () => Promise<string[]> }) {
  const { items, error, denied, loading, failed } = useList(load);
  return (
    <>
      <ListState
        loading={loading}
        denied={denied}
        failed={failed}
        empty={items.length === 0}
        emptyText="NOTHING HERE"
      />
      <ErrorLine msg={error} />
      <ul>
        {items.map((i) => (
          <li key={i}>{i}</li>
        ))}
      </ul>
    </>
  );
}

describe("useList", () => {
  // ⚠️ Yükleniyor ile boş AYRI ekranlar olmalı. Eskiden değildi: veri
  // henüz gelmemişken "hiç kayıt yok" yazıyordu — bir yetkilendirme
  // panelinde bu, erişim hakkında YANLIŞ bir şey söylemek demek.
  it("yuklenirken bos-durum metnini GOSTERMEZ", async () => {
    let resolve!: (v: string[]) => void;
    render(<Probe load={() => new Promise<string[]>((r) => (resolve = r))} />);

    expect(screen.getByText("Loading…")).toBeInTheDocument();
    expect(screen.queryByText("NOTHING HERE")).not.toBeInTheDocument();

    resolve([]);
    await waitFor(() =>
      expect(screen.getByText("NOTHING HERE")).toBeInTheDocument(),
    );
    expect(screen.queryByText("Loading…")).not.toBeInTheDocument();
  });

  // Bir kez düşen istekten sonra ekranda kalan kırmızı satır, sonraki
  // BAŞARILI yüklemelerde de duruyordu.
  it("basarili yuklemede eski hatayi temizler", async () => {
    let call = 0;
    const load = () => {
      call++;
      return call === 1
        ? Promise.reject(new ApiError(500, "boom"))
        : Promise.resolve(["a"]);
    };

    const { rerender } = render(<Probe load={load} />);
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("boom"),
    );

    // Aynı kancayı yeni bir load ile yeniden kur: refresh tetiklenir.
    rerender(<Probe load={() => Promise.resolve(["a"])} />);
    await waitFor(() =>
      expect(screen.queryByRole("alert")).not.toBeInTheDocument(),
    );
  });

  // ⚠️ Burada window.location.reload() vardı ve SONSUZ DÖNGÜ riskiydi:
  // sameOrigin katmanı da 403 döndürüyor, yani yanlış yapılandırılmış
  // bir vekil arkasında sayfa yenilenip aynı 403'ü alıp yeniden
  // yenileniyordu — kullanıcının çıkamayacağı bir kısır döngü.
  it("403'te sayfayi YENILEMEZ, durumu anlatir", async () => {
    const reload = vi.fn();
    vi.stubGlobal("location", { ...window.location, reload });

    render(
      <Probe load={() => Promise.reject(new ApiError(403, "forbidden"))} />,
    );

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        /admin access was refused/i,
      ),
    );
    expect(reload).not.toHaveBeenCalled();
  });

  // Error OLMAYAN bir reddediş de görünür olmalı.
  it("Error olmayan reddedisi de gosterir", async () => {
    render(<Probe load={() => Promise.reject("düz dize")} />);
    await waitFor(() => {
      const alert = screen.getByRole("alert");
      expect(alert.textContent?.trim()).not.toBe("");
    });
  });
});

describe("ErrorLine", () => {
  it("bos mesajda hicbir sey cizmez", () => {
    const { container } = render(<ErrorLine msg="" />);
    expect(container).toBeEmptyDOMElement();
  });

  // Renk TEK BAŞINA sinyal olamaz: renk körü bir kullanıcı için
  // crimson ile green aynıdır. Stil sayfası ::before ile "Error:" öneki
  // koyuyor; burada rolün duyurulduğunu sabitliyoruz.
  it("ekran okuyucuya duyurulur", () => {
    render(<ErrorLine msg="bir şey oldu" />);
    expect(screen.getByRole("alert")).toHaveTextContent("bir şey oldu");
  });
});

describe("ActionButton", () => {
  // Onay yoktu: yanlış satırdaki "delete" tek tıkla bir kullanıcıyı
  // siliyordu.
  it("onay reddedilirse eylemi CALISTIRMAZ", async () => {
    const onClick = vi.fn();
    vi.stubGlobal(
      "confirm",
      vi.fn(() => false),
    );

    render(
      <ActionButton onClick={onClick} confirm="emin misin?">
        delete
      </ActionButton>,
    );
    await userEvent.click(screen.getByRole("button"));

    expect(onClick).not.toHaveBeenCalled();
  });

  it("onay verilirse calisir", async () => {
    const onClick = vi.fn();
    vi.stubGlobal(
      "confirm",
      vi.fn(() => true),
    );

    render(
      <ActionButton onClick={onClick} confirm="emin misin?">
        delete
      </ActionButton>,
    );
    await userEvent.click(screen.getByRole("button"));

    expect(onClick).toHaveBeenCalledTimes(1);
  });

  // ⚠️ Uçuş sırasında kilit yoktu: iki kez tıklanan "Create" 409 alıyor,
  // sunucu onu "already exists" diye gösteriyor ve kullanıcı BAŞARILI
  // olmuş bir işlem için hata görüyordu. Panelin hata mesajlarına
  // güvenmemeyi böyle öğreniyor.
  it("ucus sirasinda ikinci tiklamayi engeller", async () => {
    let resolve!: () => void;
    const onClick = vi.fn(() => new Promise<void>((r) => (resolve = r)));

    render(<ActionButton onClick={onClick}>create</ActionButton>);
    const btn = screen.getByRole("button");

    await userEvent.click(btn);
    expect(btn).toBeDisabled();

    await userEvent.click(btn).catch(() => {});
    expect(onClick).toHaveBeenCalledTimes(1);

    resolve();
    await waitFor(() => expect(btn).not.toBeDisabled());
  });

  it("erisilebilir ad tasir", () => {
    render(
      <ActionButton onClick={() => {}} label="delete user ayse">
        delete
      </ActionButton>,
    );
    expect(
      screen.getByRole("button", { name: "delete user ayse" }),
    ).toBeInTheDocument();
  });
});

/*
 * ⚠️ "ÇEKİLEMEDİ", "BOŞ" DEĞİLDİR — dosyanın kendi gerekçesinin
 * dördüncü hâli.
 *
 * Hata dalı yalnızca setError çağırıyordu; `items` boş kaldığı için
 * ListState onu `empty` sanıp OLUMLU bir cümle yazıyordu, kırmızı hata
 * satırının hemen altında. İkisinden hangisinin okunacağı belli: olumlu
 * cümle bir olgu gibi durur, hata satırı bir aksaklık gibi. Yükleniyor
 * ile boşu ayıran testin hemen yanında, çekilemeyen ile boş
 * ayrılmıyordu.
 */
it("istek dustugunde bos-durum metnini GOSTERMEZ", async () => {
  render(<Probe load={() => Promise.reject(new Error("database is down"))} />);

  await waitFor(() =>
    expect(screen.getByText(/database is down/i)).toBeInTheDocument(),
  );
  expect(screen.queryByText("NOTHING HERE")).not.toBeInTheDocument();
  expect(
    screen.getByText(/not a statement that\s+there is nothing here/i),
  ).toBeInTheDocument();
});

// 403 hâlâ kendi cümlesini alıyor: yetkinin reddi ile sorgunun
// çökmesi farklı şeyler ve farklı eylem gerektiriyor.
it("403 kendi cumlesini korur", async () => {
  render(<Probe load={() => Promise.reject(new ApiError(403, "forbidden"))} />);
  await waitFor(() =>
    expect(screen.getByText(/admin access was refused/i)).toBeInTheDocument(),
  );
  expect(screen.queryByText("NOTHING HERE")).not.toBeInTheDocument();
});
