import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import Modal from "./Modal";

describe("modal", () => {
  /*
   * ⚠️ İKİ MODAL AYNI SAYFADA OLABİLİYOR.
   *
   * Profil sayfasında hem anahtar ekleme hem kimlik doğrulayıcı
   * kurulumu var. Başlık kimliği sabit ("modal-title") olsaydı, ikisi
   * kapalı olsa bile — kapalı bir <dialog> çocuklarını DOM'da tutuyor —
   * aynı id iki kez var olurdu ve ekran okuyucu aria-labelledby'ı ilk
   * eşleşmeye bağlayıp ikinci modalı YANLIŞ başlıkla duyururdu.
   */
  it("iki modal ayrı başlık kimliği alıyor", () => {
    const { container } = render(
      <>
        <Modal open title="Add an SSH key" onClose={() => {}}>
          <p>bir</p>
        </Modal>
        <Modal open title="Set up an authenticator" onClose={() => {}}>
          <p>iki</p>
        </Modal>
      </>,
    );
    const ids = [...container.querySelectorAll("dialog")].map((d) =>
      d.getAttribute("aria-labelledby"),
    );
    expect(ids[0]).toBeTruthy();
    expect(ids[1]).toBeTruthy();
    expect(ids[0]).not.toBe(ids[1]);

    // Ve her biri KENDİ başlığını gösteriyor.
    for (const id of ids) {
      expect(container.querySelector(`#${CSS.escape(id!)}`)).toBeTruthy();
    }
    expect(
      container.querySelector(`#${CSS.escape(ids[0]!)}`)!.textContent,
    ).toBe("Add an SSH key");
    expect(
      container.querySelector(`#${CSS.escape(ids[1]!)}`)!.textContent,
    ).toBe("Set up an authenticator");
  });

  // Kapatma düğmesi durumu üzerinden kapatıyor: DOM'u doğrudan
  // kapatmak, `open` true kalırken dialog'u kapatıp ikisini
  // ayrıştırırdı (Modal.tsx'teki gerekçe).
  it("kapatma düğmesi onClose çağırıyor", async () => {
    const onClose = vi.fn();
    render(
      <Modal open title="Add an SSH key" onClose={onClose}>
        <p>içerik</p>
      </Modal>,
    );
    await userEvent.click(
      screen.getByRole("button", { name: /close this dialog/i }),
    );
    expect(onClose).toHaveBeenCalled();
  });
});
