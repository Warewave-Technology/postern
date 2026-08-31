import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ChangePassword from "./ChangePassword";
import { api } from "./api";

beforeEach(() => vi.restoreAllMocks());

describe("zorunlu parola değişikliği", () => {
  /*
   * ⚠️ MEVCUT DEĞER İSTENİYOR.
   *
   * Bu ekranın göründüğü an, tam olarak değerin İKİ kişinin elinde
   * olduğu an: yönetici onu üretti ve iletti. Mevcut değer sorulmasaydı,
   * onu gören herkes tek istekle hesabı kalıcı olarak alırdı — yani
   * zorunlu değişiklik, devralmayı zorlaştırmak yerine kolaylaştırırdı.
   */
  it("mevcut değer olmadan gönderilemiyor", async () => {
    render(<ChangePassword name="ayse" onDone={() => {}} />);

    await userEvent.type(
      screen.getByLabelText("New password"),
      "kirmizi-bisiklet-42",
    );
    await userEvent.type(
      screen.getByLabelText("New password again"),
      "kirmizi-bisiklet-42",
    );

    expect(
      screen.getByRole("button", { name: /set password and continue/i }),
    ).toHaveProperty("disabled", true);
  });

  // İki kutu tutmuyorsa gönderilmiyor: hatırlamadığı bir parolayı
  // koyan kişi, bir sonraki girişte dışarıda kalır.
  it("iki kutu tutmuyorsa gönderilemiyor ve sebebi yazıyor", async () => {
    render(<ChangePassword name="ayse" onDone={() => {}} />);

    await userEvent.type(screen.getByLabelText(/current sign-in/i), "ESKI");
    await userEvent.type(
      screen.getByLabelText("New password"),
      "kirmizi-bisiklet-42",
    );
    await userEvent.type(
      screen.getByLabelText("New password again"),
      "kirmizi-bisiklet-43",
    );

    expect(screen.getByText(/do not match/i)).toBeTruthy();
    expect(
      screen.getByRole("button", { name: /set password and continue/i }),
    ).toHaveProperty("disabled", true);
  });

  /*
   * ⚠️ KURAL SUNUCUDAN GELİYOR.
   *
   * Politikayı ekrana kopyalamak bir güvenlik kontrolünün ikinci
   * kopyası olurdu ve iki kopyadan biri er ya da geç geride kalır:
   * kullanıcı "12 karakter" yazan bir ekrana bakarken sunucu 16
   * isterdi.
   */
  it("uzunluk kuralını sunucunun söylediği değerden yazıyor", async () => {
    render(
      <ChangePassword
        name="ayse"
        policy={{ min_length: 16, max_length: 256, min_distinct: 5 }}
        onDone={() => {}}
      />,
    );
    expect(
      screen.getAllByText(/at least 16 characters/i).length,
    ).toBeGreaterThan(0);
  });

  it("başarıyla değiştirince çağıranı bilgilendiriyor", async () => {
    const change = vi
      .spyOn(api, "changePassword")
      .mockResolvedValue({ ok: true });
    const onDone = vi.fn();

    render(<ChangePassword name="ayse" onDone={onDone} />);
    await userEvent.type(
      screen.getByLabelText(/current sign-in/i),
      "ESKI-DEGER",
    );
    await userEvent.type(
      screen.getByLabelText("New password"),
      "kirmizi-bisiklet-42",
    );
    await userEvent.type(
      screen.getByLabelText("New password again"),
      "kirmizi-bisiklet-42",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /set password and continue/i }),
    );

    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(change).toHaveBeenCalledWith("ESKI-DEGER", "kirmizi-bisiklet-42");
  });

  // Sunucunun reddi EKRANDA görünmeli: politika sunucuda uygulanıyor ve
  // "neden olmadı" sorusunun tek cevabı o metin.
  it("sunucunun politika reddini olduğu gibi gösteriyor", async () => {
    vi.spyOn(api, "changePassword").mockRejectedValue(
      new Error(
        "password does not meet the policy: it must not contain your username",
      ),
    );

    render(<ChangePassword name="ayse" onDone={() => {}} />);
    await userEvent.type(screen.getByLabelText(/current sign-in/i), "ESKI");
    await userEvent.type(
      screen.getByLabelText("New password"),
      "ayse-ayse-ayse",
    );
    await userEvent.type(
      screen.getByLabelText("New password again"),
      "ayse-ayse-ayse",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /set password and continue/i }),
    );

    await waitFor(() =>
      expect(screen.getByText(/must not contain your username/i)).toBeTruthy(),
    );
  });
});
