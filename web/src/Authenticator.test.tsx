import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Authenticator from "./Authenticator";
import { api, type TOTPStatus } from "./api";

const status = (over: Partial<TOTPStatus> = {}): TOTPStatus => ({
  enrolled: false,
  pending: false,
  can_begin: true,
  needs_fresh_login: true,
  ...over,
});

beforeEach(() => vi.restoreAllMocks());

/*
 * Bu ekranın var olma sebebi: ikinci anahtar eklemek yeniden doğrulama
 * istiyor ve postern yalnızca YEREL parolayı doğrulayabiliyordu — yani
 * dizinden gelen hesaplara verilen cevap "yöneticine sor" idi.
 */
describe("kimlik doğrulayıcı", () => {
  it("SSO hesabında sır sormuyor: sorulacak bir sır yok", async () => {
    vi.spyOn(api, "totpStatus").mockResolvedValue(status());
    render(<Authenticator />);

    await userEvent.click(
      await screen.findByRole("button", {
        name: /set up an authenticator app/i,
      }),
    );
    // Parola kutusu ÇİZİLMEMELİ: bu hesabın postern'de parolası yok ve
    // boş bir kutu, kullanıcıyı asla geçemeyeceği bir alana bakmaya
    // zorlardı.
    expect(screen.queryByLabelText(/sign-in secret/i)).toBeNull();
    expect(screen.getByRole("button", { name: /continue/i })).toBeEnabled();
  });

  /*
   * ⚠️ REDDİN SEBEBİ YAZMALI.
   *
   * Sebebi söylemeyen bir ret kullanıcıya "bozuk" gibi görünür ve onu
   * yöneticiye gönderir — bu ekranın kaldırmak için var olduğu şeyin
   * ta kendisi.
   */
  it("bayat oturumda sebebini söylüyor, boş bir form göstermiyor", async () => {
    vi.spyOn(api, "totpStatus").mockResolvedValue(
      status({ can_begin: false, needs_fresh_login: true }),
    );
    render(<Authenticator />);

    expect(
      await screen.findByText(/sign in again and come back/i),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /set up an authenticator app/i }),
    ).toBeNull();
  });

  /*
   * ⚠️ KURULUM MODALDA. Kart yalnızca durumu ve düğmeyi taşıyor;
   * QR ile kod alanı karta gömülüyken kartı üç katına çıkarıyor ve
   * "ikinci faktörüm var mı" sorusunun cevabını yığının altında
   * bırakıyordu.
   */
  it("kurulum anahtarını okunur biçimde ve yalnızca kayıt sonrası gösteriyor", async () => {
    vi.spyOn(api, "totpStatus").mockResolvedValue(status());
    vi.spyOn(api, "totpBegin").mockResolvedValue({
      secret: "ABCDEFGHIJKLMNOP",
      uri: "otpauth://totp/postern:yigit?secret=ABCDEFGHIJKLMNOP",
      qr: ["101", "010", "101"],
    });
    render(<Authenticator />);

    // Kayıt başlamadan sır ORTADA OLMAMALI.
    expect(screen.queryByText(/ABCD EFGH/)).toBeNull();

    await userEvent.click(
      await screen.findByRole("button", {
        name: /set up an authenticator app/i,
      }),
    );
    await userEvent.click(screen.getByRole("button", { name: /continue/i }));

    /*
     * ⚠️ DÖRTLÜ GRUPLAR. Kullanıcı bunu telefona ELLE geçiriyor (QR
     * yok); kesintisiz 32 karakterlik bir base32 değeri gözle doğru
     * okumak mümkün değil ve yanlış geçiren kişi hatayı ancak kodları
     * hiç tutmayınca fark eder.
     */
    expect(await screen.findByText("ABCD EFGH IJKL MNOP")).toBeInTheDocument();

    /*
     * ⚠️ QR NORMAL YOL, ELLE GİRİŞ YEDEK — ikisi de olmalı. Yalnızca
     * QR gösteren bir ekran, kamerasız bir masaüstünden kurulum yapan
     * kullanıcıyı çıkmazda bırakır; yalnızca metin gösteren ekran ise
     * herkesi 32 karakter yazmaya zorlar.
     */
    expect(
      screen.getByRole("img", { name: /scan it with your authenticator/i }),
    ).toBeInTheDocument();
  });

  /*
   * ⚠️ KAPATMAK KOD İSTİYOR.
   *
   * İstemeseydi, oturumu çalan biri faktörü kapatıp yerine kendininkini
   * bağlardı — yani faktör, onu atlatmak isteyen için engel olmaktan
   * çıkardı.
   */
  it("kapatmak için kod istiyor", async () => {
    vi.spyOn(api, "totpStatus").mockResolvedValue(status({ enrolled: true }));
    const off = vi.spyOn(api, "totpDisable").mockResolvedValue(undefined);
    render(<Authenticator />);

    await userEvent.click(
      await screen.findByRole("button", {
        name: /turn off the authenticator on this account/i,
      }),
    );
    // Onay düğmesi kod girilmeden ÇALIŞMAMALI.
    const confirm = screen.getByRole("button", { name: /confirm/i });
    expect(confirm).toBeDisabled();
    expect(off).not.toHaveBeenCalled();

    await userEvent.type(screen.getByLabelText(/current code/i), "123456");
    await userEvent.click(confirm);
    expect(off).toHaveBeenCalledWith("123456");
  });
});

/*
 * ⚠️ KURULUM VE KAPATMA MODALDA, KARTTA DEĞİL.
 *
 * QR, kurulum anahtarı ve kod alanı karta gömülüyken kartı üç katına
 * çıkarıyordu ve "ikinci faktörüm var mı" sorusunun cevabı o yığının
 * altında kayboluyordu. İkisi de ara sıra yapılan eylemler.
 *
 * ⚠️ VARLIK DEĞİL AÇIKLIK sınanıyor: kapalı bir <dialog> çocuklarını
 * DOM'da tutuyor ve jsdom onu gizlemiyor.
 */
describe("kurulum modali", () => {
  it("düğmeye basılana kadar kapalı", async () => {
    vi.spyOn(api, "totpStatus").mockResolvedValue(status());
    const { container } = render(<Authenticator />);
    await screen.findByRole("button", { name: /set up an authenticator app/i });

    const dialog = container.querySelector("dialog")!;
    expect(dialog.open).toBe(false);

    await userEvent.click(
      screen.getByRole("button", { name: /set up an authenticator app/i }),
    );
    expect(dialog.open).toBe(true);
  });

  // Kapatma da kendi modalında: kartın üstünde kalıcı bir kod kutusu,
  // kapatmayı yanlışlıkla yapılabilir bir şeye çevirirdi.
  it("kapatma ayrı modalda ve kapalı başlıyor", async () => {
    vi.spyOn(api, "totpStatus").mockResolvedValue(status({ enrolled: true }));
    const { container } = render(<Authenticator />);
    await screen.findByRole("button", {
      name: /turn off the authenticator on this account/i,
    });

    const dialog = container.querySelector("dialog")!;
    expect(dialog.open).toBe(false);
    await userEvent.click(
      screen.getByRole("button", {
        name: /turn off the authenticator on this account/i,
      }),
    );
    expect(dialog.open).toBe(true);
  });

  /*
   * ⚠️ KAYIT BAŞLATILAMIYORSA MODAL HİÇ ÇİZİLMİYOR — sebebi kartta
   * yazıyor. Kapalı bir dialog'un içinde erişilemez bir form
   * bırakmanın anlamı yok.
   */
  it("bayat oturumda modal yok, sebep kartta", async () => {
    vi.spyOn(api, "totpStatus").mockResolvedValue(
      status({ can_begin: false, needs_fresh_login: true }),
    );
    const { container } = render(<Authenticator />);
    expect(
      await screen.findByText(/sign in again and come back/i),
    ).toBeTruthy();
    expect(container.querySelector("dialog")).toBeNull();
  });
});
