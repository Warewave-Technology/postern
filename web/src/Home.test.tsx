import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import Home from "./Home";
import { api, type Me, type MyTarget } from "./api";

const me: Me = {
  name: "ayse",
  os_user: "ayse",
  admin: false,
  targets: [],
  terminal_enabled: true,
  files_enabled: true,
  files_write_enabled: false,
  public_key_login: true,
};

const t = (name: string, labels: Record<string, string> = {}): MyTarget => ({
  name,
  labels,
});

const show = (targets: MyTarget[]) => {
  vi.spyOn(api, "myTargets").mockResolvedValue(targets);

  return render(<Home me={me} />);
};

/*
 * headings, ekrandaki öbek başlıklarını sırayla verir.
 *
 * ⚠️ BÜYÜK HARF BEKLENMİYOR. Ortam adı ekranda büyük harfle görünüyor
 * ama bu yalnızca CSS (text-transform); DOM'da label'ın kendi yazımı
 * duruyor ve testin ölçtüğü şey o olmalı — aksi hâlde bir stil
 * değişikliği, davranışı ölçen bir testi düşürürdü.
 */
const headings = () =>
  Array.from(document.querySelectorAll(".tgroup-head, .tgroup-env-head")).map(
    (h) =>
      Array.from(h.querySelectorAll("span"))
        .map((x) => (x.textContent ?? "").trim())
        .join(" ")
        .trim(),
  );

beforeEach(() => vi.restoreAllMocks());

/*
 * ⚠️ ASIL KIRILIM: app, ALTINDA env.
 *
 * Bir filoda "hangi makineye bağlanacağım" sorusu neredeyse hiç
 * alfabetik bir listeyle cevaplanmıyor; önce hangi uygulama, sonra
 * hangi ortam diye soruluyor. Ekran o sırayı taşımalı.
 */
it("app başlığının altında env'e göre kırıyor", async () => {
  show([
    t("web-2", { app: "shop", env: "test" }),
    t("web-1", { app: "shop", env: "prod" }),
  ]);

  await screen.findByText("web-1");
  expect(headings()).toEqual(["shop 2 machines", "prod", "test"]);
});

/*
 * ⚠️ app'i OLMAYAN AMA env'i OLAN MAKİNE KAYBOLMUYOR. "Others" açılıyor
 * ve makine kendi env adının altında duruyor; ikisi de yoksa "Other env"
 * altında. Kalanlar HER ZAMAN en sonda: alfabetik sıraya karışsalardı
 * göz onları aramayı öğrenemezdi.
 */
it("app'siz makineyi Others altında env adıyla gösteriyor", async () => {
  show([
    t("lonely", { env: "staging" }),
    t("bare"),
    t("shop-1", { app: "shop", env: "prod" }),
  ]);

  await screen.findByText("lonely");
  expect(headings()).toEqual([
    "shop 1 machine",
    "prod",
    "Others 2 machines",
    "staging",
    "Other env",
  ]);
});

/*
 * ⚠️ HİÇ LABEL YOKSA GRUPLAMA HİÇ ÇİZİLMİYOR.
 *
 * Tek bir "Others → Other env" başlığının altında her şeyi göstermek,
 * düz ızgaradan daha kötü: iki satır gürültü ekliyor ve hiçbir şey
 * ayırmıyor. Gruplama ilk app ya da env label'ı geldiğinde kendiliğinden
 * başlıyor.
 */
it("label yokken düz ızgara kalıyor", async () => {
  show([t("a"), t("b", { owner: "ops" })]);

  await screen.findByText("a");
  expect(headings()).toEqual([]);
  expect(document.querySelectorAll(".card-grid")).toHaveLength(1);
});

/*
 * ⚠️ ÖNCE SÜZ, SONRA GRUPLA. Tersi, aramanın boşalttığı bir başlığı
 * ekranda bırakırdı: "shop" yazan bir öbek altında hiç kart olmadan
 * durur ve okuyan onu bir arıza sanardı.
 */
it("arama boşalttığı öbeği de kaldırıyor", async () => {
  show([
    t("shop-1", { app: "shop", env: "prod" }),
    t("mail-1", { app: "mail", env: "prod" }),
  ]);
  await screen.findByText("shop-1");

  await userEvent.type(screen.getByRole("searchbox"), "shop");

  await waitFor(() => expect(screen.queryByText("mail-1")).toBeNull());
  expect(headings()).toEqual(["shop 1 machine", "prod"]);
});
