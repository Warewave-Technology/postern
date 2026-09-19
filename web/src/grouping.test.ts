import { expect, it } from "vitest";
import { MyTarget } from "./api";
import { OTHER_APP, OTHER_ENV, appOf, envOf, groupTargets } from "./grouping";

const t = (name: string, labels: Record<string, string> = {}): MyTarget => ({
  name,
  labels,
});

/** shape, öbekleri okunur bir dizgeye indirger. */
const shape = (targets: MyTarget[]) =>
  (groupTargets(targets) ?? []).map(
    (a) =>
      `${a.app}: ` +
      a.envs
        .map((e) => `${e.env}[${e.targets.map((x) => x.name).join(",")}]`)
        .join(" "),
  );

/*
 * ⚠️ İKİ ANAHTAR ADI DA OKUNUYOR VE HARF DUYARSIZ.
 *
 * Yazımı yönetici seçmiyor: keşif, Proxmox ve vCenter etiketlerini
 * olduğu gibi alıyor. Harf duyarlı bir okuma, doğru etiketlenmiş bir
 * makineyi "label'ı yok" sayar ve yönetici neden gruplanmadığını
 * hiçbir yerden anlayamazdı.
 */
it("app ve env'i iki adla ve harf duyarsız okuyor", () => {
  expect(appOf(t("a", { app: "billing" }))).toBe("billing");
  expect(appOf(t("a", { application: "billing" }))).toBe("billing");
  expect(appOf(t("a", { APP: "billing" }))).toBe("billing");
  expect(envOf(t("a", { Environment: "prod" }))).toBe("prod");

  // Boş değer YOK sayılıyor: adı boş bir başlık üretirdi.
  expect(appOf(t("a", { app: "  " }))).toBe("");
  expect(envOf(t("a", {}))).toBe("");
});

/* app varsa env onun ALTINA giriyor — istenen asıl kırılım. */
it("app'in altında env'e göre kırıyor", () => {
  expect(
    shape([
      t("web-1", { app: "shop", env: "prod" }),
      t("web-2", { app: "shop", env: "test" }),
      t("db-1", { app: "shop", env: "prod" }),
    ]),
  ).toEqual(["shop: prod[db-1,web-1] test[web-2]"]);
});

/*
 * ⚠️ app'i OLMAYAN AMA env'i OLAN MAKİNE KAYBOLMUYOR. "Others" açılıyor
 * ve makine kendi env adının altında duruyor; env'i de yoksa "Other env"
 * altında. Bu ikisini tek bir çöp öbeğine atmak, ortamı yazılmış bir
 * makineyi hiç yazılmamış gibi gösterirdi.
 */
it("app'siz makineyi Others altında env adıyla tutuyor", () => {
  expect(
    shape([
      t("lonely", { env: "staging" }),
      t("bare"),
      t("shop-1", { app: "shop", env: "prod" }),
    ]),
  ).toEqual([
    "shop: prod[shop-1]",
    `${OTHER_APP}: staging[lonely] ${OTHER_ENV}[bare]`,
  ]);
});

/* app'i olup env'i olmayan da kendi app'inin altında "Other env"de. */
it("env'siz makine app'inin altında kalıyor", () => {
  expect(shape([t("x", { app: "shop" })])).toEqual([`shop: ${OTHER_ENV}[x]`]);
});

/*
 * ⚠️ "KALANLAR" HER ZAMAN EN SONDA. Alfabetik sıraya karışsaydı
 * "Others" bazen ortada, bazen başta çıkardı ve göz onu aramayı
 * öğrenemezdi.
 */
it("kalanları en sona koyuyor, gerisi alfabetik", () => {
  const got = shape([
    t("z", { app: "zebra", env: "prod" }),
    t("o", { env: "prod" }),
    t("a", { app: "alpha", env: "test" }),
    t("a2", { app: "alpha" }),
  ]);
  expect(got[0]).toMatch(/^alpha: /);
  expect(got[1]).toMatch(/^zebra: /);
  expect(got[2]).toMatch(new RegExp(`^${OTHER_APP}: `));
  // Env ekseninde de aynı kural: adı olan önce, kalan sonra.
  expect(got[0]).toBe(`alpha: test[a] ${OTHER_ENV}[a2]`);
});

/*
 * ⚠️ HİÇ LABEL YOKSA GRUPLAMA HİÇ ÇİZİLMİYOR (null).
 *
 * Tek bir "Others → Other env" başlığının altında her şeyi göstermek,
 * düz ızgaradan daha kötü: iki satır gürültü ekliyor ve hiçbir şey
 * ayırmıyor. Çağıran null görünce eski düzeni çiziyor.
 */
it("hiç app ve env yoksa gruplamıyor", () => {
  expect(groupTargets([t("a"), t("b", { owner: "ops" })])).toBeNull();
});

/* Tek bir env bile gruplamayı başlatıyor: app şart değil. */
it("tek başına env gruplamayı başlatıyor", () => {
  expect(groupTargets([t("a"), t("b", { env: "prod" })])).not.toBeNull();
});

/* Sayaç başlıkta yazılıyor: alt öbeklerin toplamı olmalı. */
it("app sayacı bütün ortamları topluyor", () => {
  const groups = groupTargets([
    t("a", { app: "shop", env: "prod" }),
    t("b", { app: "shop", env: "test" }),
    t("c", { app: "shop" }),
  ]);
  expect(groups?.[0].count).toBe(3);
});
