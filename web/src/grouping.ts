import { MyTarget } from "./api";

/**
 * Ana ekrandaki hedefleri app ve env label'larına göre öbekler.
 *
 * ⚠️ KARAR SAF, ÇİZİM AYRI. Bu dosyada React yok: "hangi makine hangi
 * başlığın altına düşer" sorusu render etmeden, tablo testiyle
 * kanıtlanabilsin diye. Aynı ayrım hostacct ve policy'de de var ve
 * orada kararın doğruluğunu tartışmak yerine ÖLÇMEYİ mümkün kıldı.
 */

/** Başlıksız kalanların öbekleri. */
export const OTHER_APP = "Others";
export const OTHER_ENV = "Other env";

/** EnvGroup, bir app'in altındaki tek bir ortam. */
export type EnvGroup = {
  env: string;
  /** true ise bu öbek "env'i olmayanlar" — adı bir label'dan gelmiyor. */
  other: boolean;
  targets: MyTarget[];
};

/** AppGroup, bir uygulamanın bütün ortamları. */
export type AppGroup = {
  app: string;
  /** true ise bu öbek "app'i olmayanlar". */
  other: boolean;
  envs: EnvGroup[];
  count: number;
};

/*
 * labelOf, label'ı ANAHTAR ADINI HARF DUYARSIZ arayarak okur.
 *
 * ⚠️ YAZIMI YÖNETİCİ SEÇMİYOR. Keşif, Proxmox ve vCenter etiketlerini
 * olduğu gibi alıyor; "App", "ENV", "Environment" hepsi gerçek hayatta
 * görülen yazımlar. Harf duyarlı bir okuma, doğru etiketlenmiş bir
 * makineyi "label'ı yok" sayardı ve yönetici neden gruplanmadığını
 * hiçbir yerden anlayamazdı.
 *
 * Boş değer YOK sayılıyor: "env=" yazan bir etiket, adı boş bir başlık
 * üretirdi.
 */
function labelOf(t: MyTarget, names: string[]): string {
  for (const want of names) {
    for (const [k, v] of Object.entries(t.labels)) {
      if (k.toLowerCase() !== want) continue;
      const value = v.trim();
      if (value !== "") return value;
    }
  }

  return "";
}

/** appOf, hedefin uygulaması; yoksa boş. */
export function appOf(t: MyTarget): string {
  // Sıra önemli: ikisi birden yazılıysa kısa olan kazanıyor, çünkü
  // "application" genelde uzun yazmayı sevenin ikinci tercihi.
  return labelOf(t, ["app", "application"]);
}

/** envOf, hedefin ortamı; yoksa boş. */
export function envOf(t: MyTarget): string {
  return labelOf(t, ["env", "environment"]);
}

/*
 * byName, başlıkları harf duyarsız alfabetik sıralar ve "kalanlar"
 * öbeğini EN SONA atar.
 *
 * ⚠️ localeCompare KULLANILMIYOR. Sonucu tarayıcının yereline bağlı ve
 * aynı fikstür iki makinede iki sıra üretebilirdi; sıralamayı ölçen bir
 * test o zaman "bazen" geçerdi.
 */
function byName<T extends { other: boolean }>(
  key: (x: T) => string,
): (a: T, b: T) => number {
  return (a, b) => {
    if (a.other !== b.other) return a.other ? 1 : -1;
    const x = key(a).toLowerCase();
    const y = key(b).toLowerCase();
    if (x !== y) return x < y ? -1 : 1;

    return key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0;
  };
}

/*
 * groupTargets, hedefleri app → env hiyerarşisine yerleştirir.
 *
 * ⚠️ HİÇ LABEL YOKSA null DÖNÜYOR, BOŞ HİYERARŞİ DEĞİL. Tek bir
 * "Others → Other env" başlığının altında her şeyi göstermek, bugünkü
 * düz ızgaradan daha kötü: iki satır gürültü ekliyor ve hiçbir şey
 * ayırmıyor. Çağıran null görünce eski düzeni çiziyor ve gruplama, ilk
 * app ya da env label'ı geldiğinde kendiliğinden başlıyor.
 */
export function groupTargets(targets: MyTarget[]): AppGroup[] | null {
  if (!targets.some((t) => appOf(t) !== "" || envOf(t) !== "")) return null;

  const apps = new Map<string, Map<string, MyTarget[]>>();
  for (const t of targets) {
    const app = appOf(t) || OTHER_APP;
    const env = envOf(t) || OTHER_ENV;
    const envs = apps.get(app) ?? new Map<string, MyTarget[]>();
    envs.set(env, [...(envs.get(env) ?? []), t]);
    apps.set(app, envs);
  }

  const out: AppGroup[] = [];
  for (const [app, envs] of apps) {
    const groups: EnvGroup[] = [];
    for (const [env, list] of envs) {
      groups.push({
        env,
        other: env === OTHER_ENV,
        targets: [...list].sort((a, b) => (a.name < b.name ? -1 : 1)),
      });
    }
    groups.sort(byName((g) => g.env));
    out.push({
      app,
      other: app === OTHER_APP,
      envs: groups,
      count: groups.reduce((n, g) => n + g.targets.length, 0),
    });
  }
  out.sort(byName((g) => g.app));

  return out;
}
