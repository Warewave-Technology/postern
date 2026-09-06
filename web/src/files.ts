/**
 * Dosya tarayıcısının saf yardımcıları.
 *
 * Ayrı bir dosyada, çünkü hepsi bileşenden bağımsız test edilebiliyor:
 * yol birleştirme ve kip çözme, jsdom'un çizim yapmasını beklemeye
 * değmeyecek kadar kendi başına doğru ya da yanlış.
 */

import type { Entry } from "./sftp";

/**
 * joinPath, bir dizinle bir adı birleştirir.
 *
 * ⚠️ ".." BURADA ÇÖZÜLMÜYOR ve bu kasıtlı: hedefin dosya sisteminde
 * sembolik bağlar var ve ".."in nereye çıktığını yalnızca hedef bilir.
 * Yukarı çıkmak için ayrı bir yol var (parentPath) ve o da sunucuya
 * MUTLAK bir yol soruyor — politikanın da gördüğü yol o.
 */
export function joinPath(dir: string, name: string): string {
  if (dir.endsWith("/")) return dir + name;
  return dir + "/" + name;
}

/** parentPath, bir yolun üst dizini. Kökün üstü yine köktür. */
export function parentPath(p: string): string {
  if (p === "/" || p === "") return "/";
  const trimmed = p.endsWith("/") ? p.slice(0, -1) : p;
  const i = trimmed.lastIndexOf("/");
  if (i <= 0) return "/";
  return trimmed.slice(0, i);
}

/**
 * crumbs, yol çubuğunun parçaları.
 *
 * Her parça, ORAYA KADARKİ mutlak yolu taşıyor: kullanıcı "/var" a
 * tıkladığında sunucuya sorulan şey "/var" oluyor, göreli bir sıçrama
 * değil.
 */
export function crumbs(p: string): { label: string; path: string }[] {
  const out = [{ label: "/", path: "/" }];
  let acc = "";
  for (const part of p.split("/")) {
    if (part === "") continue;
    acc += "/" + part;
    out.push({ label: part, path: acc });
  }
  return out;
}

/**
 * sortEntries, dizinleri önce, sonra adı sıralar.
 *
 * ⚠️ SIRALAMA YERİNDE DEĞİL: gelen dizi çözümleyicinin tamponundan
 * geliyor ve onu değiştirmek, aynı listeyi bir daha okuyan birine
 * karışmış veri verirdi.
 */
export function sortEntries(list: Entry[]): Entry[] {
  return [...list].sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    return a.name.localeCompare(b.name, undefined, { numeric: true });
  });
}

/** hidden, nokta ile başlayan girdi. */
export function hidden(e: Entry): boolean {
  return e.name.startsWith(".");
}

/**
 * formatSize, baytı okunur hale getirir.
 *
 * ⚠️ 1024'LÜK BASAMAK ve birimler KiB/MiB: dosya boyutu için sistem
 * araçlarının (ls -h, du -h) kullandığı basamak bu, ve panelde farklı
 * bir sayı göstermek "hangisi doğru" sorusunu doğurur.
 */
export function formatSize(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB", "PiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

const S_IFMT = 0o170000;

/** formatMode, kipi `ls -l` biçimine çevirir. */
export function formatMode(mode: number): string {
  const type =
    {
      0o040000: "d",
      0o120000: "l",
      0o100000: "-",
      0o010000: "p",
      0o140000: "s",
    }[mode & S_IFMT] ?? "?";

  let out = type;
  for (let shift = 6; shift >= 0; shift -= 3) {
    const bits = (mode >> shift) & 0o7;
    out += bits & 4 ? "r" : "-";
    out += bits & 2 ? "w" : "-";
    out += bits & 1 ? "x" : "-";
  }
  return out;
}

/**
 * formatTime, unix saniyesini okunur tarihe çevirir.
 *
 * ⚠️ SIFIR "tarih yok" DEMEK, 1970 değil. Hedefin ATTRS'ında zaman
 * bayrağı kapalı olabiliyor ve o hâlde alan hiç gelmiyor; "1 Jan 1970"
 * yazmak, olmayan bir bilgiyi varmış gibi göstermek olurdu.
 */
export function formatTime(unix: number): string {
  if (!unix) return "—";
  const d = new Date(unix * 1000);
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
