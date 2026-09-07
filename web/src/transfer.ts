/**
 * Aktarım kuyruğu: durumlar, ilerleme ve sıraya koyma.
 *
 * Bileşenden AYRI ve saf, çünkü buradaki iddiaların hiçbiri çizime bağlı
 * değil: "yarım kalan aktarım tamamlandı görünmemeli", "bir aktarımın
 * hatası kuyruğu durdurmamalı", "yüzde bilinmiyorsa uydurulmamalı". Bunlar
 * jsdom'un yerleşim yapmasını beklemeye değmeyecek kadar kendi başına
 * doğru ya da yanlış.
 */

export type Direction = "up" | "down";

export type TransferState =
  "queued" | "running" | "done" | "failed" | "cancelled";

export interface Transfer {
  id: number;
  dir: Direction;
  /** Kullanıcının gördüğü ad. */
  name: string;
  /** Hedefteki mutlak yol. */
  remotePath: string;
  state: TransferState;
  /** Taşınan bayt. */
  done: number;
  /** Toplam bayt; bilinmiyorsa undefined. */
  total?: number;
  /** Başarısızlık sebebi — kullanıcıya gösterilecek cümle. */
  error?: string;
}

/**
 * percent, ilerleme yüzdesi.
 *
 * ⚠️ TOPLAM BİLİNMİYORSA undefined DÖNÜYOR, sıfır değil. Bilinmeyen
 * boyutu %0 diye çizmek, çubuğu hiç ilerlemiyormuş gibi gösterir ve
 * kullanıcı aktarımın takıldığını sanar. Bilinmiyorsa çubuk yerine
 * taşınan bayt yazılmalı.
 */
export function percent(t: Transfer): number | undefined {
  if (t.total === undefined || t.total <= 0) return undefined;

  return Math.min(100, Math.round((t.done / t.total) * 100));
}

/**
 * isSettled, aktarımın bittiği (artık değişmeyeceği).
 *
 * ⚠️ "done" DEĞİL "settled": başarısız ve iptal edilmiş de bitmiştir.
 * Yalnızca "done"a bakan bir arayüz, düşen bir aktarımı sonsuza kadar
 * "sürüyor" gösterir.
 */
export function isSettled(t: Transfer): boolean {
  return t.state === "done" || t.state === "failed" || t.state === "cancelled";
}

/** summarise, kuyruğun tek satırlık özeti. */
export function summarise(list: Transfer[]): {
  running: number;
  done: number;
  failed: number;
  /** Kuyruğun tamamı için yüzde; hiçbirinin boyutu bilinmiyorsa undefined. */
  percent?: number;
} {
  let running = 0;
  let done = 0;
  let failed = 0;
  let sumDone = 0;
  let sumTotal = 0;
  let known = false;

  for (const t of list) {
    if (t.state === "running" || t.state === "queued") running++;
    if (t.state === "done") done++;
    if (t.state === "failed") failed++;

    if (t.total !== undefined && t.total > 0) {
      known = true;
      sumTotal += t.total;
      sumDone += Math.min(t.done, t.total);
    }
  }

  return {
    running,
    done,
    failed,
    percent: known
      ? Math.min(100, Math.round((sumDone / sumTotal) * 100))
      : undefined,
  };
}

/**
 * joinRemote, hedefteki dizinle dosya adını birleştirir.
 *
 * ⚠️ ADIN İÇİNDEKİ EĞİK ÇİZGİ ATILIYOR. Yerel taraftan gelen ad, sürükle
 * bırakılan bir klasörün içindeki göreli yol olabilir ("a/b/c.txt") ya da
 * kötü niyetli olabilir ("../../etc/passwd"). Hedefteki yolu istemcinin
 * uydurmasına izin vermek, yol politikasının gördüğü yolu istemcinin
 * seçmesi demek — politika o yolu yine kontrol eder, ama kullanıcının
 * NİYET ETTİĞİ yer ile yazılan yer ayrışır.
 *
 * Yani burada yapılan şey güvenlik değil (o sunucuda), DÜRÜSTLÜK:
 * yüklenen dosya, kullanıcının baktığı dizine gidiyor.
 */
export function joinRemote(dir: string, name: string): string {
  const leaf = name.split("/").pop() ?? name;
  const safe = leaf.replace(/\0/g, "");
  if (dir.endsWith("/")) return dir + safe;

  return dir + "/" + safe;
}

/**
 * nextId, kuyruk için artan kimlik üreteci.
 *
 * Modül düzeyinde tutuluyor: React'in yeniden çizimleri arasında da
 * benzersiz kalmalı, yoksa iki aktarım aynı satırı paylaşır.
 */
let counter = 0;
export function nextId(): number {
  counter += 1;

  return counter;
}

/** resetIds, testler için. */
export function resetIds() {
  counter = 0;
}

/**
 * maxDownloadBytes, tarayıcıya indirilebilecek en büyük dosya.
 *
 * ⚠️ BİR SINIR SEÇMEK ZORUNLUYDU ve seçilmemiş olması ertelemenin
 * sebebiydi. İndirilen parçalar bir Blob'da toplanıyor; tarayıcı bunu
 * gerektiğinde diske taşıyor ama sınırsız değil, ve sınıra çarpan bir
 * sekme SESSİZCE ölüyor — kullanıcı yarım dosyayla kalıyor ve sebebini
 * göremiyor.
 *
 * 2 GiB, tarayıcıların pratikte taşıyabildiği büyüklüğün altında ve bir
 * bastion üzerinden geçmesi makul olanın üstünde. Sınırı aşan dosya için
 * doğru araç gerçek bir SFTP istemcisi ve mesaj bunu söylüyor.
 */
export const maxDownloadBytes = 2 * 1024 * 1024 * 1024;

/** tooLargeToDownload, boyut sınırının cümlesi. */
export function tooLargeToDownload(size: number): string | null {
  if (size <= maxDownloadBytes) return null;

  return (
    "this file is larger than the browser can hold (over 2 GiB) — " +
    "use an SFTP client for it"
  );
}
