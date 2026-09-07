/**
 * Tarayıcıdaki YEREL dosyalara erişim.
 *
 * ⚠️ BU DOSYA BİR TARAYICI KISITININ ETRAFINDA KURULU ve kısıt ölçüldü,
 * varsayılmadı.
 *
 * "Sol taraf senin bilgisayarın" diye CANLI bir yerel dosya gezgini
 * yalnızca File System Access API ile yazılabiliyor (showDirectoryPicker).
 * O API Safari'de YOK — ve bu bir gecikme değil: WebKit'in kendi
 * standards-positions deposunda teklif "oppose" ile, "concerns: security"
 * gerekçesiyle 2023'te kapatılmış. Firefox'ta da yok. Yani destek
 * Chromium'a özgü.
 *
 * Her tarayıcıda çalışan şey daha dar ve tek yönlü:
 *   - <input type="file" webkitdirectory> ile klasör seçmek (macOS Safari
 *     11.1+; iOS'ta öznitelik sessizce ETKİSİZ),
 *   - sürükle bırakılan klasörü webkitGetAsEntry ile gezmek,
 *   - File.stream()/slice() ile büyük dosyayı belleğe almadan okumak.
 *
 * Hiçbirinde KALICI tutamak ya da yerel diske geri yazma yok. Bu yüzden
 * yerel taraf bir GEZGİN değil, bir TEPSİ: kullanıcı dosya/klasör seçiyor
 * ya da bırakıyor, seçtikleri listede duruyor. İndirme ise tarayıcının
 * kendi indirme klasörüne gidiyor — yeri seçtiremiyoruz.
 *
 * Aynı ekranı her tarayıcıda göstermenin sebebi bu: Chromium'da gerçek
 * gezgin çizip Safari'de başka bir şey göstermek, aynı ürünü iki farklı
 * ürün yapardı ve "bende neden öyle değil" sorusunu doğururdu.
 */

/** LocalFile, yerelden seçilmiş tek dosya. */
export interface LocalFile {
  /** Gösterilecek ad. Klasör seçildiyse klasör içi göreli yol. */
  name: string;
  size: number;
  file: File;
}

/**
 * fromFileList, bir <input> ya da bırakma olayından gelen dosyaları alır.
 *
 * ⚠️ webkitRelativePath TERCİH EDİLİYOR: klasör seçildiğinde ad tek
 * başına ("x.txt") aynı adı taşıyan iki dosyayı ayırt edilemez kılardı.
 * Göreli yol listede görünüyor; hedefe yazılırken yalnızca yaprak ad
 * kullanılıyor (transfer.joinRemote).
 */
export function fromFileList(files: FileList | File[]): LocalFile[] {
  const out: LocalFile[] = [];
  for (const f of Array.from(files)) {
    const rel = (f as File & { webkitRelativePath?: string })
      .webkitRelativePath;
    out.push({ name: rel && rel !== "" ? rel : f.name, size: f.size, file: f });
  }

  return out;
}

/**
 * fromDataTransfer, sürükle-bırak olayından dosyaları çıkarır.
 *
 * ⚠️ KLASÖR BIRAKMAK DESTEKLENİYOR ve bu, DataTransferItem.webkitGetAsEntry
 * ile yapılıyor (Safari 11.1+). Modern muadili getAsFileSystemHandle
 * Safari'de YOK, o yüzden eski Entries API kullanılıyor.
 *
 * ⚠️ readEntries DÖNGÜYLE ÇAĞRILIYOR. Tek çağrı dizinin TAMAMINI
 * döndürmüyor — çağrı başına sınırlı sayıda girdi veriyor ve boş dizi
 * gelene kadar tekrar çağrılması gerekiyor. Tek çağrıyla yetinen kod
 * büyük klasörlerde SESSİZCE eksik liste üretir; küçüklerde çalıştığı
 * için de fark edilmez.
 */
export async function fromDataTransfer(dt: DataTransfer): Promise<LocalFile[]> {
  const entries: FileSystemEntry[] = [];
  for (const item of Array.from(dt.items)) {
    if (item.kind !== "file") continue;
    const e = item.webkitGetAsEntry?.();
    if (e) entries.push(e);
  }

  // Klasör desteği yoksa düz dosya listesine düş.
  if (entries.length === 0) return fromFileList(dt.files);

  const out: LocalFile[] = [];
  for (const e of entries) await walkEntry(e, "", out);

  return out;
}

async function walkEntry(
  entry: FileSystemEntry,
  prefix: string,
  out: LocalFile[],
): Promise<void> {
  if (entry.isFile) {
    const f = await new Promise<File | null>((resolve) => {
      (entry as FileSystemFileEntry).file(
        (file) => resolve(file),
        () => resolve(null),
      );
    });
    if (f) out.push({ name: prefix + f.name, size: f.size, file: f });

    return;
  }

  if (!entry.isDirectory) return;

  const reader = (entry as FileSystemDirectoryEntry).createReader();
  for (;;) {
    const batch = await new Promise<FileSystemEntry[]>((resolve) => {
      reader.readEntries(
        (items) => resolve(items),
        () => resolve([]),
      );
    });
    if (batch.length === 0) break;
    for (const child of batch) {
      await walkEntry(child, prefix + entry.name + "/", out);
    }
  }
}

/**
 * readInChunks, bir dosyayı parça parça okuyan üretici döner.
 *
 * ⚠️ TAMAMI BELLEĞE ALINMIYOR. File diskteki dosyaya tembel bir referans;
 * slice + arrayBuffer ile parça parça okumak 1 GB'lık bir dosyayı belleğe
 * getirmiyor. (File.stream() de var ama slice her yerde çalışıyor ve
 * konumu bizim kontrol etmemizi sağlıyor.)
 */
export function readInChunks(
  file: File,
  chunk: number,
): () => Promise<Uint8Array | null> {
  let at = 0;

  return async () => {
    if (at >= file.size) return null;
    const end = Math.min(at + chunk, file.size);
    const buf = await file.slice(at, end).arrayBuffer();
    at = end;

    return new Uint8Array(buf);
  };
}

/**
 * saveBlob, indirilen parçaları kullanıcının indirme klasörüne yazar.
 *
 * ⚠️ YERİNİ SEÇTİREMİYORUZ. showSaveFilePicker Safari'de ve Firefox'ta
 * yok; her yerde çalışan tek yol, bir nesne URL'i ve `download` özniteliği
 * taşıyan bir bağlantıya tıklamak. Dosya tarayıcının indirme klasörüne
 * gidiyor ve adı çakışırsa tarayıcı kendi yeniden adlandırıyor.
 *
 * ⚠️ URL SERBEST BIRAKILIYOR. Bırakılmazsa Blob sekme kapanana kadar
 * bellekte kalıyor; birkaç yüz megabaytlık birkaç indirme, sekmeyi
 * şişirmeye yeter.
 */
export function saveBlob(parts: BlobPart[], name: string, type?: string) {
  const blob = new Blob(parts, type ? { type } : undefined);
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();

  // Tıklama eşzamanlı başlıyor ama indirme URL'i hemen okumuyor;
  // ölçülen pratik: bir sonraki tikte serbest bırakmak güvenli.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/**
 * hasDirectoryPicker, tarayıcının GERÇEK bir yerel gezgin kurmasına izin
 * verip vermediği.
 *
 * Bugün yalnızca arayüzün doğru cümleyi yazması için kullanılıyor:
 * kullanıcıya "klasörünü seç" demek ile "klasörünü sürükle" demek farklı
 * şeyler ve yanlışını yazmak, olmayan bir düğmeyi aratır.
 */
export function hasDirectoryPicker(): boolean {
  return (
    typeof (window as { showDirectoryPicker?: unknown }).showDirectoryPicker ===
    "function"
  );
}
