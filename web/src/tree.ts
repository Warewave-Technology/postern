/**
 * Hedefteki bir dizin ağacının gezilmesi.
 *
 * ⚠️ AYRI DOSYADA VE İSTEMCİDEN BAĞIMSIZ: gezgin yalnızca `readdir`
 * isteyen bir arayüz alıyor. Buradaki iddiaların hepsi ("bağ izlenmiyor",
 * "tavan aşılınca duruluyor", "kardeş adları tekilleştiriliyor") bir
 * websocket ya da çizim olmadan ölçülebiliyor.
 *
 * ⚠️ GEZİNMENİN BİR DENETİM MALİYETİ VAR ve tavanın sebebi o — ama
 * MEKANİZMA İLK YAZDIĞIM GİBİ DEĞİL, ölçüm onu çürüttü.
 *
 * Ölçülen maliyet: dizin başına BİR satır (opendir), indirilen dosya
 * başına İKİ satır (open + transfer) ve aynı sayıda satır oturumun
 * .cast kaydına. readdir, read ve stat hiçbir şey yazmıyor. Oran bir
 * testle sabitlendi — değişirse test düşüyor, buradaki gerekçe sessizce
 * yanlış kalmıyor (test/integration/sftppanel_test.go,
 * TestFetchingAFolderCostsOneRowPerDirectoryAndTwoPerFile).
 *
 * "journalCap (10000) aşılırsa oturum ölür" diye yazmıştım; yanlıştı.
 * O tavan oturumun TOPLAMINI değil, HENÜZ YAZILAMAMIŞ BİRİKİMİ
 * sınırlıyor ve birikim iki saniyede bir boşalıyor (sftpjournal.go
 * flushEvery). Yani "şu kadar girdiden sonra oturum ölür" diye bir sayı
 * yok; risk bir ORAN — bir boşaltma penceresine 10000 satır sığdıran
 * bir hız, ya da tek bir aktarımda satır satır INSERT eden bir
 * boşaltmanın 10 saniyelik zaman aşımına çarpması.
 *
 * Tavan yine de duruyor, çünkü bağladığı başka şeyler gerçek: arşivin
 * boyu, indirmenin süresi, denetim tablosunun ve kaydın büyümesi, ve
 * oturum ayrıntısı sayfasının okunabilirliği (dosya listesi
 * sayfalanmıyor). Sıralı kuyruk da hızı kendiliğinden sınırlıyor: her
 * dosya için gidiş-dönüş bekleniyor.
 */

import { Halted, type Entry, type Origin, type Stopper } from "./sftp";
import { joinPath } from "./files";
import { safeName, uniqueName } from "./zip";
import { maxDownloadBytes } from "./transfer";

const S_IFMT = 0o170000;
const S_IFREG = 0o100000;

/**
 * maxTreeEntries, tek bir indirmede İNCELENECEK girdi sayısı.
 *
 * ⚠️ İNCELENEN, ARŞİVE GİREN DEĞİL. İlk hâli yalnızca alınan dosya ve
 * dizinleri sayıyordu; atlananlar (bağlar, aygıtlar, reddedilen
 * dizinler) sayaca hiç girmiyordu. Oysa reddedilen her DİZİN defterde
 * kendi satırını bırakıyor ve atlanan her girdi arşivin içindeki nota
 * aday oluyor — yani bir milyon bağ taşıyan bir dizin, "hiçbir şey
 * indirilmedi" derken hem defteri hem belleği şişirebiliyordu. Tek bir
 * sayı, incelenen her şeyi sayınca anlatması da kolaylaşıyor.
 */
export const maxTreeEntries = 4000;

/**
 * maxPathBytes, bir girdinin hedefteki yol uzunluğu tavanı.
 *
 * ⚠️ ESKİ GEREKÇE ARTIK GEÇERLİ DEĞİL — VE BURADA DURMASI YANILTIRDI.
 * Bu tavan, uzun bir yolun denetim satırını ZEHİRLEMESİNE karşı
 * konmuştu: session_files.path btree indeksli, PostgreSQL girdiyi 2704
 * baytta reddediyor ve sunucu yolu 4096 bayta kadar saklıyordu; aradaki
 * bir yol INSERT'i düşürüyor, oturumu öldürüyor ve tamponun başına geri
 * konarak sonraki her boşaltmayı da düşürüyordu. Arıza SUNUCUDA
 * kapatıldı (sftpaudit yolu 2692 bayta indiriyor ve kestiğini
 * işaretliyor) — zaten orada kapatılması gerekiyordu, çünkü sıradan bir
 * SSH istemcisi aynı yolu bu panelden geçmeden üretebiliyor.
 *
 * TAVAN YİNE DURUYOR ama iddiası artık daha küçük: sunucunun sınırının
 * ALTINDA kalarak, panelin indirdiği bir dosyanın defterde KESİLMEMİŞ
 * bir yolla durmasını garanti ediyor. Denetçinin gördüğü yol, indirilen
 * dosyanın tam yolu.
 */
export const maxPathBytes = 2000;

/**
 * noteName, arşivin içine konan "eksikler" dosyasının adı.
 *
 * ⚠️ AD GEZGİN TARAFINDAN ÖNCEDEN AYRILIYOR. Aksi hâlde hedefte aynı
 * adla bir dosya açan biri, o adı KENDİSİ kapıyor ve postern'in gerçek
 * notu "… (2).txt" oluyordu: denetçi bariz adı açıp saldırganın
 * güvence metnini okurdu.
 */
export const noteName = "POSTERN-NOT-INCLUDED.txt";

/**
 * maxTreeDepth, inilecek en derin seviye.
 *
 * ⚠️ SONSUZ DERİNLİK GERÇEK. Bağları izlemiyoruz, ama hedefte bind-mount
 * ya da /proc gibi kendini tekrar eden ağaçlar var; birinde derinlik
 * tavanı olmadan gezinmek, tarayıcıyı tavan sayaca çarpana kadar
 * döndürür ve o sırada defteri doldurur.
 */
export const maxTreeDepth = 32;

/** TreeFile, arşive girecek tek dosya. */
export interface TreeFile {
  /** Hedefteki mutlak yol — indirme isteği bunu taşıyor. */
  path: string;
  /** Arşivin içindeki yol. */
  rel: string;
  size: number;
  mtime: number;
  mode: number;
}

/** TreeDir, arşive girecek dizin girdisi. */
export interface TreeDir {
  rel: string;
  mtime: number;
  mode: number;
}

/**
 * Reason, bir gerekçe ve onu KİMİN yazdığı.
 *
 * ⚠️ KÖKEN AYRI BİR ALAN, cümlenin içine gömülü değil. Notun okuru
 * "bunu postern mi reddetti yoksa hedef mi hata mı verdi" sorusunu
 * soruyor ve iki cevabın sonucu farklı: ilki bir kural, ikincisi bir
 * arıza. Ayrımı metinden okumaya çalışmak, ayrımı hedefe yazdırmak
 * demekti (bkz. sftp.ts, Origin).
 */
export interface Reason {
  why: string;
  from: Origin;
}

/** Skipped, arşive GİRMEYEN bir şey ve sebebi. */
export interface Skipped extends Reason {
  /** Hedefteki yol — kullanıcı neyin eksik olduğunu görebilmeli. */
  path: string;
}

export interface Tree {
  files: TreeFile[];
  dirs: TreeDir[];
  /** Atlananlar — en fazla maxNoted tanesi yazılıyor. */
  skipped: Skipped[];
  /** Yazılmayan atlama sayısı (bkz. maxNoted). */
  skippedMore: number;
  /** Dosyaların toplam boyu. */
  bytes: number;
}

/**
 * maxNoted, arşivin içindeki nota yazılacak atlama sayısı.
 *
 * ⚠️ ATLANANLAR DA SINIRSIZ OLAMAZ. Bağlar ve aygıt dosyaları tavan
 * SAYACINA girmiyor (defterde satır bırakmıyorlar), yani hedefte bir
 * milyon bağ açan biri notu bir milyon satır yapabilirdi — hem belleği
 * hem arşivin içindeki metni. Sayı yine tam veriliyor, listesi kırpılıyor.
 */
export const maxNoted = 200;

/** Lister, gezginin istemciden ihtiyaç duyduğu tek şey. */
export interface Lister {
  readdir(path: string, signal?: Stopper): Promise<Entry[]>;
}

/**
 * tooManyEntries ve tooLarge, tavana çarpan bir indirmenin cümlesi.
 *
 * ⚠️ YARIM ARŞİV VERİLMİYOR, REDDEDİLİYOR. Tavana kadar indirip
 * "tamamlandı" demek, kullanıcıya eksik olduğunu göremeyeceği bir arşiv
 * vermek olurdu — ve bu üründe sessiz eksiklik, hata vermekten kötü.
 * Cümle ne yapılacağını da söylüyor.
 */
export function tooManyEntries(): string {
  return (
    `this folder holds more than ${maxTreeEntries.toLocaleString("en")} entries — ` +
    `more than the panel fetches in one go, because every one of them lands in ` +
    `the session's file journal and in its recording. Pick a subfolder, or use ` +
    `an SFTP client for the whole tree`
  );
}

export function tooLarge(): string {
  return (
    "this folder holds more than 2 GiB — more than the browser can assemble " +
    "into one archive; use an SFTP client for it"
  );
}

/**
 * walkTree, bir dizini özyineli olarak gezer ve arşive girecekleri döner.
 *
 * ⚠️ BAĞLAR İZLENMİYOR ve bu üç şeyi birden kapatıyor:
 *
 *   1. DÖNGÜ. "guncel -> ." gibi bir bağ, izleyen bir gezginde sonsuz
 *      döngü demek; hedefin sahibi bunu bir dizin açıp bir bağ kurarak
 *      üretebiliyor.
 *   2. SEÇİLEN AĞACIN DIŞI. "/tmp/is/veri -> /etc" bağını izlemek,
 *      kullanıcının /tmp/is'i indirdiğini sanarken /etc'yi indirmesi
 *      olurdu. Yol politikası her yolu yine görüyor (yani bu bir
 *      güvenlik açığı değil), ama NİYET ile yapılan iş ayrışırdı.
 *   3. AYNI DOSYANIN İKİ KEZ. Bir ağaçtaki bağlar, arşivi olduğundan
 *      kat kat büyütebiliyor.
 *
 * Atlanan her bağ SAYILIYOR ve kullanıcıya söyleniyor: sessizce eksik
 * bir arşiv, reddedilen bir indirmeden kötü.
 */
export async function walkTree(
  c: Lister,
  root: string,
  explain: (e: unknown) => Reason,
  opts: {
    onSeen?: (seen: number) => void;
    signal?: Stopper;
  } = {},
): Promise<Tree> {
  const base = safeName(root.split("/").filter(Boolean).pop() ?? "download");
  const out: Tree = {
    files: [],
    dirs: [],
    skipped: [],
    skippedMore: 0,
    bytes: 0,
  };
  let seen = 0;

  const note = (s: Skipped) => {
    if (out.skipped.length < maxNoted) out.skipped.push(s);
    else out.skippedMore++;
  };

  const step = () => {
    if (opts.signal?.aborted) throw new Halted();
    seen++;
    if (seen > maxTreeEntries) throw new Error(tooManyEntries());
    opts.onSeen?.(seen);
  };

  async function descend(
    dir: string,
    rel: string,
    depth: number,
    meta: { mtime: number; mode: number },
    seed?: string[],
  ) {
    let list: Entry[];
    try {
      list = await c.readdir(dir, opts.signal);
    } catch (e) {
      /*
       * ⚠️ DURDURMA BİR "OKUNAMADI" DEĞİL. Listeleme artık durdurma
       * sinyalini de taşıyor, yani Halted BURADAN da gelebiliyor;
       * aşağıdaki nota çevirmek, kullanıcının bastığı Stop'u arşivin
       * içinde "bu dizin okunamadı" diye kaydetmek olurdu — ve gezinti
       * bir sonraki girdiye kadar devam ederdi.
       */
      if (e instanceof Halted) throw e;

      /*
       * ⚠️ OKUNAMAYAN DİZİN GEZİNTİYİ BİTİRMİYOR. Bir ağaçta izin
       * verilmeyen tek bir alt dizin yüzünden bütün indirmeyi
       * reddetmek, çalışan bir şeyi çalışmaz yapardı; eksik olduğu
       * kullanıcıya arşivin içinde de yazılıyor.
       */
      note({ path: dir, ...explain(e) });
      return;
    }

    /*
     * ⚠️ DİZİN GİRDİSİ ANCAK LİSTELEME BAŞARIRSA YAZILIYOR — ve bu,
     * canlı denemede çıktı. Girdi listelemeden ÖNCE ekleniyordu, yani
     * yol politikasının reddettiği bir dizin (demoda /home/sidinak/.ssh)
     * arşivde BOŞ BİR KLASÖR olarak duruyordu. Arşivi altı ay sonra açan
     * denetçi için "reddedildi" ile "içi boştu" aynı şeye benziyor —
     * oysa biri kanıt, diğeri bilgi. Reddedilen dizin artık yalnızca
     * atlananlar notunda görünüyor.
     */
    out.dirs.push({ rel, mtime: meta.mtime, mode: meta.mode });

    const taken = new Set<string>();
    // Kökte postern'in kendi notunun adı ÖNCE ayrılıyor (bkz. noteName).
    for (const name of seed ?? []) uniqueName(taken, name);

    for (const e of list) {
      /*
       * ⚠️ "." VE ".." ATLANMAK ZORUNDA. Gerçek bir sftp-server bunları
       * READDIR sonucunda GÖNDERİYOR (OpenSSH gönderiyor) ve ".."
       * içine inmek, gezginin ağacın dışına çıkıp sonsuza kadar
       * dönmesi demek. Özyineli gezinmede yazılan ilk hata bu.
       */
      if (e.name === "." || e.name === "..") continue;

      /*
       * ⚠️ TAVAN İNCELENEN HER GİRDİYİ SAYIYOR — atlananları da. Bir
       * milyon bağ taşıyan bir dizin hiçbir dosya vermez ama defteri,
       * belleği ve notu yine şişirir.
       */
      step();

      const path = joinPath(dir, e.name);

      if (utf8Len(path) > maxPathBytes) {
        note({
          path: `${dir}/…`,
          why: "its path is too long to record",
          from: "postern",
        });
        continue;
      }

      if (e.isLink) {
        note({
          path,
          why: "symbolic link — postern does not follow links when it fetches a folder",
          from: "postern",
        });
        continue;
      }

      if (e.isDir) {
        if (depth + 1 > maxTreeDepth) {
          note({
            path,
            why: `nested deeper than ${maxTreeDepth} levels`,
            from: "postern",
          });
          continue;
        }
        const name = uniqueName(taken, safeName(e.name));
        await descend(
          path,
          `${rel}/${name}`,
          depth + 1,
          { mtime: e.mtime, mode: e.mode },
        );
        continue;
      }

      /*
       * ⚠️ DÜZENLİ DOSYA OLDUĞU KANITLANMALI — "değil olduğu
       * kanıtlanmadıkça düzenli" DEĞİL. İlk hâli kipi sıfır olan bir
       * girdiyi dosya sayıyordu, "hedef tip göndermemiş olabilir"
       * gerekçesiyle. Ama tip bilgisini gönderip göndermemeyi HEDEF
       * seçiyor: ATTRS'ın izin bayrağını kapatan bir sunucu, bir
       * sembolik bağı bu kapıdan düzenli dosya diye geçirebilirdi — ve
       * "bağları izlemiyoruz" kuralı, tam da onu delmek isteyenin
       * elinde tek bir bit ile düşerdi. Panelde tek bir dosyaya
       * tıklamak kullanıcının kendi kararı; burada dosyaları kullanıcı
       * TEK TEK SEÇMİYOR, o yüzden ölçü daha sıkı olmak zorunda.
       *
       * FIFO ve aygıtlar da buradan eleniyor: bir FIFO'yu açıp okumak
       * yazan biri çıkana kadar BLOKLUYOR ve sıralı kuyrukta bu, bütün
       * indirmenin asılı kalması demek.
       */
      if ((e.mode & S_IFMT) !== S_IFREG) {
        note({
          path,
          why:
            e.mode === 0
              ? "the target did not say what kind of entry this is"
              : "not a regular file",
          from: "postern",
        });
        continue;
      }

      out.bytes += e.size;
      if (out.bytes > maxDownloadBytes) throw new Error(tooLarge());

      const name = uniqueName(taken, safeName(e.name));
      out.files.push({
        path,
        rel: `${rel}/${name}`,
        size: e.size,
        mtime: e.mtime,
        mode: e.mode,
      });
    }
  }

  step();
  await descend(root, base, 1, { mtime: 0, mode: 0o040755 }, [noteName]);

  return out;
}

/**
 * plain, nota yazılacak metni tek satıra ve yazdırılabilire indirger.
 *
 * ⚠️ BU METNİ HEDEF YAZIYOR ve not bir metin dosyası: birileri onu
 * `cat` ile açacak. İçindeki bir ESC dizisi terminali boyar, bir satır
 * sonu da sahte bir "Could not be read:" başlığı uydurmasına yeter —
 * yani hedef, notun KENDİ satırlarını yazabilirdi. Kayda giren metinle
 * aynı gerekçe (internal/proxy/sftpcast.go, castSafe).
 */
export function plain(s: string): string {
  let out = "";
  for (const r of s) {
    const c = r.codePointAt(0) ?? 0;
    if (c < 0x20 || c === 0x7f || (c >= 0x80 && c <= 0x9f)) continue;
    if (
      c === 0x200e ||
      c === 0x200f ||
      (c >= 0x202a && c <= 0x202e) ||
      (c >= 0x2066 && c <= 0x2069)
    ) {
      continue;
    }
    if (out.length >= 512) return out + "…";
    out += r;
  }

  return out;
}

/** utf8Len, bir dizgenin UTF-8 bayt uzunluğu. */
function utf8Len(s: string): number {
  // Hızlı yol: ASCII'de uzunluk zaten bayt sayısı.
  if (s.length <= maxPathBytes / 4) return s.length;

  return new TextEncoder().encode(s).length;
}

/**
 * quote, bir gerekçeyi konuşanıyla birlikte yazar.
 *
 * ⚠️ DAMGA HER İKİ YÖNDE DE AÇIK. postern'in satırını işaretsiz
 * bırakıp "işaretsiz olan bizimdir" demek, hedefe boş bir alan
 * bırakırdı: kendi metnini işaretsiz gibi göstermek için hiçbir şey
 * yapması gerekmezdi.
 */
function quote(s: Reason): string {
  const who = s.from === "target" ? "the target said: " : "postern: ";

  return who + plain(s.why);
}

/**
 * skipNote, atlananları arşivin içine konacak metne çevirir.
 *
 * ⚠️ NOT ARŞİVİN İÇİNE GİRİYOR, YALNIZCA EKRANA DEĞİL. Panel kapandıktan
 * sonra elde kalan tek şey arşiv; "şunlar eksik" bilgisi ekranda kalırsa,
 * altı ay sonra o arşive bakan denetçi tam bir kopyaya baktığını sanar.
 */
export function skipNote(root: string, t: Tree, failed: Skipped[]): string {
  const lines = [
    `postern did not put everything under ${root} into this archive.`,
    "",
    /*
     * ⚠️ HER SEBEP KİMİN YAZDIĞIYLA BİRLİKTE GİRİYOR.
     *
     * Bu satırlar eskiden yalnızca "bir kısmını hedef yazıyor, ayırt
     * edemiyoruz" diyordu ve doğruydu: istemci postern'in retlerini
     * "postern: " önekinden tanıyordu, o öneki de hedef yazabiliyordu.
     * Ayrım artık metinden değil akış etiketinden geliyor (sftp.ts,
     * Origin), yani burada söylenebilecek şey değişti — nota bakan
     * denetçi her satırda konuşanı görüyor.
     *
     * ⚠️ ALINTININ KENDİSİ HÂLÂ HEDEFİN METNİ. Damgayı postern yazıyor,
     * sonrası alıntı; hedefin kendi yazdığı bir damga da alıntının
     * İÇİNDE kalıyor.
     */
    "Each reason below says who produced it: \"postern:\" is this bastion's",
    "own refusal, \"the target said:\" quotes text the target wrote. The",
    "session's file journal records the same split.",
    "",
  ];

  if (t.skipped.length > 0) {
    lines.push("Skipped while listing the folder:");
    for (const s of t.skipped) lines.push(`  ${plain(s.path)}: ${quote(s)}`);
    // Liste kırpıldıysa SAYI yine veriliyor: kırpılmış bir liste,
    // kırpıldığını söylemezse eksiksiz sanılır.
    if (t.skippedMore > 0) {
      lines.push(`  … and ${t.skippedMore} more, not listed here`);
    }
    lines.push("");
  }

  if (failed.length > 0) {
    lines.push("Could not be read:");
    for (const s of failed) lines.push(`  ${plain(s.path)}: ${quote(s)}`);
    lines.push("");
  }

  /*
   * ⚠️ NOTUN SONU BİR ZAMANLAR FAZLASINI İDDİA EDİYORDU: "geri kalan her
   * şey eksiksiz okundu" ve "her dosyanın defterde bir satırı var".
   * İkisini de bu kod kanıtlayamıyor — birincisi teslim edilen baytın
   * doğrulanmasına, ikincisi ise sunucunun defteri yazabilmiş olmasına
   * bağlı, ve defter dolduğunda olayı SESSİZCE düşürebiliyor. Kanıtı
   * arşivin içinde taşımayan bir cümle, arşivin kendisi hakkında
   * hak edilmemiş bir onay.
   */
  lines.push(
    "The rest of the archive is what the target returned for each of these",
    "paths, fetched through the same audited path as any SSH client. Whether",
    "the session's journal recorded every one of them is a question for",
    "`postern session verify` and the session's own page, not for this file.",
  );

  return lines.join("\n");
}
