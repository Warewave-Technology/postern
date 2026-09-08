/**
 * ZIP yazıcısı — tarayıcıda, elle.
 *
 * ⚠️ NİYE ELLE. Bir dizini indirmek kullanıcıya TEK dosya vermek zorunda
 * (tarayıcı çoklu indirmeyi engelliyor ve yeri seçtiremiyoruz), yani bir
 * arşiv biçimi gerekiyordu. Hazır bir kütüphane almak, web/ tarafına
 * ilk çalışma-zamanı bağımlılığını sokmak demekti: NOTICES dosyası,
 * lisans takibi ve `make notices-check` bunun bedelini her sürümde
 * ödetiyor. Depoda zaten kendi SFTP çözümleyicimiz var; store-only bir
 * zip ondan küçük.
 *
 * ⚠️ SIKIŞTIRMA YOK (yöntem 0) ve bu bilinçli. Deflate arşivi küçültürdü
 * ama bir yanlış hesaplanmış CRC ya da boyut alanı, AÇILABİLEN ama
 * eksik bir arşiv üretir — sessiz bozulma, hata vermekten kötü. Yöntem
 * alanı burada değişken; sıkıştırma sonradan eklenecekse yeri belli.
 *
 * ⚠️ ZIP64 YOK ve gerekmiyor: arşivin tamamı transfer.maxDownloadBytes
 * (2 GiB) ile sınırlı, yani 32 bitlik boyut ve konum alanları taşmıyor.
 * Taşarsa yazıcı DURUYOR (bkz. addFile) — sessizce sarmalanmış bir konum,
 * açıldığında çöp veren bir arşiv demek.
 */

const localSig = 0x04034b50;
const centralSig = 0x02014b50;
const eocdSig = 0x06054b50;

// Sabit bölümlerin boyu: yerel başlık, merkezî dizin girdisi, son kayıt.
const localHeader = 30;
const centralHeader = 46;
const eocdSize = 22;

/**
 * utf8Flag, genel amaç bayrağının 11. biti.
 *
 * ⚠️ OLMAZSA WINDOWS ADI BOZUYOR. Bit yoksa açan taraf adı CP437
 * varsayıyor; hedefteki "günlükler" klasörü Windows'ta "gÃ¼nlÃ¼kler"
 * olarak çıkıyor. Adlar zaten UTF-8 yazılıyor, bayrak onu SÖYLÜYOR.
 */
const utf8Flag = 0x0800;

/** madeBy, "UNIX, spec 2.0" — dış öznitelikteki kip bunsuz okunmuyor. */
const madeBy = 0x031e;
const needed = 20;

/** dosDirBit, MS-DOS dizin özniteliği (dizin girdileri için). */
const dosDirBit = 0x10;

/**
 * maxEntries ve maxArchiveBytes, ZIP64'süz biçimin kendi sınırları.
 *
 * ⚠️ SINIRA ÇARPMAK HATA VERMELİ, SARMALAMA DEĞİL. u16 girdi sayacı ve
 * u32 konum alanları taşarsa arşiv yine "yazılıyor" ama açıldığında
 * yanlış yerden okunuyor. Aktarımın kendi tavanları bunların çok
 * altında; bunlar biçimin son savunması.
 */
export const maxEntries = 0xffff;
export const maxArchiveBytes = 0xffffffff;

const crcTable = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[i] = c >>> 0;
  }
  return t;
})();

/**
 * crc32, parça parça hesaplanabilen CRC-32 (zip'in istediği polinom).
 *
 * ⚠️ ÖNCEKİ DEĞERLE ÇAĞRILABİLİYOR: dosya belleğe alınmadan, parçalar
 * geldikçe hesaplanıyor. Tamamını toplayıp sonra hesaplamak, 2 GiB'lık
 * bir dosyayı JavaScript yığınına getirmek olurdu.
 */
export function crc32(chunk: Uint8Array, prev = 0): number {
  let c = (prev ^ 0xffffffff) >>> 0;
  for (let i = 0; i < chunk.length; i++) {
    c = (crcTable[(c ^ chunk[i]) & 0xff] ^ (c >>> 8)) >>> 0;
  }

  return (c ^ 0xffffffff) >>> 0;
}

/**
 * dosStamp, unix saniyesini MS-DOS tarih/saat çiftine çevirir.
 *
 * ⚠️ 1980 ÖNCESİ YOK. Biçim yılı 1980'den sayıyor; hedefteki bir dosyanın
 * mtime'ı 0 olabiliyor (ATTRS'ta zaman bayrağı kapalı) ve o hâlde
 * çıkarılan sarmalama 2043 gibi bir tarih verirdi. Taban ve tavan
 * KIRPILIYOR: yanlış bir tarih, belli bir tabandan kötü.
 */
export function dosStamp(unix: number): { time: number; date: number } {
  const d = new Date((unix > 0 ? unix : Date.now() / 1000) * 1000);
  const year = d.getFullYear();

  /*
   * ⚠️ SINIR DIŞINDA KALAN TARİH TÜMÜYLE DEĞİŞTİRİLİYOR, YALNIZCA YILI
   * DEĞİL. İlk hâli yılı kırpıp ay/gün/saati olduğu gibi bırakıyordu:
   * 1970'ten gelen bir zaman damgası "1 Ocak 1980, 02:00" oluyordu —
   * saat nereden geldiği belirsiz bir kalıntı. Taban ve tavan artık
   * kendi başına anlamlı: gün ve saat de tabanın kendisi.
   */
  if (year < 1980) return { date: (1 << 5) | 1, time: 0 };
  if (year > 2107) return { date: ((2107 - 1980) << 9) | (12 << 5) | 31, time: 0 };

  return {
    date: ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
  };
}

/** ZipMeta, bir girdinin arşivdeki kimliği. */
export interface ZipMeta {
  /** Arşivin içindeki yol. Bileşenleri zaten temizlenmiş olmalı (safePath). */
  path: string;
  /** Unix saniyesi; 0 ise "bilinmiyor". */
  mtime: number;
  /** Unix kipi (izinler). 0 ise makul bir varsayılan yazılıyor. */
  mode: number;
}

interface Central extends ZipMeta {
  crc: number;
  size: number;
  offset: number;
  dir: boolean;
}

class Bytes {
  private b: number[] = [];

  u16(v: number) {
    this.b.push(v & 0xff, (v >>> 8) & 0xff);
  }

  u32(v: number) {
    this.b.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
  }

  raw(x: Uint8Array) {
    for (const v of x) this.b.push(v);
  }

  /*
   * Dönüş tipi AÇIKÇA Uint8Array<ArrayBuffer>: TypeScript 5.7'den beri
   * Uint8Array tamponuna göre genelleşti ve süslenmemiş hâli
   * SharedArrayBuffer'ı da kapsıyor — Blob onu kabul etmiyor.
   */
  done(): Uint8Array<ArrayBuffer> {
    return new Uint8Array(this.b);
  }
}

/**
 * ZipWriter, girdileri sırayla yazıp sonunda arşivi döner.
 *
 * ⚠️ GÖVDELER Blob OLARAK TUTULUYOR, Uint8Array OLARAK DEĞİL. Tarayıcı
 * bir Blob'u gerektiğinde diske taşıyabiliyor; JavaScript dizisi
 * taşıyamıyor. Bir dosya bittiği anda parçalarını Blob'a çevirmek,
 * arşivin TAMAMININ yığında birikmesini engelliyor — 200 dosyalık bir
 * ağaçta fark, sekmenin yaşayıp yaşamaması oluyor.
 */
export class ZipWriter {
  private parts: BlobPart[] = [];
  private central: Central[] = [];
  private offset = 0;
  /** Merkezî dizinin şu ana kadarki boyu — tavan hesabına giriyor. */
  private centralBytes = 0;

  /** count, şu ana kadar yazılan girdi sayısı. */
  get count(): number {
    return this.central.length;
  }

  /** bytes, şu ana kadar yazılan bayt. */
  get bytes(): number {
    return this.offset;
  }

  /**
   * addFile, gövdesi hazır bir dosyayı arşive koyar.
   *
   * CRC ve boyut ÖNCEDEN biliniyor (çağıran parçalar geldikçe
   * hesaplıyor), o yüzden yerel başlık tam yazılıyor.
   *
   * ⚠️ VERİ TANIMLAYICISI (bayrak 3) KULLANILMIYOR. Akış hâlinde yazan
   * araçlar boyutu sonda bildiriyor; ama sıkıştırmasız bir girdide bu,
   * verinin nerede bittiğini sırayla okuyan çözücülere BIRAKMAK demek —
   * bazı araçlarda çalışmıyor. Dosyayı önce bitirip sonra yazmak bu
   * belirsizliği hiç doğurmuyor.
   */
  addFile(meta: ZipMeta, body: BlobPart[], size: number, crc: number) {
    const name = new TextEncoder().encode(meta.path);
    this.guard(localHeader + name.length + size, name.length);

    const h = new Bytes();
    h.u32(localSig);
    h.u16(needed);
    h.u16(utf8Flag);
    h.u16(0); // yöntem: store
    const { time, date } = dosStamp(meta.mtime);
    h.u16(time);
    h.u16(date);
    h.u32(crc);
    h.u32(size);
    h.u32(size);
    h.u16(name.length);
    h.u16(0); // ek alan yok
    h.raw(name);

    const head = h.done();
    this.central.push({
      ...meta,
      crc,
      size,
      offset: this.offset,
      dir: false,
    });
    this.parts.push(head, new Blob(body));
    this.offset += head.length + size;
  }

  /**
   * addDirectory, boş bir dizin girdisi yazar.
   *
   * ⚠️ BOŞ DİZİNLER KAYBOLMAMALI. Zip'te dizin, yalnızca içindeki
   * dosyaların yolunda ima ediliyor; boş bir dizinin kendi girdisi
   * yoksa arşivden HİÇ ÇIKMIYOR. Kullanıcı indirdiği ağacın aynısını
   * beklerken bir klasörün yok olması, sessiz bir eksiklik.
   */
  addDirectory(meta: ZipMeta) {
    const path = meta.path.endsWith("/") ? meta.path : meta.path + "/";
    const name = new TextEncoder().encode(path);
    this.guard(localHeader + name.length, name.length);

    const h = new Bytes();
    h.u32(localSig);
    h.u16(needed);
    h.u16(utf8Flag);
    h.u16(0);
    const { time, date } = dosStamp(meta.mtime);
    h.u16(time);
    h.u16(date);
    h.u32(0);
    h.u32(0);
    h.u32(0);
    h.u16(name.length);
    h.u16(0);
    h.raw(name);

    const head = h.done();
    this.central.push({
      ...meta,
      path,
      crc: 0,
      size: 0,
      offset: this.offset,
      dir: true,
    });
    this.parts.push(head);
    this.offset += head.length;
  }

  /** finish, merkezî dizini ve sonu yazar; arşivi döner. */
  finish(): Blob {
    const start = this.offset;
    const c = new Bytes();

    for (const e of this.central) {
      const name = new TextEncoder().encode(e.path);
      c.u32(centralSig);
      c.u16(madeBy);
      c.u16(needed);
      c.u16(utf8Flag);
      c.u16(0);
      const { time, date } = dosStamp(e.mtime);
      c.u16(time);
      c.u16(date);
      c.u32(e.crc);
      c.u32(e.size);
      c.u32(e.size);
      c.u16(name.length);
      c.u16(0); // ek alan
      c.u16(0); // yorum
      c.u16(0); // disk
      c.u16(0); // iç öznitelik
      /*
       * Dış öznitelik: üst 16 bit unix kipi, alt bayt MS-DOS. Kip
       * yoksa makul bir varsayılan yazılıyor — sıfır kip, bazı
       * araçlarda okunamayan bir dosya olarak çıkıyor.
       */
      const mode = e.mode || (e.dir ? 0o040755 : 0o100644);
      c.u32(((mode & 0xffff) << 16) | (e.dir ? dosDirBit : 0));
      c.u32(e.offset);
      c.raw(name);
    }

    const dir = c.done();
    const end = new Bytes();
    end.u32(eocdSig);
    end.u16(0); // bu disk
    end.u16(0); // merkezî dizinin diski
    end.u16(this.central.length);
    end.u16(this.central.length);
    end.u32(dir.length);
    end.u32(start);
    end.u16(0); // arşiv yorumu

    return new Blob([...this.parts, dir, end.done()], {
      type: "application/zip",
    });
  }

  /**
   * guard, biçimin kendi sınırlarına çarpmayı hataya çevirir.
   *
   * ⚠️ SAYILAN ŞEY YAZMANIN GERÇEK MALİYETİ. İlk hâli yalnızca ad ve
   * gövde uzunluğunu topluyordu; yerel başlığın 30 baytını, merkezî
   * dizinin girdi başına 46+ad baytını ve sondaki 22 baytı hiç
   * görmüyordu. Eksik sayan bir tavan, geçildiğini FARK ETMEDEN geçilen
   * bir tavan — ve u32 alanları sessizce sarmalanıp arşivi yanlış
   * yerden okutuyor.
   */
  private guard(add: number, nameLen: number) {
    if (this.central.length >= maxEntries) {
      throw new Error(`an archive cannot hold more than ${maxEntries} entries`);
    }

    const central = this.centralBytes + centralHeader + nameLen;
    if (this.offset + add + central + eocdSize > maxArchiveBytes) {
      throw new Error(
        "the archive grew past 4 GiB, which this format cannot address",
      );
    }
    this.centralBytes = central;
  }
}

/**
 * safeName, hedeften gelen bir dosya adını arşive konabilir hâle getirir.
 *
 * ⚠️ BU BİR GÜVENLİK KONTROLÜ, KOZMETİK DEĞİL — ve saldırgan hedefin
 * SAHİBİ. Arşivin içindeki yolu, açan aracın nereye yazacağını
 * belirliyor: "../../.ssh/authorized_keys" adında bir dosya, denetçi
 * arşivi kendi makinesinde açtığında EV DİZİNİNİN DIŞINA yazardı
 * (zip-slip). Ters bölü Windows'ta ayraç; "." ve ".." her yerde
 * özel. Yani hedefte bir klasör açıp içine bu adla dosya koyan biri,
 * postern'i kendi silahına çeviremesin.
 *
 * ⚠️ ATILMIYOR, ETKİSİZLEŞTİRİLİYOR. Böyle bir adı listeden düşürmek,
 * arşivde SESSİZ bir eksik bırakırdı; adı bozup içeriği taşımak,
 * denetçiye "burada tuhaf bir ad vardı" diyor.
 */
export function safeName(name: string): string {
  let out = "";
  for (const r of name) {
    const c = r.codePointAt(0) ?? 0;
    // C0, DEL ve C1: dosya adında ekranı boyayan kaçış dizileri.
    if (c < 0x20 || c === 0x7f || (c >= 0x80 && c <= 0x9f)) continue;
    /*
     * ⚠️ İKİ YÖNLÜ YAZI DENETİMLERİ DE ATILIYOR ve sebebi kontrol
     * karakterlerininkiyle aynı: ad, OLDUĞUNDAN BAŞKA görünüyor.
     * İçinde U+202E taşıyan "fatura<RLO>gnp.exe", panelde de arşiv
     * listesinde de "faturaexe.png" diye okunuyor — denetçi bir resme
     * tıkladığını sanarken çalıştırılabilir bir dosya açıyor.
     */
    if (
      c === 0x200e ||
      c === 0x200f ||
      (c >= 0x202a && c <= 0x202e) ||
      (c >= 0x2066 && c <= 0x2069)
    ) {
      continue;
    }
    out += r === "/" || r === "\\" ? "_" : r;
  }

  // Temizlikten sonra bakılıyor: "..\x00" da ".." demek.
  if (out === "" || out === "." || out === "..") return "_";

  /*
   * Windows'un ayrılmış aygıt adları: "CON", "NUL", "COM1"… Bu adla bir
   * dosya çıkarmak Windows'ta ya başarısız oluyor ya da bir aygıta
   * yazıyor — arşivin geri kalanı açılırken bu girdi kayboluyor.
   */
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i.test(out)) {
    out = "_" + out;
  }

  /*
   * Windows sondaki noktayı ve boşluğu SESSİZCE atıyor; "veri." ile
   * "veri" aynı dosyaya çıkıyor ve ikincisi birincisini eziyor.
   */
  return /[. ]$/.test(out) ? out + "_" : out;
}

/**
 * uniqueName, bir dizinin İÇİNDE çakışan adı ayırır.
 *
 * ⚠️ TEKLİK YOLUN TAMAMINDA DEĞİL, KARDEŞLER ARASINDA ARANIYOR ve bu
 * ayrımı gerçek `unzip` öğretti. İlk hâli yolun tamamını bir kümede
 * tutuyordu; "kok/_" adlı bir DOSYA ile "kok/_/tmp/x" yolundaki "_"
 * DİZİNİ farklı iki yol olduğu için çakışma sayılmıyordu, ama arşivde
 * aynı ada iki farklı şey düşüyordu ve unzip çıkarırken "üzerine
 * yazayım mı" diye soruyordu. Seviye seviye teklik, hem bunu hem düz
 * ad çakışmasını tek kuralla kapatıyor.
 *
 * ⚠️ ÇAKIŞMA GERÇEKTEN OLUYOR ve hedefin sahibi üretebiliyor: adlar
 * geçerli UTF-8 olmak zorunda değil, iki bozuk ad çözülünce aynı U+FFFD
 * dizisine düşüyor. Aynı adı iki kez yazmak, açan aracın birini
 * diğerinin üstüne yazması demek — sessiz veri kaybı.
 */
export function uniqueName(taken: Set<string>, name: string): string {
  if (!taken.has(fold(name))) {
    taken.add(fold(name));
    return name;
  }

  // Uzantı korunuyor: "a.log" ikinci kez gelirse "a (2).log" oluyor,
  // "a.log (2)" değil — ikincisini hiçbir araç doğru açmıyor.
  const dot = name.lastIndexOf(".");
  const stem = dot > 0 ? name.slice(0, dot) : name;
  const ext = dot > 0 ? name.slice(dot) : "";

  for (let n = 2; ; n++) {
    const next = `${stem} (${n})${ext}`;
    if (!taken.has(fold(next))) {
      taken.add(fold(next));
      return next;
    }
  }
}

/**
 * fold, iki adın AÇILDIĞINDA aynı dosyaya düşüp düşmeyeceği.
 *
 * ⚠️ ARŞİVİN İÇİNDE FARKLI OLMAK YETMİYOR. "README" ve "readme" zip'te
 * iki ayrı girdi; `unzip -t` de geçiyor. Ama macOS'un APFS'i ve Windows
 * büyük/küçük harf ayırmıyor, ve macOS adları NFD'ye ayrıştırıyor: iki
 * girdi çıkarılırken TEK dosyaya düşüyor ve sonuncusu diğerini eziyor.
 * Denetçi bunu göremiyor — arşivde iki satır var, diskte bir dosya.
 */
function fold(name: string): string {
  return name.normalize("NFC").toLowerCase();
}
