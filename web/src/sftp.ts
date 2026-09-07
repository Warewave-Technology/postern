/**
 * Tarayıcı tarafı SFTP — SALT OKUMA.
 *
 * NEDEN KENDİ ÇÖZÜMLEYİCİMİZ. Panelin dosya tarayıcısı, sunucuda SFTP
 * istemcisi tutan bir yardımcı uçla da yazılabilirdi ve o tasarım
 * REDDEDİLDİ: hedef dosyalarına giden, denetim defterine bağlanmamış
 * ikinci bir yol demekti. Burada tarayıcı, SSH istemcisinin konuştuğu
 * protokolün AYNISINI konuşuyor ve paketler postern'in çözümleyicisinden
 * (internal/sftpaudit) geçiyor: yol politikası, defter ve kayıt zinciri
 * kendiliğinden çalışıyor.
 *
 * ⚠️ KAPSAM DAR VE SINIRI AD UZAYINDAN GEÇİYOR. Dosya okumak ve yazmak
 * kodlanıyor; AD UZAYINI değiştiren hiçbir şey kodlanmıyor — silme,
 * yeniden adlandırma, dizin yaratma, izin değiştirme, bağ kurma. Bu bir
 * kolaylık değil, ikinci bir kilit: panelden bir dosyayı silmek ya da
 * taşımak, bilinçli bir protokol işi olmak zorunda kalsın.
 *
 * Yazmanın kendisi sunucuda ayrıca kararlı: kanal varsayılan olarak
 * salt-okunur (session.sftp_panel_write) ve açık olduğunda bile her
 * yazma isteği rolün yol kurallarına soruluyor. Buradaki kısıt onun
 * yerine geçmiyor, üstüne biniyor.
 *
 * Sürüm 3 (draft-ietf-secsh-filexfer-02) — OpenSSH'in sftp-server'ının
 * konuştuğu sürüm.
 */

export const FXP = {
  INIT: 1,
  VERSION: 2,
  OPEN: 3,
  CLOSE: 4,
  READ: 5,
  WRITE: 6,
  OPENDIR: 11,
  READDIR: 12,
  REALPATH: 16,
  STAT: 17,
  READLINK: 19,
  STATUS: 101,
  HANDLE: 102,
  DATA: 103,
  NAME: 104,
  ATTRS: 105,
} as const;

/**
 * FXF, SSH_FXP_OPEN bayrakları (sürüm 3).
 *
 * ⚠️ EXCL BİLEREK YOK. Yükleme var olan bir dosyanın üzerine yazıyor
 * (TRUNC) — EXCL eklemek "dosya varsa hata ver" demek olurdu ve
 * kullanıcının gördüğü şey, aynı adı ikinci kez yüklediğinde sebebi
 * anlaşılmayan bir ret olurdu. Üzerine yazmanın kendisi zaten yol
 * kuralına tabi.
 */
export const FXF = {
  READ: 0x1,
  WRITE: 0x2,
  CREAT: 0x8,
  TRUNC: 0x10,
} as const;

export const FX = {
  OK: 0,
  EOF: 1,
  NO_SUCH_FILE: 2,
  PERMISSION_DENIED: 3,
  FAILURE: 4,
  BAD_MESSAGE: 5,
  NO_CONNECTION: 6,
  CONNECTION_LOST: 7,
  OP_UNSUPPORTED: 8,
} as const;

/**
 * maxPacket, kabul edilen en büyük SFTP paketi.
 *
 * ⚠️ SUNUCUDAKİ SINIRLA AYNI OLMAK ZORUNDA DEĞİL, ONDAN BÜYÜK OLMAMALI:
 * postern 1 MiB'ı aşan paketi zaten düşürüyor. Burada aynı değeri
 * tutmak, bozuk bir uzunluk alanının tarayıcıda gigabaytlık bir tampon
 * ayırtmasını engelliyor.
 */
export const maxPacket = 1 << 20;

const S_IFMT = 0o170000;
const S_IFDIR = 0o040000;
const S_IFLNK = 0o120000;

export interface Entry {
  name: string;
  /** `ls -l` biçimli satır: sahip/grup yalnızca burada var (v3 attrs sayı veriyor). */
  longname: string;
  size: number;
  mode: number;
  mtime: number;
  isDir: boolean;
  isLink: boolean;
}

/** SFTPError, hedefin verdiği durum kodunu ve mesajını taşır. */
export class SFTPError extends Error {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message);
    this.name = "SFTPError";
  }
}

// ---------------------------------------------------------------- kodlama

class Writer {
  private buf = new Uint8Array(256);
  private n = 0;

  private need(k: number) {
    if (this.n + k <= this.buf.length) return;
    let size = this.buf.length * 2;
    while (size < this.n + k) size *= 2;
    const next = new Uint8Array(size);
    next.set(this.buf.subarray(0, this.n));
    this.buf = next;
  }

  u8(v: number) {
    this.need(1);
    this.buf[this.n++] = v & 0xff;
  }

  u32(v: number) {
    this.need(4);
    new DataView(this.buf.buffer).setUint32(this.n, v >>> 0);
    this.n += 4;
  }

  str(s: string) {
    const b = new TextEncoder().encode(s);
    this.u32(b.length);
    this.need(b.length);
    this.buf.set(b, this.n);
    this.n += b.length;
  }

  /**
   * u64, 64 bitlik alan yazar (dosya konumu).
   *
   * ⚠️ Number ile: 2^53'ün üstündeki konumlar kayıplı olurdu, ama o
   * 8 petabaytlık bir dosya demek. BigInt'i bütün çağrı zincirine
   * taşımak, ulaşılmayacak bir sınır için ödenmiş bir bedel olurdu.
   */
  u64(v: number) {
    this.u32(Math.floor(v / 0x100000000));
    this.u32(v >>> 0);
  }

  /** raw, uzunluk önekli ham baytları yazar (tutamak için). */
  raw(b: Uint8Array) {
    this.u32(b.length);
    this.need(b.length);
    this.buf.set(b, this.n);
    this.n += b.length;
  }

  /** frame, gövdeyi uzunluk önekiyle sarar — tele giden biçim. */
  frame(): Uint8Array {
    const out = new Uint8Array(4 + this.n);
    new DataView(out.buffer).setUint32(0, this.n);
    out.set(this.buf.subarray(0, this.n), 4);
    return out;
  }
}

class Reader {
  private p = 0;
  private view: DataView;

  constructor(private b: Uint8Array) {
    this.view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }

  get done() {
    return this.p >= this.b.length;
  }

  u8(): number {
    if (this.p + 1 > this.b.length) throw new Error("sftp: truncated packet");
    return this.b[this.p++];
  }

  u32(): number {
    if (this.p + 4 > this.b.length) throw new Error("sftp: truncated packet");
    const v = this.view.getUint32(this.p);
    this.p += 4;
    return v;
  }

  /**
   * u64, 64 bitlik alanı sayıya çevirir.
   *
   * ⚠️ 2^53'ün ÜSTÜ KAYIPLI ve bu kabul edilebilir: alan dosya boyutu ve
   * 8 petabaytın üstünde bir dosyanın panelde birkaç bayt yanlış
   * gösterilmesi, BigInt'i bütün arayüze taşımaktan iyi. Sayı yalnızca
   * gösteriliyor; hiçbir karar ona dayanmıyor.
   */
  u64(): number {
    const hi = this.u32();
    const lo = this.u32();
    return hi * 0x100000000 + lo;
  }

  str(): string {
    const n = this.u32();
    if (this.p + n > this.b.length) throw new Error("sftp: truncated string");
    const s = new TextDecoder().decode(this.b.subarray(this.p, this.p + n));
    this.p += n;
    return s;
  }

  /** bytes, uzunluk önekli ham alanı döner (handle için). */
  bytes(): Uint8Array {
    const n = this.u32();
    if (this.p + n > this.b.length) throw new Error("sftp: truncated bytes");
    const s = this.b.subarray(this.p, this.p + n);
    this.p += n;
    return s;
  }
}

export interface Attrs {
  size: number;
  mode: number;
  mtime: number;
}

/**
 * readAttrs, v3 ATTRS yapısını okur.
 *
 * ⚠️ BAYRAKLAR SIRAYLA VE HEPSİ OKUNMALI — atlanan bir alan, PAKETİN
 * GERİ KALANINI kaydırır. Dizin listesinde bu, ikinci girdiden itibaren
 * her şeyin çöp çıkması demek; test bunu tam olarak bu yüzden bütün
 * bayraklar açıkken de ölçüyor.
 */
function readAttrs(r: Reader): Attrs {
  const flags = r.u32();
  const a: Attrs = { size: 0, mode: 0, mtime: 0 };

  if (flags & 0x01) a.size = r.u64();
  if (flags & 0x02) {
    r.u32(); // uid
    r.u32(); // gid
  }
  if (flags & 0x04) a.mode = r.u32();
  if (flags & 0x08) {
    r.u32(); // atime
    a.mtime = r.u32();
  }
  if (flags & 0x80000000) {
    const count = r.u32();
    for (let i = 0; i < count; i++) {
      r.str();
      r.str();
    }
  }

  return a;
}

// ------------------------------------------------------------ çerçeveleme

/**
 * Framer, akıştan gelen baytları tam SFTP paketlerine böler.
 *
 * ⚠️ WEBSOCKET ÇERÇEVESİ = SFTP PAKETİ DEĞİL. Sunucu, hedeften geleni
 * olduğu gibi aktarıyor; bir websocket mesajında iki paket ya da bir
 * paketin yarısı olabilir. Bunu varsaymak, büyük dizin listelerinde
 * "bazen çalışıyor" diye teşhis edilen bir hata olurdu.
 */
export class Framer {
  private buf = new Uint8Array(0);

  push(chunk: Uint8Array): Uint8Array[] {
    const merged = new Uint8Array(this.buf.length + chunk.length);
    merged.set(this.buf);
    merged.set(chunk, this.buf.length);
    this.buf = merged;

    const out: Uint8Array[] = [];
    for (;;) {
      if (this.buf.length < 4) break;
      const n = new DataView(
        this.buf.buffer,
        this.buf.byteOffset,
        this.buf.byteLength,
      ).getUint32(0);
      if (n === 0 || n > maxPacket) {
        throw new Error(`sftp: bad packet length ${n}`);
      }
      if (this.buf.length < 4 + n) break;
      out.push(this.buf.slice(4, 4 + n));
      this.buf = this.buf.subarray(4 + n);
    }

    return out;
  }
}

// ---------------------------------------------------------------- istemci

export interface Transport {
  send(frame: Uint8Array): void;
}

/**
 * Reply, bir isteğin cevabı.
 *
 * ⚠️ TİP ALANI TAŞINIYOR ve bu şart: READDIR'in cevabı ya NAME (girdiler)
 * ya da EOF taşıyan STATUS oluyor. İkisini yalnızca gövdeye bakarak
 * ayırmaya çalışmak, "boş dizin" ile "liste bitti" arasındaki farkı
 * tahmine bırakırdı.
 */
interface Reply {
  typ: number;
  r: Reader;
}

type Pending = {
  resolve: (r: Reply) => void;
  reject: (e: Error) => void;
};

/**
 * SFTPClient, salt-okunur bir SFTP oturumu sürer.
 *
 * Taşıma katmanı DIŞARIDAN veriliyor: sınıf websocket'i bilmiyor, bu da
 * bütün protokol yolunun soketsiz test edilebilmesini sağlıyor.
 */
export class SFTPClient {
  private id = 0;
  private pending = new Map<number, Pending>();
  private framer = new Framer();
  private versionResolve: (() => void) | null = null;
  private versionReject: ((e: Error) => void) | null = null;
  private closed: Error | null = null;

  constructor(private tx: Transport) {}

  /** open, INIT gönderir ve VERSION'ı bekler. */
  open(): Promise<void> {
    const w = new Writer();
    w.u8(FXP.INIT);
    w.u32(3);
    this.tx.send(w.frame());

    return new Promise((resolve, reject) => {
      this.versionResolve = resolve;
      this.versionReject = reject;
    });
  }

  /**
   * feed, akıştan gelen baytları verir.
   *
   * Çözümleme hatası ÖLÜMCÜL: paket sınırını kaybetmiş bir akışta
   * devam etmek, rastgele baytları cevap sanmak demek.
   */
  feed(chunk: Uint8Array) {
    let packets: Uint8Array[];
    try {
      packets = this.framer.push(chunk);
    } catch (e) {
      this.fail(e instanceof Error ? e : new Error(String(e)));
      return;
    }
    for (const p of packets) {
      try {
        this.dispatch(p);
      } catch (e) {
        this.fail(e instanceof Error ? e : new Error(String(e)));
        return;
      }
    }
  }

  /** fail, bekleyen her isteği reddeder — soket koptuğunda çağrılıyor. */
  fail(err: Error) {
    if (this.closed) return;
    this.closed = err;
    this.versionReject?.(err);
    this.versionResolve = null;
    this.versionReject = null;
    for (const p of this.pending.values()) p.reject(err);
    this.pending.clear();
  }

  private dispatch(p: Uint8Array) {
    const r = new Reader(p);
    const typ = r.u8();

    if (typ === FXP.VERSION) {
      // Sürüm gövdesinde uzantılar da var; okumuyoruz çünkü hiçbirini
      // kullanmıyoruz.
      this.versionResolve?.();
      this.versionResolve = null;
      this.versionReject = null;
      return;
    }

    const id = r.u32();
    const waiter = this.pending.get(id);
    if (!waiter) return; // Cevapsız kalmış bir id: yok sayılıyor.
    this.pending.delete(id);

    if (typ === FXP.STATUS) {
      const code = r.u32();
      let msg = "";
      try {
        msg = r.str();
      } catch {
        // Mesaj alanı isteğe bağlı: bazı sunucular yalnızca kod
        // gönderiyor.
      }
      if (code === FX.OK || code === FX.EOF) {
        waiter.resolve({ typ, r });
        return;
      }
      waiter.reject(new SFTPError(code, msg || statusText(code)));
      return;
    }

    waiter.resolve({ typ, r });
  }

  private request(build: (w: Writer, id: number) => void): Promise<Reply> {
    if (this.closed) return Promise.reject(this.closed);

    const id = ++this.id;
    const w = new Writer();
    build(w, id);
    this.tx.send(w.frame());

    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
  }

  /** realpath, göreli ya da "." yolunu hedefte mutlak yola çevirir. */
  async realpath(path: string): Promise<string> {
    const { r } = await this.request((w, id) => {
      w.u8(FXP.REALPATH);
      w.u32(id);
      w.str(path);
    });
    const count = r.u32();
    if (count < 1) throw new Error("sftp: empty realpath reply");
    return r.str();
  }

  /**
   * open, bir dosyayı açar ve tutamağını döner.
   *
   * ⚠️ ATTRS ALANI BOŞ GİDİYOR (bayrak yok). Sürüm 3'te OPEN'ın sonunda
   * bir öznitelik yapısı var; izin/boyut göndermek, hedefin kendi
   * umask'ını ve var olan dosyanın kipini EZERDİ. Yeni dosyanın izinleri
   * hedefin kararı olsun.
   */
  private async openFile(path: string, flags: number): Promise<Uint8Array> {
    const { r } = await this.request((w, id) => {
      w.u8(FXP.OPEN);
      w.u32(id);
      w.str(path);
      w.u32(flags);
      w.u32(0);
    });

    return r.bytes();
  }

  private closeHandle(handle: Uint8Array) {
    /*
     * Tutamağı KAPAT — hata yolunda da. Sızdırılan bir tutamak hedefteki
     * sftp-server'da açık kalıyor; sunucunun tutamak sayısı sınırlı ve
     * sızıntının sonu "dosya açılamıyor" oluyor.
     */
    this.request((w, id) => {
      w.u8(FXP.CLOSE);
      w.u32(id);
      w.raw(handle);
    }).catch(() => {
      // Kapatma hatası kullanıcıya söylenecek bir şey değil.
    });
  }

  /**
   * download, bir dosyayı okur ve parçalarını sırayla verir.
   *
   * ⚠️ PARÇALAR ÇAĞIRANA VERİLİYOR, BELLEKTE BİRİKTİRİLMİYOR. Tamamını
   * bir Blob'a toplamak 1 GB'lık bir dosyada sekmeyi düşürür; çağıran
   * parçaları aldığı gibi diske ya da bir akışa yazabilsin.
   *
   * ⚠️ İSTEKLER BORU HATTINDA AMA SIRALI TESLİM EDİLİYOR. Aynı anda
   * maxInFlight kadar READ uçuyor (yoksa her parça için tam bir gidiş
   * dönüş beklenir ve hız ağ gecikmesine kilitlenir), ama cevaplar
   * konumlarına göre sıraya diziliyor: dosyayı yazan taraf parçaları
   * karışık sırada alırsa dosya bozulur.
   */
  async download(
    path: string,
    onChunk: (b: Uint8Array) => void | Promise<void>,
    onProgress?: (p: Progress) => void,
    total?: number,
  ): Promise<number> {
    const handle = await this.openFile(path, FXF.READ);
    let done = 0;

    try {
      let offset = 0;
      let eof = false;
      const inflight = new Map<number, Promise<Uint8Array | null>>();

      const fire = (at: number) => {
        const pr = this.request((w, id) => {
          w.u8(FXP.READ);
          w.u32(id);
          w.raw(handle);
          w.u64(at);
          w.u32(chunkSize);
        })
          .then((reply) => (reply.typ === FXP.DATA ? reply.r.bytes() : null))
          .catch((e: unknown) => {
            // EOF, hata değil: dosyanın sonu STATUS ile bildiriliyor.
            if (e instanceof SFTPError && e.code === FX.EOF) return null;
            throw e;
          });
        inflight.set(at, pr);
      };

      while (!eof || inflight.size > 0) {
        while (!eof && inflight.size < maxInFlight) {
          fire(offset);
          offset += chunkSize;
        }

        // Sıradaki konumun cevabını bekle: teslim SIRALI olmak zorunda.
        const next = Math.min(...inflight.keys());
        const chunk = await inflight.get(next)!;
        inflight.delete(next);

        if (chunk === null || chunk.length === 0) {
          /*
           * ⚠️ EOF GÖRÜLDÜ: DAHA SONRAKİ KONUMLAR ATILIYOR.
           *
           * Boru hattı EOF'un ötesine istek göndermiş olabilir; onların
           * cevaplarını beklemek gereksiz, ama daha ÖNEMLİSİ, gelen
           * veriyi dosyaya eklemek yanlış olurdu: EOF'tan sonrası
           * dosyanın parçası değil.
           */
          eof = true;
          inflight.clear();
          break;
        }

        await onChunk(chunk);
        done += chunk.length;
        onProgress?.({ done, total });

        /*
         * ⚠️ KISA CEVAP EOF DEĞİL. Sunucu istenenden az bayt
         * döndürebiliyor; bunu dosya sonu saymak, dosyayı sessizce
         * kırpardı — sessiz bozulma, hata vermekten kötü.
         */
        if (chunk.length < chunkSize) {
          eof = eof || false;
        }
      }
    } finally {
      this.closeHandle(handle);
    }

    return done;
  }

  /**
   * upload, bir dosyayı hedefe yazar.
   *
   * ⚠️ HER PARÇANIN CEVABI BEKLENİYOR (pencere içinde). Cevap beklemeden
   * yazmak, WebSocket gönderme kuyruğuna dosyanın tamamını yığmak
   * demek — tarayıcı belleği dosyayla birlikte büyür. Pencere sabit.
   *
   * ⚠️ TRUNC VAR, EXCL YOK: aynı adı ikinci kez yüklemek üzerine yazıyor.
   * EXCL, kullanıcının sebebini anlamayacağı bir ret üretirdi; üzerine
   * yazma yetkisi zaten yol kuralına tabi.
   */
  async upload(
    path: string,
    read: () => Promise<Uint8Array | null>,
    onProgress?: (p: Progress) => void,
    total?: number,
  ): Promise<number> {
    const handle = await this.openFile(path, FXF.WRITE | FXF.CREAT | FXF.TRUNC);
    let done = 0;

    try {
      let offset = 0;
      const inflight: Promise<unknown>[] = [];

      for (;;) {
        const chunk = await read();
        if (chunk === null) break;
        if (chunk.length === 0) continue;

        const at = offset;
        offset += chunk.length;

        inflight.push(
          this.request((w, id) => {
            w.u8(FXP.WRITE);
            w.u32(id);
            w.raw(handle);
            w.u64(at);
            w.raw(chunk);
          }).then(() => {
            done += chunk.length;
            onProgress?.({ done, total });
          }),
        );

        if (inflight.length >= maxInFlight) {
          await inflight.shift();
        }
      }

      // Kalan pencereyi boşalt: biri düşerse hata BURADAN çıkmalı,
      // yoksa "tamamlandı" yazıp yarım dosya bırakırdık.
      await Promise.all(inflight);
    } finally {
      this.closeHandle(handle);
    }

    return done;
  }

  /** readdir, bir dizini baştan sona okur. */
  async readdir(path: string): Promise<Entry[]> {
    const opened = await this.request((w, id) => {
      w.u8(FXP.OPENDIR);
      w.u32(id);
      w.str(path);
    });
    const handle = opened.r.bytes();

    const out: Entry[] = [];
    try {
      for (;;) {
        const reply = await this.request((w, id) => {
          w.u8(FXP.READDIR);
          w.u32(id);
          w.raw(handle);
        });

        // Liste bitti: hedef NAME yerine EOF taşıyan STATUS gönderdi.
        if (reply.typ !== FXP.NAME) break;

        const count = reply.r.u32();
        if (count === 0) break;
        for (let i = 0; i < count; i++) {
          const name = reply.r.str();
          const longname = reply.r.str();
          const a = readAttrs(reply.r);
          out.push({
            name,
            longname,
            size: a.size,
            mode: a.mode,
            mtime: a.mtime,
            isDir: (a.mode & S_IFMT) === S_IFDIR,
            isLink: (a.mode & S_IFMT) === S_IFLNK,
          });
        }
      }
    } finally {
      this.closeHandle(handle);
    }

    return out;
  }
}

/**
 * chunkSize, aktarımın parça boyu.
 *
 * ⚠️ TAVANIN ÇOK ALTINDA VE BİLEREK. Protokol sınırı 1 MiB (maxPacket,
 * her iki uçta), ama tavana yakın parçalar iki şeyi birden kötüleştiriyor:
 * ilerleme çubuğu sıçraya sıçraya ilerliyor (bir parça ya hep ya hiç), ve
 * tek bir parçanın tarayıcıda tamponlanması ölçülebilir bir bellek
 * sıçraması oluyor. 32 KiB, OpenSSH'in kendi sftp istemcisinin de
 * kullandığı büyüklük.
 */
export const chunkSize = 32 * 1024;

/**
 * maxInFlight, aynı anda cevabı beklenen istek sayısı.
 *
 * ⚠️ SINIRSIZ BORU HATTI TARAYICIYI ŞİŞİRİR. İstekleri cevap beklemeden
 * sıraya koymak hızlı görünüyor ama WebSocket gönderme kuyruğu dosyanın
 * TAMAMINI belleğe alabilir — ve sunucu tarafında da bekleyenler tablosu
 * dolu tutulur. Sabit bir pencere, hızın çoğunu veriyor ve iki tarafta da
 * sınırı belirli tutuyor.
 */
export const maxInFlight = 16;

/** Transfer, süren bir aktarımın ilerlemesi. */
export interface Progress {
  /** Taşınan bayt. */
  done: number;
  /** Toplam bayt; bilinmiyorsa undefined (ilerleme yüzdesi çizilemez). */
  total?: number;
}

/** statusText, sunucu mesaj göndermediğinde kullanılan karşılık. */
export function statusText(code: number): string {
  switch (code) {
    case FX.NO_SUCH_FILE:
      return "no such file or directory";
    case FX.PERMISSION_DENIED:
      return "permission denied";
    case FX.OP_UNSUPPORTED:
      return "operation not supported";
    case FX.FAILURE:
      return "the target refused the request";
    default:
      return `sftp status ${code}`;
  }
}
