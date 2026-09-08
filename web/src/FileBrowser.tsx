import { useCallback, useEffect, useRef, useState } from "react";
import { SFTPClient, SFTPError, Halted, chunkSize, newStop } from "./sftp";
import type { Entry, Stopper } from "./sftp";
import { ZipWriter, crc32, safeName } from "./zip";
import {
  noteName,
  plain,
  skipNote,
  walkTree,
  type Reason,
  type Skipped,
} from "./tree";
import {
  fromDataTransfer,
  fromFileList,
  readInChunks,
  saveBlob,
  hasDirectoryPicker,
  type LocalFile,
} from "./local";
import {
  isSettled,
  joinRemote,
  maxDownloadBytes,
  nextId,
  percent,
  progressText,
  tooLargeToDownload,
  type Transfer,
} from "./transfer";
import {
  crumbs,
  formatMode,
  formatSize,
  formatTime,
  hidden,
  joinPath,
  parentPath,
  sortEntries,
} from "./files";
import { FolderIcon, FileIcon, LinkIcon } from "./icons";

/**
 * FileBrowser — hedefteki dosyalara SALT OKUNUR gezinme.
 *
 * ⚠️ BU BİLEŞEN HEDEFE DOĞRUDAN BAĞLANMIYOR. WebSocket, postern'in
 * /api/sftp/{target} ucuna gidiyor; oradan SSH oturumu, oradan hedefin
 * sftp-server'ı. Yani panelden yapılan her istek, SSH istemcisinden
 * gelen bir istekle AYNI yoldan geçiyor: aynı yol politikası, aynı
 * denetim defteri, aynı kayıt zinciri.
 *
 * ⚠️ SALT OKUNURLUĞU BU DOSYA SAĞLAMIYOR. Kısıt sunucuda
 * (proxy.SetSFTPReadOnly): buradaki JavaScript'in taşıdığı hiçbir kural,
 * çalınmış bir oturumun elle yazdığı FXP_WRITE'ı durduramaz. Burada
 * yazma isteği HİÇ KODLANMIYOR olması ikinci bir kilit, birincisi değil.
 *
 * ⚠️ DİZİN İNDİRMEK BİR AĞAÇ GEZİNTİSİ, TEK BİR İSTEK DEĞİL ve maliyeti
 * denetim defterinde: dizin başına bir satır, dosya başına bir satır
 * daha. proxy.journalCap (10000) aşılırsa oturum ÖLÜYOR — yani sınırsız
 * bir indirme, yaptığı işin KAYDINI da götürürdü. Tavanlar ve reddetme
 * cümleleri tree.ts'te ve sebebi bu.
 */

type Phase = "connecting" | "ready" | "closed";

export default function FileBrowser({
  target,
  canWrite,
}: {
  target: string;
  /** Yükleme açık mı (session.sftp_panel_write). */
  canWrite: boolean;
}) {
  const clientRef = useRef<SFTPClient | null>(null);
  const [phase, setPhase] = useState<Phase>("connecting");
  const [cwd, setCwd] = useState("");
  const [entries, setEntries] = useState<Entry[]>([]);
  const [error, setError] = useState("");
  /*
   * ⚠️ UYARI METNİ KÖKENİYLE BİRLİKTE TUTULUYOR. Bu kutuya hem postern'in
   * kendi cümlesi hem hedefin stderr'i düşüyor; ikisini aynı biçimde
   * çizmek, hedefe bastion'ın sesini vermek olurdu.
   */
  const [notice, setNotice] = useState<Reason | null>(null);
  const [busy, setBusy] = useState(false);
  const [showHidden, setShowHidden] = useState(false);

  // Yerel taraf: seçilmiş/bırakılmış dosyalar ve seçim.
  const [local, setLocal] = useState<LocalFile[]>([]);
  const [localPick, setLocalPick] = useState<Set<string>>(new Set());
  const [remotePick, setRemotePick] = useState<Set<string>>(new Set());
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const [dropping, setDropping] = useState<"local" | "remote" | null>(null);

  /*
   * ⚠️ AKTARIMLAR SIRAYLA KOŞUYOR ve kuyruk bir ref'te.
   *
   * Aynı anda birkaçını sürmek hızlı görünüyor ama tek bir kanalı
   * paylaşıyorlar: pencereler birbirine karışıyor, ilerleme çubukları
   * anlamsızlaşıyor ve bir hata hangi dosyaya ait olduğunu kaybediyor.
   * Sıralı kuyruk, kullanıcıya "şu an bu dosya" diyebilmenin şartı.
   */
  const queueRef = useRef<Promise<void>>(Promise.resolve());

  /*
   * ⚠️ DURDURMA BAYRAKLARI DURUMDA DEĞİL, BİR REF'TE. Süren bir aktarım
   * bayrağı okurken React'in o anki çiziminde ne olduğu önemli değil;
   * durumda tutmak, çalışan döngüye BAYAT bir kopya verirdi ve Stop
   * düğmesi ancak bir sonraki çizimde işe yarardı.
   */
  const stops = useRef(new Map<number, () => void>());

  /** stop, bir aktarımı durdurur (sırada bekleyeni de). */
  const stop = useCallback((id: number) => {
    stops.current.get(id)?.();
  }, []);

  /**
   * open, bir dizini okur ve BAŞARIRSA oraya geçer.
   *
   * ⚠️ SIRA ÖNEMLİ. Önce yolu değiştirip sonra okumaya çalışsaydık,
   * reddedilen bir dizin adres çubuğunda ve kırıntılarda "içindeymişiz
   * gibi" durur, ama liste bir öncekinin listesi olurdu — kullanıcı
   * yanlış dizinin içeriğine bakarken doğru dizinde olduğunu sanardı.
   */
  const open = useCallback(async (dir: string) => {
    const c = clientRef.current;
    if (!c) return;

    setBusy(true);
    setError("");
    try {
      const list = await c.readdir(dir);
      setEntries(sortEntries(list));
      setCwd(dir);
    } catch (e) {
      setError(reason(e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(
      `${scheme}//${location.host}/api/sftp/${encodeURIComponent(target)}`,
    );
    ws.binaryType = "arraybuffer";

    const client = new SFTPClient({
      send: (frame) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(frame);
      },
    });
    clientRef.current = client;

    ws.onopen = () => {
      client
        .open()
        .then(() => client.realpath("."))
        .then((home) => {
          setPhase("ready");
          return open(home);
        })
        .catch((e) => {
          setPhase("closed");
          setError(reason(e));
        });
    };

    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") return; // Kontrol mesajı: burada yok.
      const frame = new Uint8Array(ev.data as ArrayBuffer);
      if (frame.length < 1) return;

      /*
       * ⚠️ İLK BAYT AKIŞ VE KÖKEN ETİKETİ (wschannel.go): 0 hedefin
       * kanal verisi, 1 hedefin stderr'i, 2 postern'in kendi cevabı,
       * 3 postern'in kendi satırı. Etiketi ayıklamadan çözümleyiciye
       * vermek, her çerçevede paket sınırını bir bayt kaydırırdı.
       *
       * ⚠️ KÖKEN BURADAN ÇIKIYOR, METİNDEN DEĞİL. Panel eskiden
       * "postern: " önekini kanıt sayıyordu ve o öneki hedef de
       * yazabiliyordu; artık kanıt, hedefin yazamadığı tek şey.
       *
       * ⚠️ TANIMADIĞIMIZ ETİKET SESSİZCE ATILIYOR. Sunucu bizden yeni
       * olabilir; bilinmeyen bir etiketi 0 sanıp çözümleyiciye vermek,
       * çerçevelemeyi kaydırırdı.
       */
      const body = frame.subarray(1);
      switch (frame[0]) {
        case 0:
          client.feed(body, "target");
          break;
        case 2:
          client.feed(body, "postern");
          break;
        case 1:
        case 3:
          // Cevabı beklenen bir istek varsa aynı sebep zaten hata
          // olarak da geliyor; bu kanal, isteğe bağlanamayan durumlar
          // için.
          /*
           * ⚠️ METİN BURADA DA TEMİZLENİYOR — explain()'deki gerekçenin
           * aynısı. Bu şerit, hedefin baytlarının panele en DOĞRUDAN
           * girdiği yer: STATUS metni bir isteğe bağlı, bu ise değil.
           * Temizlemeden çizmek, atıf damgasını ("the target said: ")
           * iki yönlü yazı işaretiyle cümlenin ortasına taşımaya izin
           * verirdi — yani kökeni tele taşıyıp son adımda geri vermek.
           *
           * ⚠️ ETİKETE BAKMADAN, İKİSİNE DE. postern'in kendi metninde
           * zaten kontrol karakteri yok, yani temizlik ona bir şey
           * yapmıyor; ama böylece güvenlik, etiketin DOĞRU olmasına
           * bağlı kalmıyor. Sınıflandırmayı doğrulamadan okunabilen bir
           * savunma, sınıflandırmanın yanlış olabileceği her gün
           * çalışmaya devam ediyor.
           */
          setNotice({
            why: plain(new TextDecoder().decode(body).trim()),
            from: frame[0] === 3 ? "postern" : "target",
          });
          break;
      }
    };

    ws.onclose = (ev) => {
      setPhase("closed");
      client.fail(new Error(closeReason(ev)));
      setError((prev) => prev || closeReason(ev));
    };

    ws.onerror = () => {
      // Ayrıntı yok: tarayıcı hata olayının içini JavaScript'e
      // VERMİYOR. Sebep varsa onclose'dan gelecek.
      setPhase("closed");
    };

    return () => {
      clientRef.current = null;
      ws.close();
    };
    // open kararlı (useCallback, boş bağımlılık): soket hedef
    // değiştiğinde kurulmalı, her çizimde değil.
  }, [target, open]);

  /** patch, tek bir aktarımın durumunu günceller. */
  const patch = useCallback((id: number, over: Partial<Transfer>) => {
    setTransfers((list) =>
      list.map((t) => (t.id === id ? { ...t, ...over } : t)),
    );
  }, []);

  /**
   * enqueue, bir aktarımı kuyruğa koyar.
   *
   * ⚠️ BİR AKTARIMIN HATASI KUYRUĞU DURDURMUYOR. Beş dosya seçip
   * birinde izin hatası almak, kalan dördünün de iptal olması demek
   * olmamalı — kullanıcı hangisinin neden düştüğünü satırında görüyor
   * ve diğerleri akmaya devam ediyor.
   */
  const enqueue = useCallback(
    (t: Transfer, run: (signal: Stopper) => Promise<void>) => {
      const { signal, stop: halt } = newStop();
      stops.current.set(t.id, halt);
      setTransfers((list) => [...list, t]);

      queueRef.current = queueRef.current.then(async () => {
        try {
          if (!clientRef.current) {
            patch(t.id, { state: "cancelled", error: "the session closed" });
            return;
          }
          /*
           * ⚠️ SIRADA BEKLERKEN DURDURULMUŞ OLABİLİR. Kuyruk sıralı ve
           * bir dizin indirmesi dakikalarca sürebiliyor; o sırada
           * basılan Stop, sıra geldiğinde işi HİÇ BAŞLATMAMALI.
           */
          if (signal.aborted) {
            patch(t.id, { state: "cancelled", error: "stopped before it began" });
            return;
          }
          patch(t.id, { state: "running" });
          await run(signal);
          patch(t.id, { state: "done" });
        } catch (e) {
          /*
           * ⚠️ DURDURMA BAŞARISIZLIK DEĞİL. Kullanıcının kendi bastığı
           * düğmeyi kırmızı bir arıza satırı olarak geri vermek, olmayan
           * bir sorunu varmış gibi gösterir.
           */
          if (e instanceof Halted) {
            /*
             * ⚠️ DURDURMANIN İKİ YÖNDE FARKLI SONUCU VAR. İndirme
             * dosyayı ancak sonunda kaydediyor, yani yarıda kesilen
             * bir indirmeden geriye HİÇBİR ŞEY kalmıyor. Yükleme ise
             * hedefe yazdığını yazmış oluyor. İkisini aynı cümleyle
             * geçmek, kullanıcıyı hedefte yarım kalmış bir dosyadan
             * habersiz bırakırdı.
             */
            patch(t.id, {
              state: "cancelled",
              error:
                t.dir === "up"
                  ? "stopped — bytes already written are still on the target"
                  : "stopped — nothing was saved",
            });
          } else {
            patch(t.id, { state: "failed", error: reason(e) });
          }
        } finally {
          stops.current.delete(t.id);
        }
      });
    },
    [patch],
  );

  /** startUpload, seçilen yerel dosyaları hedefe yazar. */
  const startUpload = useCallback(
    (picks: LocalFile[]) => {
      for (const lf of picks) {
        const id = nextId();
        const remotePath = joinRemote(cwd, lf.name);
        enqueue(
          {
            id,
            dir: "up",
            name: lf.name,
            remotePath,
            state: "queued",
            done: 0,
            total: lf.size,
          },
          async (signal) => {
            await clientRef.current!.upload(
              remotePath,
              readInChunks(lf.file, chunkSize),
              {
                onProgress: (p) => patch(id, { done: p.done }),
                size: lf.size,
                signal,
              },
            );
            // Liste tazelensin: yüklenen dosya sağ tarafta görünmeli,
            // yoksa kullanıcı yüklemenin olmadığını sanar.
            void open(cwd);
          },
        );
      }
    },
    [cwd, enqueue, open, patch],
  );

  /** startDownload, seçilen hedef dosyalarını tarayıcıya indirir. */
  const startDownload = useCallback(
    (picks: Entry[]) => {
      for (const e of picks) {
        const id = nextId();
        const remotePath = joinPath(cwd, e.name);
        const tooBig = tooLargeToDownload(e.size);

        enqueue(
          {
            id,
            dir: "down",
            name: e.name,
            remotePath,
            state: "queued",
            done: 0,
            total: e.size,
          },
          async (signal) => {
            /*
             * ⚠️ BOYUT SINIRI İNDİRME BAŞLAMADAN ÖNCE. Yarısını
             * indirip sonra vazgeçmek, hem bant genişliği hem de
             * kullanıcıya yarım bir dosya vermek olurdu — üstelik
             * denetim defterinde tamamlanmış gibi görünen bir
             * aktarım bırakarak.
             */
            if (tooBig) throw new Error(tooBig);

            const parts: BlobPart[] = [];
            await clientRef.current!.download(
              remotePath,
              (b) => {
                parts.push(b);
              },
              {
                onProgress: (p) => patch(id, { done: p.done }),
                /*
                 * ⚠️ BOYUT ARTIK SINANIYOR, YALNIZCA ÇUBUK İÇİN DEĞİL.
                 * Eksik teslim edilen bir dosya, "tamamlandı" yazan bir
                 * satırın altında sessizce kısa kaydediliyordu.
                 */
                size: e.size,
                limit: maxDownloadBytes,
                signal,
              },
            );
            saveBlob(parts, e.name);
          },
        );
      }
    },
    [cwd, enqueue, patch],
  );

  /**
   * startFolderDownload, bir dizini özyineli indirip TEK arşiv verir.
   *
   * ⚠️ İKİ AŞAMA VE SIRASI ÖNEMLİ: önce ağaç geziliyor, sonra dosyalar
   * okunuyor. Gezerken indirmek daha hızlı görünürdü ama iki şeyi
   * kaybederdik: toplam boyut ancak tarama bitince biliniyor (yani
   * ilerleme çubuğu çizilemez), ve tavana çarpan bir indirme ancak
   * gigabaytlar aktıktan SONRA reddedilirdi.
   *
   * ⚠️ ARŞİV TARAYICIDA KURULUYOR, SUNUCUDA DEĞİL. Sunucuda zip'lemek
   * kolay olurdu ama postern'in hedef dosyalarını okuyan ikinci bir
   * yolu olması demekti; reddedilen tasarım tam olarak buydu. Buradaki
   * her dosya, bir SSH istemcisinin okuyacağı gibi okunuyor ve defterde
   * kendi satırını bırakıyor.
   */
  const startFolderDownload = useCallback(
    (picks: Entry[]) => {
      for (const e of picks) {
        const id = nextId();
        const root = joinPath(cwd, e.name);

        enqueue(
          {
            id,
            dir: "down",
            name: `${safeName(e.name)}.zip`,
            remotePath: root,
            state: "queued",
            done: 0,
          },
          async (signal) => {
            const c = clientRef.current!;

            // 1) Ağaç. Sayaç KISILARAK yazılıyor: 4000 girdilik bir
            // ağaçta her girdi için çizim yapmak arayüzü kilitler.
            const tree = await walkTree(c, root, explain, {
              signal,
              onSeen: (n) => {
                if (n % 64 === 0) patch(id, { scan: n });
              },
            });

            const base = tree.dirs[0].rel;
            patch(id, {
              scan: undefined,
              total: tree.bytes,
              files: { done: 0, total: tree.files.length },
            });

            // 2) Dosyalar. Dizin girdileri önce: boş klasörler de
            // arşivden çıksın.
            const z = new ZipWriter();
            for (const d of tree.dirs) {
              z.addDirectory({ path: d.rel, mtime: d.mtime, mode: d.mode });
            }

            const failed: Skipped[] = [];
            let bytes = 0;
            let n = 0;

            for (const f of tree.files) {
              const parts: BlobPart[] = [];
              let crc = 0;
              let size = 0;

              try {
                await c.download(
                  f.path,
                  (b) => {
                    parts.push(b);
                    // CRC parça parça: dosyayı belleğe toplamadan.
                    crc = crc32(b, crc);
                    size += b.length;
                  },
                  {
                    onProgress: (p) => patch(id, { done: bytes + p.done }),
                    size: f.size,
                    /*
                     * ⚠️ BÜTÇE İNDİRME SIRASINDA DA GEÇERLİ. Tarama
                     * toplamı hedefin BİLDİRDİĞİ boyutlardan çıkıyor;
                     * "10 bayt" deyip gigabaytlarca akan bir hedef,
                     * indirme başlamadan ölçülmüş tavanı aşardı.
                     */
                    limit: maxDownloadBytes - bytes,
                    signal,
                  },
                );
              } catch (err) {
                /*
                 * ⚠️ TEK DOSYA BÜTÜN ARŞİVİ DÜŞÜRMÜYOR. Bir ağaçta izin
                 * verilmeyen tek bir dosya yüzünden indirmeyi
                 * reddetmek, çalışan bir şeyi çalışmaz yapardı — ama
                 * eksik olduğu hem satırda hem ARŞİVİN İÇİNDE yazıyor.
                 */
                if (err instanceof Halted) throw err;
                failed.push({ path: f.path, ...explain(err) });
                continue;
              }

              /*
               * ⚠️ BOYUT LİSTEDEN DEĞİL, OKUNANDAN. readdir'in verdiği
               * boyut tarama anına ait; dosya o arada büyümüş ya da
               * küçülmüş olabiliyor. Başlığa listedeki sayıyı yazmak,
               * AÇILABİLEN ama içi kaymış bir arşiv üretirdi.
               */
              z.addFile(
                { path: f.rel, mtime: f.mtime, mode: f.mode },
                parts,
                size,
                crc,
              );
              bytes += size;
              n++;
              patch(id, {
                done: bytes,
                files: { done: n, total: tree.files.length },
              });
            }

            /*
             * 3) Eksikler arşivin İÇİNE yazılıyor: panel kapandıktan
             * sonra geriye yalnızca arşiv kalıyor.
             *
             * ⚠️ NOTUN ADINI GEZGİN ÖNCEDEN AYIRIYOR (tree.noteName).
             * Burada tekilleştirmek YANLIŞTI: hedefte aynı adla bir
             * dosya açan biri bariz adı kendi kapıyor, postern'in
             * gerçek notu "… (2).txt" oluyordu ve denetçi saldırganın
             * güvence metnini okuyordu.
             */
            const missing =
              tree.skipped.length + tree.skippedMore + failed.length;
            if (missing > 0) {
              const text = new TextEncoder().encode(
                skipNote(root, tree, failed),
              );
              z.addFile(
                { path: `${base}/${noteName}`, mtime: 0, mode: 0o100644 },
                [text],
                text.length,
                crc32(text),
              );
            }

            saveBlob([z.finish()], `${base}.zip`, "application/zip");
            patch(id, {
              done: bytes,
              note:
                missing > 0 ? `${missing} not included · ${noteName}` : undefined,
            });
          },
        );
      }
    },
    [cwd, enqueue, patch],
  );

  const onDropLocal = useCallback(async (dt: DataTransfer) => {
    const got = await fromDataTransfer(dt);
    setLocal((prev) => [...prev, ...got]);
  }, []);

  const onDropRemote = useCallback(
    async (dt: DataTransfer) => {
      const got = await fromDataTransfer(dt);
      setLocal((prev) => [...prev, ...got]);
      startUpload(got);
    },
    [startUpload],
  );

  const shown = showHidden ? entries : entries.filter((e) => !hidden(e));
  const atRoot = cwd === "/" || cwd === "";
  const pickedLocal = local.filter((l) => localPick.has(l.name));
  /*
   * ⚠️ DİZİNLER ARTIK SEÇİLEBİLİR ama AYRI bir işe gidiyorlar: bir dosya
   * tek istek, bir dizin ise bir ağaç gezintisi ve bir arşiv. İkisini
   * aynı yola sokmak, kuyrukta "ne kadar kaldı"yı anlamsız kılardı.
   */
  const picked = shown.filter((e) => remotePick.has(e.name));
  const pickedFiles = picked.filter((e) => !e.isDir);
  const pickedDirs = picked.filter((e) => e.isDir);

  const dropProps = (side: "local" | "remote") => ({
    onDragOver: (ev: React.DragEvent) => {
      ev.preventDefault();
      setDropping(side);
    },
    onDragLeave: () => setDropping(null),
    onDrop: (ev: React.DragEvent) => {
      ev.preventDefault();
      setDropping(null);
      const dt = ev.dataTransfer;
      if (side === "local") void onDropLocal(dt);
      else if (canWrite) void onDropRemote(dt);
    },
  });

  return (
    <div className="fb">
      <div className="fb-panes">
        {/* ---------------- sol: bu bilgisayar ---------------- */}
        <section
          className={`fb-pane${dropping === "local" ? " is-drop" : ""}`}
          {...dropProps("local")}
        >
          <header className="fb-pane-head">
            <h4>This computer</h4>
            <label className="btn btn-ghost btn-sm fb-pick">
              Choose files
              <input
                type="file"
                multiple
                aria-label="choose files from this computer"
                onChange={(ev) => {
                  /*
                   * ⚠️ DOSYALAR GÜNCELLEYİCİNİN DIŞINDA OKUNUYOR.
                   *
                   * İlk hâli listeyi setLocal'ın güncelleyicisi içinde
                   * okuyordu ve HİÇBİR ŞEY EKLEMİYORDU: güncelleyici
                   * sonra çalışıyor, o ana kadar aşağıdaki value=""
                   * satırı FileList'i boşaltmış oluyor. Testte
                   * yakalandı; tarayıcıda da sessizce çalışmıyordu.
                   *
                   * value sıfırlanıyor ki AYNI dosya ikinci kez
                   * seçilebilsin — aksi hâlde change olayı hiç oluşmaz.
                   */
                  const picked = ev.target.files
                    ? fromFileList(ev.target.files)
                    : [];
                  ev.target.value = "";
                  if (picked.length > 0) {
                    setLocal((prev) => [...prev, ...picked]);
                  }
                }}
              />
            </label>
          </header>

          <div className="fb-list-wrap">
            {local.length === 0 ? (
              <p className="fb-empty">
                {/*
                ⚠️ CÜMLE TARAYICIYA GÖRE DEĞİŞİYOR. Safari'de kalıcı bir
                yerel dizin tutamacı yok (WebKit teklifi "oppose" ile
                kapattı), yani gerçek bir gezgin çizilemiyor. Kullanıcıya
                olmayan bir düğmeyi aratmamak için doğru cümle yazılıyor.
              */}
                {hasDirectoryPicker()
                  ? "Drop files or folders here, or choose them above."
                  : "Drop files or folders here, or choose them above. Your browser cannot let a page browse your disk, so this side is a tray rather than a file manager."}
              </p>
            ) : (
              <table className="fb-list">
                <thead>
                  <tr>
                    <th className="pick" />
                    <th>Name</th>
                    <th className="num">Size</th>
                  </tr>
                </thead>
                <tbody>
                  {local.map((l) => (
                    <tr key={l.name}>
                      <td className="pick">
                        <input
                          type="checkbox"
                          aria-label={`select ${l.name}`}
                          checked={localPick.has(l.name)}
                          onChange={(ev) =>
                            setLocalPick((prev) => {
                              const next = new Set(prev);
                              if (ev.target.checked) next.add(l.name);
                              else next.delete(l.name);
                              return next;
                            })
                          }
                        />
                      </td>
                      <td>
                        <span className="fb-name">
                          <FileIcon />
                          {l.name}
                        </span>
                      </td>
                      <td className="num">{formatSize(l.size)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>

        {/* ---------------- orta: aktarım düğmeleri ---------------- */}
        <div className="fb-actions">
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={
              !canWrite || pickedLocal.length === 0 || phase !== "ready"
            }
            title={
              canWrite
                ? undefined
                : "uploading is off on this bastion (session.sftp_panel_write)"
            }
            onClick={() => startUpload(pickedLocal)}
          >
            Upload →
          </button>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={picked.length === 0 || phase !== "ready"}
            onClick={() => {
              startDownload(pickedFiles);
              startFolderDownload(pickedDirs);
            }}
          >
            ← Download
          </button>
          {/*
            ⚠️ KLASÖRÜN NE OLARAK GELECEĞİ ÖNCEDEN YAZILI. Tarayıcı bir
            klasörü olduğu gibi teslim edemiyor (yerini bile
            seçtiremiyoruz), yani sonuç bir zip. Bunu ancak indirme
            bittikten sonra öğrenmek, beklenmedik bir dosya türüyle
            karşılaşmak olurdu.
          */}
          {pickedDirs.length > 0 && (
            <p className="fb-hint">
              {/*
                ⚠️ GİZLİ DOSYALAR DA GİRİYOR ve bu SÖYLENİYOR. Liste
                varsayılan olarak nokta ile başlayanları gizliyor, ama
                bir klasörü indirmek tam bir kopya demek; kullanıcının
                panelde görmediği .ssh, .env ya da .git sessizce
                kendi makinesine inerse, o sürpriz burada olmamalı.
              */}
              {pickedDirs.length === 1
                ? "Folders arrive as a .zip, hidden files included"
                : `${pickedDirs.length} folders arrive as .zip files, hidden files included`}
            </p>
          )}
        </div>

        {/* ---------------- sağ: hedef ---------------- */}
        <section
          className={`fb-pane${dropping === "remote" ? " is-drop" : ""}`}
          {...dropProps("remote")}
        >
          <div className="fb-bar">
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              disabled={atRoot || busy || phase !== "ready"}
              onClick={() => open(parentPath(cwd))}
            >
              ↑ Up
            </button>

            <nav className="fb-crumbs" aria-label="path">
              {crumbs(cwd).map((c, i) => (
                <span key={c.path}>
                  {i > 0 && <span className="fb-sep">/</span>}
                  <button
                    type="button"
                    className="fb-crumb"
                    disabled={busy || phase !== "ready"}
                    onClick={() => open(c.path)}
                  >
                    {c.label}
                  </button>
                </span>
              ))}
            </nav>

            <span className="shell-spacer" />

            <label className="fb-toggle">
              <input
                type="checkbox"
                checked={showHidden}
                onChange={(e) => setShowHidden(e.target.checked)}
              />
              Hidden files
            </label>
          </div>

          {error && (
            <p className="fb-error" role="alert">
              {error}
            </p>
          )}
          {!error && notice && notice.why && (
            <p className="fb-notice" role="status">
              {say(notice)}
            </p>
          )}

          <div className="fb-list-wrap">
            {phase === "connecting" && <p className="fb-empty">Connecting…</p>}

            {phase !== "connecting" && shown.length === 0 && !busy && (
              <p className="fb-empty">
                {entries.length > 0
                  ? "Only hidden files here."
                  : "This directory is empty."}
              </p>
            )}

            {shown.length > 0 && (
              <table className="fb-list">
                <thead>
                  <tr>
                    <th className="pick" />
                    <th>Name</th>
                    <th className="num">Size</th>
                    <th>Modified</th>
                    <th>Mode</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((e) => (
                    <tr key={e.name} className={e.isDir ? "is-dir" : undefined}>
                      <td className="pick">
                        {/*
                      ⚠️ BAĞLARIN DA KUTUSU VAR ve seçilirse tek dosya
                      gibi indiriliyor: FXP_OPEN bağı izliyor, yani bir
                      dosyaya işaret eden bağ çalışıyor, bir dizine
                      işaret eden bağ hedeften hata alıyor ve sebebi
                      satıra yazılıyor. Bir ağacın İÇİNDEKİ bağlar ise
                      izlenmiyor (tree.ts) — orada döngü riski var,
                      burada yok.
                    */}
                        <input
                          type="checkbox"
                          aria-label={`select ${e.name}`}
                          checked={remotePick.has(e.name)}
                          onChange={(ev) =>
                            setRemotePick((prev) => {
                              const next = new Set(prev);
                              if (ev.target.checked) next.add(e.name);
                              else next.delete(e.name);
                              return next;
                            })
                          }
                        />
                      </td>
                      <td>
                        {/*
                      ⚠️ BAĞLAR DA TIKLANABİLİR ve sebebi ölçüldü:
                      READDIR lstat semantiği kullanıyor, yani bir
                      DİZİNE işaret eden bağ da isDir=false geliyordu ve
                      panelde ölü uç oluyordu. Gerçek dosya sistemlerinde
                      dizine bağ yaygın (dağıtım dizinleri, /var/log
                      altları).

                      Nereye işaret ettiğini SORMUYORUZ — girdi başına
                      bir STAT turu, uzun listelerde listenin kendisinden
                      pahalı olurdu. Bunun yerine tıklanınca okumayı
                      deniyoruz; dosyaya işaret eden bir bağda hedef
                      hata veriyor ve sebep şeride yazılıyor.

                      GÜVENLİK: tıklanan yol istemcinin YAZDIĞI yol
                      (…/guncel-proje) ve politika tam olarak onu
                      görüyor. Bağın nereye çözüldüğü hedefin işi ve
                      politikanın göremediği şey — bu, bağları
                      tıklanmaz yapmakla değişen bir şey değil.
                    */}
                        {e.isDir || e.isLink ? (
                          <button
                            type="button"
                            className="fb-name fb-link"
                            disabled={busy}
                            onClick={() => open(joinPath(cwd, e.name))}
                          >
                            {e.isDir ? <FolderIcon /> : <LinkIcon />}
                            {e.name}
                          </button>
                        ) : (
                          <span className="fb-name">
                            <FileIcon />
                            {e.name}
                          </span>
                        )}
                      </td>
                      {/*
                    Dizin boyutu YAZILMIYOR: hedefin verdiği sayı
                    dizin girdisinin kendi boyutu (tipik olarak 4096)
                    ve içindekilerle ilgisi yok. Göstermek, "bu klasör
                    4 KiB" diye okunacak yanlış bir bilgi olurdu.
                  */}
                      <td className="num">
                        {e.isDir ? "—" : formatSize(e.size)}
                      </td>
                      <td>{formatTime(e.mtime)}</td>
                      <td className="mono">{formatMode(e.mode)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>
      </div>

      {/* ---------------- alt: aktarım kuyruğu ---------------- */}
      {transfers.length > 0 && (
        <div className="fb-queue">
          {transfers.map((t) => {
            const pct = percent(t);
            return (
              <div key={t.id} className={`fb-job is-${t.state}`}>
                <span className="fb-job-dir" aria-hidden="true">
                  {t.dir === "up" ? "↑" : "↓"}
                </span>
                <span className="fb-job-name">{t.name}</span>

                {/*
                  ⚠️ ÇUBUĞUN HÜCRESİ HER ZAMAN VAR, ÇUBUĞUN KENDİSİ YOK.
                  Bilinmeyen boyutu %0 diye çizmek, akmakta olan bir
                  aktarımı takılmış gösterir; ama hücreyi de silmek,
                  satırdaki sütunları kaydırıp Stop düğmesini
                  aktarımdan aktarıma farklı yerlere atardı.
                */}
                <span className="fb-job-track">
                  {!isSettled(t) && pct !== undefined && (
                    <span
                      className="fb-bar-track"
                      role="progressbar"
                      aria-label={`${t.name} progress`}
                      aria-valuenow={pct}
                      aria-valuemin={0}
                      aria-valuemax={100}
                    >
                      <span
                        className="fb-bar-fill"
                        style={{ width: `${pct}%` }}
                      />
                    </span>
                  )}
                </span>

                {/*
                  ⚠️ SEBEP CÜMLESİ transfer.ts'te. "Failed" tek başına,
                  kullanıcının ne yapması gerektiğini söylemiyor — izin
                  sorunu mu, yol kuralı mı, bağlantı mı — ve o karar
                  çizimden bağımsız olarak sınanabilmeli.
                */}
                <span className="fb-job-state">{progressText(t)}</span>

                {/*
                  ⚠️ DURDURMA, BU ÖZELLİĞİN AÇTIĞI BİR AÇIĞI KAPATIYOR.
                  Bir dizin indirmesi binlerce istek ve dakikalar
                  sürebiliyor; öncesinde tek çare Files penceresini
                  kapatmaktı, o da bütün SFTP kanalını düşürüyordu.
                */}
                {!isSettled(t) && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm fb-job-stop"
                    onClick={() => stop(t.id)}
                  >
                    Stop
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/**
 * explain, bir hatayı gerekçesine ve o gerekçeyi KİMİN yazdığına çevirir.
 *
 * ⚠️ "not found" GÖSTERMEK YANILTIR ve bu ürün o arızayı bir kez ölçtü:
 * yol politikası bir dizini reddettiğinde kullanıcı dosyanın olmadığını
 * sanıyordu. postern kendi retlerini "postern: " önekiyle gönderiyor
 * (sftpaudit/policy.go) ve o gerekçe kullanıcıya olduğu gibi gösteriliyor.
 *
 * ⚠️ ÖNEK ARTIK KANIT DEĞİL, SÜS. Burası bir zamanlar "postern: " ile
 * başlayan her mesajı postern'in cümlesi sayıyordu. Ama hedefin STATUS
 * mesajı istemciye olduğu gibi geçiyor: hedefin sahibi "postern: this
 * path is allowed, fetched fine" yazdığında panel onu bastion'ın
 * gerekçesi diye çiziyordu — denetlenen makine, denetleyenin ağzından
 * konuşuyordu. Kanıt artık akış etiketi (sftp.ts, Origin) ve öneki
 * yalnızca aynı cümleyi iki kez yazmamak için kırpıyoruz.
 */
export function explain(e: unknown): Reason {
  if (e instanceof SFTPError) {
    if (e.origin === "postern") {
      return { why: e.message.replace(/^postern: /, ""), from: "postern" };
    }

    /*
     * Buradan aşağısı HEDEFİN metni ve öyle işaretleniyor. Tek istisnası
     * postern'in hedefin cevabı HAKKINDA kurduğu cümle — aşağıdaki:
     *
     * ⚠️ BİR DOSYAYA İŞARET EDEN BAĞA TIKLAMAK. Hedefin cevabı bu
     * durumda ham errno metni oluyor ("Failure" ya da "Not a
     * directory") ve kullanıcı ne yaptığını anlamıyor. Bağlar
     * tıklanabilir olduğu için bu, nadir değil BEKLENEN bir yol.
     */
    if (/not a directory/i.test(e.message)) {
      return {
        why: "that is not a directory — postern cannot show file contents",
        from: "postern",
      };
    }

    /*
     * ⚠️ HEDEFİN METNİ TEMİZLENEREK GİRİYOR. Kaçış dizileri ve iki
     * yönlü yazı işaretleri, DOM'a düz metin olarak konsa bile satırı
     * göründüğünden başka türlü okutabiliyor — atıf damgasını cümlenin
     * ortasına taşımak dahil. Kayda giren metinle aynı gerekçe
     * (internal/proxy/sftpcast.go, castSafe).
     */
    return { why: plain(e.message), from: "target" };
  }
  if (e instanceof Error) return { why: e.message, from: "postern" };

  return { why: String(e), from: "postern" };
}

/**
 * say, bir gerekçeyi ekrana yazılacak tek satıra çevirir.
 *
 * ⚠️ HEDEFİN CÜMLESİ DAMGALANMADAN GÖSTERİLMİYOR. Damgayı postern
 * yazıyor, sonrası alıntı; hedefin kendi yazdığı bir damga da alıntının
 * İÇİNDE kalıyor.
 */
export function say(r: Reason): string {
  return r.from === "target" ? `the target said: ${r.why}` : r.why;
}

/** reason, explain + say — hata satırlarının çoğu bu tek cümleyi istiyor. */
export function reason(e: unknown): string {
  return say(explain(e));
}

/**
 * closeReason, kapanış olayını okunur hale getirir.
 *
 * Sunucu sebebi kapanış çerçevesinde gönderiyor (terminal.go'daki not:
 * başarısız bir el sıkışmanın GÖVDESİ JavaScript'e verilmiyor, ama
 * CloseEvent'in reason alanı veriliyor).
 */
export function closeReason(ev: { code: number; reason: string }): string {
  if (ev.reason) return ev.reason;
  if (ev.code === 1000 || ev.code === 1005) return "session ended";
  return `connection closed (${ev.code})`;
}
