import { useCallback, useEffect, useRef, useState } from "react";
import { SFTPClient, SFTPError, FX } from "./sftp";
import type { Entry } from "./sftp";
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
 * İNDİRME KASTEN YOK. Dosya içeriğini tarayıcıya getirmek ayrı bir
 * karar: kaydın ne göstereceği, boyut sınırı ve veri çıkışı politikası
 * ayrıca konuşulmadan açılmamalı.
 */

type Phase = "connecting" | "ready" | "closed";

export default function FileBrowser({ target }: { target: string }) {
  const clientRef = useRef<SFTPClient | null>(null);
  const [phase, setPhase] = useState<Phase>("connecting");
  const [cwd, setCwd] = useState("");
  const [entries, setEntries] = useState<Entry[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [showHidden, setShowHidden] = useState(false);

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
       * ⚠️ İLK BAYT AKIŞ ETİKETİ (wschannel.go): 0 kanal verisi, 1
       * stderr. Etiketi ayıklamadan çözümleyiciye vermek, her
       * çerçevede paket sınırını bir bayt kaydırırdı.
       */
      if (frame[0] === 1) {
        // postern'in gerekçesi. Cevabı beklenen bir istek varsa aynı
        // sebep zaten hata olarak da geliyor; bu kanal, isteğe
        // bağlanamayan durumlar için.
        setNotice(new TextDecoder().decode(frame.subarray(1)).trim());
        return;
      }
      client.feed(frame.subarray(1));
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

  const shown = showHidden ? entries : entries.filter((e) => !hidden(e));
  const atRoot = cwd === "/" || cwd === "";

  return (
    <div className="fb">
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
      {!error && notice && (
        <p className="fb-notice" role="status">
          {notice}
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
                <th>Name</th>
                <th className="num">Size</th>
                <th>Modified</th>
                <th>Mode</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((e) => (
                <tr key={e.name} className={e.isDir ? "is-dir" : undefined}>
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
                  <td className="num">{e.isDir ? "—" : formatSize(e.size)}</td>
                  <td>{formatTime(e.mtime)}</td>
                  <td className="mono">{formatMode(e.mode)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

/**
 * reason, bir hatayı kullanıcıya söylenecek cümleye çevirir.
 *
 * ⚠️ "not found" GÖSTERMEK YANILTIR ve bu ürün o arızayı bir kez
 * ölçtü: yol politikası bir dizini reddettiğinde kullanıcı dosyanın
 * olmadığını sanıyordu. postern kendi retlerini "postern: " önekiyle
 * gönderiyor (sftpaudit/policy.go); o mesaj varsa OLDUĞU GİBİ
 * gösteriliyor, çünkü sebebi zaten o yazıyor.
 */
export function reason(e: unknown): string {
  if (e instanceof SFTPError) {
    if (e.message.startsWith("postern: ")) return e.message.slice(9);
    /*
     * ⚠️ BİR DOSYAYA İŞARET EDEN BAĞA TIKLAMAK. Hedefin cevabı bu
     * durumda ham errno metni oluyor ("Failure" ya da "Not a
     * directory") ve kullanıcı ne yaptığını anlamıyor. Bağlar
     * tıklanabilir olduğu için bu, nadir değil BEKLENEN bir yol.
     */
    if (/not a directory/i.test(e.message)) {
      return "that is not a directory — postern cannot show file contents";
    }
    if (e.code === FX.PERMISSION_DENIED) {
      return `permission denied on the target: ${e.message}`;
    }
    return e.message;
  }
  if (e instanceof Error) return e.message;
  return String(e);
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
