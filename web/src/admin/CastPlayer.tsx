import { useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { ApiError, api, toMessage } from "../api";
import { ErrorLine, WarnLine } from "./common";
import {
  parseCast, compress, duration, formatDuration, initialSize, parseResize,
  type CastEvent,
} from "../cast";

// Oturum kaydı oynatıcı.
//
// Kaydı zaten bağımlı olduğumuz xterm.js'e geri oynatıyor. Neden
// asciinema-player değil: bkz. cast.ts başındaki not — paket WASM
// kullanıyor ve postern'in CSP'si onu engelliyor.
//
// Girdi olayları ("i") BİLEREK oynatılmıyor: kayıt varsayılan olarak
// girdiyi tutmuyor (sudo parolası girdidir), tutan kurulumlarda da onu
// ekrana basmak kaydın kendisinden daha fazlasını göstermek olurdu.

type Loaded = {
  cols: number;
  rows: number;
  events: Array<CastEvent & { playAt: number }>;
  total: number;
  truncated: boolean;
};

const SPEEDS = [0.5, 1, 2, 4, 8];

export default function CastPlayer({ sessionId, onClose }: { sessionId: string; onClose: () => void }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);

  const [cast, setCast] = useState<Loaded | null>(null);
  const [error, setError] = useState("");
  // missing, "kayıt yok"u "istek düştü"den AYIRIR: ilki oturumun bir
  // olgusu, ikincisi panelin arızası. Aynı kırmızı satırda göstermek,
  // operatöre olmayan bir arızayı aratır.
  const [missing, setMissing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [at, setAt] = useState(0);

  // --- kaydı indir ---
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    setMissing(false);

    api
      .sessionRecording(sessionId)
      .then((text) => {
        if (cancelled) return;
        const parsed = parseCast(text);
        // "i" (girdi) olayları oynatılmıyor — kayıt varsayılan olarak
        // girdiyi tutmuyor zaten. "r" (boyut) olayları TUTULUYOR:
        // oynatıcı onları uygulamazsa her kayıt 80x24 görünür.
        const output = parsed.events.filter((e) => e.kind !== "i");
        const size = initialSize(parsed.header, output);
        setCast({
          cols: size.cols,
          rows: size.rows,
          events: compress(output),
          total: duration(output),
          truncated: parsed.truncated,
        });
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        // 404'ün gövdesi JSON değil, dolayısıyla elimize yalnız
        // "Not Found" geçiyor — bu, kaydın neden yokluğunu izlemeye
        // gelen kişiye hiçbir şey anlatmıyor.
        if (e instanceof ApiError && e.status === 404) {
          setMissing(true);
          return;
        }
        // toMessage üzerinden: Error olmayan bir reddediş boş mesaj
        // bırakıyor, boş mesajda ErrorLine hiçbir şey çizmiyor ve
        // yüklenemeyen bir kayıt boş bir oynatıcı gibi görünüyordu.
        setError(toMessage(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [sessionId]);

  // --- terminali kur ---
  useEffect(() => {
    if (!cast || !hostRef.current) return;

    const term = new XTerm({
      cols: cast.cols,
      rows: cast.rows,
      convertEol: false,
      // Oynatıcıda klavye girdisi YOK: bu bir kayıt, bir oturum değil.
      disableStdin: true,
      scrollback: 5000,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
      fontSize: 13,
      theme: { background: "#111", foreground: "#eee" },
    });
    term.open(hostRef.current);
    termRef.current = term;

    return () => {
      termRef.current = null;
      term.dispose();
    };
  }, [cast]);

  // --- oynatma döngüsü ---
  useEffect(() => {
    const term = termRef.current;
    if (!cast || !term || !playing) return;

    // İleri sarma yok: xterm bir durum makinesi ve ara bir noktaya
    // "atlamak" için o noktaya kadarki tüm baytların yazılmış olması
    // gerekiyor. Konum değişince baştan yeniden besliyoruz.
    let index = 0;
    term.reset();
    const startedFrom = at;
    for (; index < cast.events.length && cast.events[index].playAt < startedFrom; index++) {
      const e = cast.events[index];
      if (e.kind === "o") term.write(e.data);
      // Geri sarmada da boyut uygulanmalı: aksi hâlde ortadan
      // başlayan oynatma yanlış genişlikte akar.
      if (e.kind === "r") {
        const size = parseResize(e.data);
        if (size) term.resize(size.cols, size.rows);
      }
    }

    const t0 = performance.now();
    let raf = 0;

    const tick = () => {
      const now = startedFrom + ((performance.now() - t0) / 1000) * speed;

      let wrote = "";
      while (index < cast.events.length && cast.events[index].playAt <= now) {
        const e = cast.events[index++];
        if (e.kind === "o") {
          wrote += e.data;
          continue;
        }
        if (e.kind === "r") {
          // Boyut değişimi biriken çıktıdan SONRA uygulanmalı:
          // yeni geometriye yazmak, eski geometride üretilmiş
          // satırları yanlış sarardı.
          if (wrote) {
            term.write(wrote);
            wrote = "";
          }
          const size = parseResize(e.data);
          if (size) term.resize(size.cols, size.rows);
        }
      }
      if (wrote) term.write(wrote);

      setAt(Math.min(now, cast.total));

      if (index >= cast.events.length) {
        setPlaying(false);
        return;
      }
      raf = requestAnimationFrame(tick);
    };

    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // at bilerek bağımlılıkta değil: her karede değişiyor ve döngüyü
    // sürekli yeniden kurardı. Konum değişimi seek() üzerinden geliyor.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cast, playing, speed]);

  const seek = (to: number) => {
    setAt(to);
    setPlaying(false);
    termRef.current?.reset();
  };

  return (
    <section className="panel" aria-label={`recording of session ${sessionId}`}>
      <header className="panel-header">
        <div className="panel-title">
          <h3>Recording</h3>
          <code className="muted">{sessionId}</code>
        </div>
        <span className="spacer" />
        <button
          className="btn-quiet"
          onClick={onClose}
          aria-label={`close the recording of session ${sessionId}`}
        >
          Close
        </button>
      </header>

      {loading && <p className="state">Loading recording…</p>}
      <ErrorLine msg={error} />
      {missing && (
        <WarnLine msg="postern has no recording for this session — either recording was switched off while it ran, or the file has since been removed from the recordings directory." />
      )}

      {cast && (
        <>
          {cast.truncated && (
            <WarnLine msg="This session is still running — the recording ends where it had been written." />
          )}

          <div className="player-controls">
            <button
              onClick={() => setPlaying((p) => !p)}
              aria-label={playing ? "pause playback" : "play the recording"}
            >
              {playing ? "Pause" : "Play"}
            </button>
            <button onClick={() => seek(0)} aria-label="restart from the beginning">
              Restart
            </button>

            <input
              type="range"
              min={0}
              max={Math.max(cast.total, 0.001)}
              step={0.1}
              value={at}
              onChange={(e) => seek(Number(e.target.value))}
              aria-label="playback position"
            />
            <span className="player-time">
              {formatDuration(at)} / {formatDuration(cast.total)}
            </span>

            <label>
              speed
              <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
                {SPEEDS.map((s) => (
                  <option key={s} value={s}>
                    {s}×
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className="surface-dark">
            <div ref={hostRef} className="terminal-host" />
          </div>

          <p className="note">
            Idle gaps longer than two seconds are shortened. Keystrokes are not shown —
            recordings do not capture input by default.
          </p>
        </>
      )}
    </section>
  );
}
