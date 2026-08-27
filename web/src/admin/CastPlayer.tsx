import { useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { api } from "../api";
import { parseCast, compress, duration, formatDuration, type CastEvent } from "../cast";

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
  const [loading, setLoading] = useState(true);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [at, setAt] = useState(0);

  // --- kaydı indir ---
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");

    api
      .sessionRecording(sessionId)
      .then((text) => {
        if (cancelled) return;
        const parsed = parseCast(text);
        const output = parsed.events.filter((e) => e.kind !== "i");
        setCast({
          cols: parsed.header.width || 80,
          rows: parsed.header.height || 24,
          events: compress(output),
          total: duration(output),
          truncated: parsed.truncated,
        });
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
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
      if (cast.events[index].kind === "o") term.write(cast.events[index].data);
    }

    const t0 = performance.now();
    let raf = 0;

    const tick = () => {
      const now = startedFrom + ((performance.now() - t0) / 1000) * speed;

      let wrote = "";
      while (index < cast.events.length && cast.events[index].playAt <= now) {
        const e = cast.events[index++];
        if (e.kind === "o") wrote += e.data;
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
    <section style={{ border: "1px solid #ccc", padding: 12, marginBottom: 16 }}>
      <header style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
        <strong>session {sessionId}</strong>
        <span style={{ flex: 1 }} />
        <button onClick={onClose}>close</button>
      </header>

      {loading && <p>loading recording…</p>}
      {error && <p style={{ color: "crimson" }}>{error}</p>}

      {cast && (
        <>
          {cast.truncated && (
            <p style={{ color: "#a60" }}>
              This session is still running — the recording ends where it had been written.
            </p>
          )}

          <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
            <button onClick={() => setPlaying((p) => !p)}>{playing ? "pause" : "play"}</button>
            <button onClick={() => seek(0)}>restart</button>

            <input
              type="range"
              min={0}
              max={Math.max(cast.total, 0.001)}
              step={0.1}
              value={at}
              onChange={(e) => seek(Number(e.target.value))}
              style={{ flex: 1, minWidth: 120 }}
              aria-label="playback position"
            />
            <span style={{ fontVariantNumeric: "tabular-nums" }}>
              {formatDuration(at)} / {formatDuration(cast.total)}
            </span>

            <label>
              speed{" "}
              <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
                {SPEEDS.map((s) => (
                  <option key={s} value={s}>
                    {s}×
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div ref={hostRef} style={{ background: "#111", padding: 8 }} />

          <p style={{ fontSize: 12, color: "#666", marginTop: 8 }}>
            Idle gaps longer than two seconds are shortened. Keystrokes are not shown —
            recordings do not capture input by default.
          </p>
        </>
      )}
    </section>
  );
}
