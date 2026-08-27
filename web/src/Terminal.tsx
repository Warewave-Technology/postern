import { useEffect, useRef } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

// Backend sözleşmesi (internal/httpapi/wschannel.go):
//   binary frame  (her iki yön)  : terminal verisi
//   text/JSON     (istemci→sunucu): {"type":"resize","cols":N,"rows":M}

export default function Terminal({ target, onClose }: { target: string; onClose: () => void }) {
  const hostRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!hostRef.current) return;

    const term = new XTerm({
      convertEol: false,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
      fontSize: 13,
      theme: { background: "#111", foreground: "#eee" },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);
    fit.fit();

    // ws:// veya wss:// — sayfanın şemasını izle. Sunucu https ise
    // terminal de tls üzerinden gider (config zaten https zorunlu kılıyor).
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${scheme}//${location.host}/api/terminal/${encodeURIComponent(target)}`);
    ws.binaryType = "arraybuffer";

    const sendResize = () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    };

    ws.onopen = () => {
      term.focus();
      sendResize();
    };

    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") {
        // Kontrol mesajı (exit gibi) — veri akışına karışmaz.
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === "exit") term.writeln(`\r\n[session ended: status ${msg.status}]`);
        } catch { /* tanınmayan kontrol mesajını yok say */ }
        return;
      }
      term.write(new Uint8Array(ev.data));
    };

    ws.onclose = () => term.writeln("\r\n[disconnected]");
    ws.onerror = () => term.writeln("\r\n[connection error]");

    // Klavye girdisi ham bayt olarak gider: xterm zaten kaçış dizilerini
    // üretiyor, bizim yorumlamamıza gerek yok.
    const dataSub = term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(data));
    });

    const onWindowResize = () => {
      fit.fit();
      sendResize();
    };
    window.addEventListener("resize", onWindowResize);

    return () => {
      window.removeEventListener("resize", onWindowResize);
      dataSub.dispose();
      ws.close();
      term.dispose();
    };
  }, [target]);

  return (
    <section>
      <h2>
        {target}{" "}
        <button onClick={onClose} style={{ fontSize: "0.8rem" }}>close</button>
      </h2>
      <div ref={hostRef} style={{ height: "70vh", background: "#111", padding: "0.5rem" }} />
    </section>
  );
}
