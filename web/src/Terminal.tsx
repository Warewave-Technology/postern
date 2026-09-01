import { useEffect, useRef } from "react";
import { gruvbox, terminalFont } from "./theme/terminal";
import type { Resolved } from "./theme/mode";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

// Backend sözleşmesi (internal/httpapi/wschannel.go):
//   binary frame  (her iki yön)  : terminal verisi
//   text/JSON     (istemci→sunucu): {"type":"resize","cols":N,"rows":M}

export default function Terminal({
  target,
  onClose,
  theme,
  fullScreen,
}: {
  target: string;
  onClose?: () => void;
  /** Çözülmüş tema — xterm paleti CSS değişkeninden okuyamıyor. */
  theme: Resolved;
  /** Tam ekran kabuk sayfası: kendi başlığını çizmiyor. */
  fullScreen?: boolean;
}) {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);

  useEffect(() => {
    if (!hostRef.current) return;

    const term = new XTerm({
      convertEol: false,
      // Tema ve yazı ayarları TEK KAYNAKTAN (theme/terminal.ts): canlı
      // izleyen ile kaydından izleyen operatör aynı renkleri görmeli.
      theme: gruvbox(theme),
      ...terminalFont,
    });
    termRef.current = term;
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);

    // ws:// veya wss:// — sayfanın şemasını izle. Sunucu https ise
    // terminal de tls üzerinden gider (config zaten https zorunlu kılıyor).
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(
      `${scheme}//${location.host}/api/terminal/${encodeURIComponent(target)}`,
    );
    ws.binaryType = "arraybuffer";

    const sendResize = () => {
      // Sıfır ya da negatif boyut GÖNDERİLMEZ. Sunucu bunu zaten
      // sınırlıyor (proxy.clampDim) ama bozuk bir ölçümü tele koymanın
      // bir faydası yok: hedefteki kabuk de bu boyutu görüyor.
      if (term.cols < 1 || term.rows < 1) return;
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(
          JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }),
        );
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
          if (msg.type === "exit")
            term.writeln(`\r\n[session ended: status ${msg.status}]`);
        } catch {
          /* tanınmayan kontrol mesajını yok say */
        }
        return;
      }
      term.write(new Uint8Array(ev.data));
    };

    /*
     * ⚠️ KAPANIŞ SEBEBİ VARSA ONU YAZ.
     *
     * ÖLÇÜLEN ARIZA: hedefi bu bastion'ın CA'sına güvenecek şekilde
     * yapılandırmamış bir kurulumda, kabuk düğmesine basan kullanıcının
     * gördüğü tek şey "[disconnected]" idi. Sunucu sebebi biliyordu
     * ama upgrade'den ÖNCE HTTP hatası döndürüyordu — ve tarayıcı,
     * başarısız bir WebSocket el sıkışmasının durum kodunu da gövdesini
     * de JavaScript'e vermiyor. Sebep artık kapanış çerçevesiyle
     * geliyor (internal/httpapi/terminal.go).
     *
     * Sebep YOKSA eski metin kalıyor: normal çıkışta da onclose
     * çalışıyor ve orada söylenecek bir şey yok.
     */
    ws.onclose = (ev) => {
      const why = (ev.reason || "").trim();
      term.writeln(why ? `\r\n[${why}]` : "\r\n[disconnected]");
    };
    /*
     * onerror'da sebep YOK ve olamaz: tarayıcı el sıkışma hatasının
     * ayrıntısını kasten gizliyor. Buraya bir açıklama uydurmak,
     * bilmediğimiz bir şeyi biliyormuş gibi göstermek olurdu — onclose
     * hemen ardından çalışıyor ve varsa gerçek sebebi o yazıyor.
     */
    ws.onerror = () => term.writeln("\r\n[connection error]");

    // Klavye girdisi ham bayt olarak gider: xterm zaten kaçış dizilerini
    // üretiyor, bizim yorumlamamıza gerek yok.
    const dataSub = term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN)
        ws.send(new TextEncoder().encode(data));
    });

    /*
     * ⚠️ İLK fit() open() İLE AYNI TİKTE ÇAĞRILAMAZ.
     *
     * Ölçülen kusur: `term.open(); fit.fit();` sırayla çağrıldığında
     * xterm'in karakter ölçüm öğesi henüz yerleşmemiş oluyor ve fit
     * saçma bir hücre genişliği buluyor. Kayda düşen kanıt: pty 80x24
     * açılıp hemen ardından "2x16"ya küçültülüyordu — hedefteki kabuk
     * karşılama metnini iki karakterde bir sarıyordu.
     *
     * ResizeObserver bunu iki yönden çözüyor: ilk çağrısı yerleşimden
     * SONRA geliyor, ve pencere boyutu değişmeden kabın genişliği
     * değiştiğinde de (kenar menüsünün kırılma noktası, terminalin
     * açılması) terminal kendini düzeltiyor. Yalnız window.resize
     * dinlemek bu ikinci durumu kaçırıyordu.
     */
    const ro = new ResizeObserver(() => {
      // Kap ölçülemez durumdayken (gizli sekme, 0 genişlik) fit
      // çağırmak yine saçma bir boyut üretir; dokunma.
      if (!hostRef.current || hostRef.current.clientWidth === 0) return;
      fit.fit();
      sendResize();
    });
    ro.observe(hostRef.current);

    return () => {
      ro.disconnect();
      dataSub.dispose();
      ws.close();
      term.dispose();
      termRef.current = null;
    };
    // ⚠️ theme BAĞIMLILIK LİSTESİNDE YOK ve bilerek: listeye girseydi
    // tema değişimi terminali yeniden kurar, yani WebSocket'i kapatıp
    // ÇALIŞAN OTURUMU ÖLDÜRÜRDÜ. Palet aşağıdaki ayrı effect ile
    // yerinde güncelleniyor.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target]);

  // Tema değişince paleti YERİNDE değiştir: oturum yaşamaya devam eder.
  useEffect(() => {
    if (termRef.current) termRef.current.options.theme = gruvbox(theme);
  }, [theme]);

  // Ölçüler ve renkler stil dosyasında: inline stil prefers-color-scheme
  // ifade edemiyor.
  if (fullScreen) {
    return (
      <div className="shell-surface">
        <div ref={hostRef} className="terminal-host shell-fill" />
      </div>
    );
  }

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>{target}</h2>
          <p className="page-sub">
            Live session — everything in this window is being recorded.
          </p>
        </div>
        {onClose && <button onClick={onClose}>Close session</button>}
      </div>
      <div className="surface-dark">
        <div ref={hostRef} className="terminal-host terminal-live" />
      </div>
    </section>
  );
}
