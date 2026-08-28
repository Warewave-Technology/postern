import { useCallback, useEffect, useRef, useState } from "react";
import { Session, api, toMessage } from "../api";
import { ErrorLine } from "./common";

/**
 * Overview — bastion'da ŞU AN ne olduğu.
 *
 * Diğer bütün yönetim ekranları geçmişe bakıyor (tablolar, denetim
 * kaydı). Güvenlik gözlemi için eksik olan buydu: bir oturum açıldığı
 * anda görmek, reddedilen bir girişi olurken görmek.
 *
 * ⚠️ KAPSAM DÜRÜSTLÜĞÜ: canlı akış yalnızca BU süreçte olan olayları
 * taşıyor. CLI'dan yapılan yönetim işlemleri başka bir süreçte çalışıyor
 * ve akışa girmiyor — onların yeri Admin log. Ekran bunu yazıyor;
 * "canlı akış her şeyi gösteriyor" sanmak, göstermediğini fark etmemek
 * demek olurdu.
 */

type LiveEvent = {
  at: string;
  kind: string;
  user?: string;
  target?: string;
  source?: string;
  detail?: string;
};

// Akışta tutulan en fazla olay. Sınırsız bırakmak, açık unutulmuş bir
// sekmede belleği günlerce büyütmek demek.
const FEED_CAP = 200;

// Akış yoksa yoklama aralığı. SSE'nin yerini tutmaz ama "hiçbir şey
// göstermeme"nin yerini tutar.
const POLL_MS = 10_000;

type Status = "connecting" | "live" | "polling";

const stampFmt = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

function kindBadge(kind: string) {
  switch (kind) {
    case "session.started":
      return <span className="badge badge-info">session</span>;
    case "session.ended":
      return <span className="badge">ended</span>;
    case "auth.denied":
      return <span className="badge badge-danger">denied</span>;
    case "auth.ok":
      return <span className="badge badge-ok">sign-in</span>;
    default:
      return <span className="badge">{kind}</span>;
  }
}

export default function Overview() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [feed, setFeed] = useState<LiveEvent[]>([]);
  const [status, setStatus] = useState<Status>("connecting");
  const [error, setError] = useState("");

  // Oturum listesi olay geldikçe tazeleniyor ama arka arkaya gelen beş
  // olay beş istek açmasın diye kısa bir gecikmeyle toplanıyor.
  const refreshTimer = useRef<number | null>(null);

  const loadSessions = useCallback(() => {
    api
      .sessions()
      .then((v) => {
        setSessions(v);
        setError("");
      })
      .catch((e: unknown) => setError(toMessage(e)));
  }, []);

  const scheduleRefresh = useCallback(() => {
    if (refreshTimer.current !== null) return;
    refreshTimer.current = window.setTimeout(() => {
      refreshTimer.current = null;
      loadSessions();
    }, 400);
  }, [loadSessions]);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  useEffect(() => {
    let es: EventSource | null = null;
    let poll: number | null = null;

    const startPolling = () => {
      if (poll !== null) return;
      setStatus("polling");
      poll = window.setInterval(loadSessions, POLL_MS);
    };

    const onEvent = (ev: MessageEvent) => {
      setStatus("live");
      let parsed: LiveEvent;
      try {
        parsed = JSON.parse(ev.data);
      } catch {
        // Tek bir bozuk çerçeve akışı düşürmemeli.
        return;
      }
      setFeed((cur) => [parsed, ...cur].slice(0, FEED_CAP));
      if (parsed.kind.startsWith("session.")) scheduleRefresh();
    };

    try {
      es = new EventSource("/api/admin/events");
    } catch {
      startPolling();
      return;
    }

    es.onopen = () => setStatus("live");
    for (const k of ["session.started", "session.ended", "auth.ok", "auth.denied"]) {
      es.addEventListener(k, onEvent as EventListener);
    }
    es.onerror = () => {
      // ⚠️ İKİ FARKLI HÂL. readyState CONNECTING ise tarayıcı kendi
      // yeniden bağlanıyor — dokunma. CLOSED ise akış kalıcı olarak
      // reddedildi (rota yok, kapasite dolu, yetki gitti): burada
      // sessizce boş bir ekranda kalmak "hiçbir şey olmuyor" gibi
      // okunurdu, oysa gerçek "bakmıyorum".
      if (es && es.readyState === EventSource.CLOSED) {
        startPolling();
      }
    };

    return () => {
      es?.close();
      if (poll !== null) window.clearInterval(poll);
      if (refreshTimer.current !== null) window.clearTimeout(refreshTimer.current);
    };
  }, [loadSessions, scheduleRefresh]);

  const active = sessions.filter((s) => !s.ended_at);
  const denials = feed.filter((e) => e.kind === "auth.denied").length;

  // "Bugün" istemcinin saat diliminde: operatör ekrana kendi saatiyle
  // bakıyor ve sunucunun UTC günü onun günü değil.
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);
  const today = sessions.filter((s) => new Date(s.started_at) >= startOfDay).length;

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Overview</h2>
          <p className="page-sub">
            What is happening on this bastion right now. The stream carries
            events from this process; actions taken with the host CLI appear in
            the admin log instead.
          </p>
        </div>
        <span className={status === "live" ? "live live-on" : "live live-off"}>
          <span className="live-dot" />
          {status === "live" ? "Live" : status === "connecting" ? "Connecting…" : "Polling"}
        </span>
      </div>

      <ErrorLine msg={error} />

      <div className="stat-grid">
        <div className="stat">
          <span className="k">Active sessions</span>
          <span className="n">{active.length}</span>
          <span className="sub">
            {active.length === 0 ? "nobody is connected" : "being recorded now"}
          </span>
        </div>
        <div className="stat">
          <span className="k">Sessions today</span>
          <span className="n">{today}</span>
          <span className="sub">since midnight, your time</span>
        </div>
        <div className="stat">
          <span className="k">Refused sign-ins</span>
          <span className="n">{denials}</span>
          <span className="sub">seen while this screen was open</span>
        </div>
        <div className="stat">
          <span className="k">Recorded sessions</span>
          <span className="n">{sessions.length}</span>
          <span className="sub">most recent {sessions.length}, newest first</span>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h3>Active sessions</h3>
          <p>Open right now. Closing one is not possible from here yet.</p>
        </div>
        {active.length === 0 ? (
          <p className="no-match">No session is open.</p>
        ) : (
          <ul className="rows">
            {active.map((s) => (
              <li key={s.id} className="row">
                <span className="row-main">
                  <span className="row-name">
                    {s.user}
                    <span className="muted">→</span>
                    {s.target}
                  </span>
                  <span className="small muted">
                    as {s.os_user} from {s.src_ip} · started{" "}
                    <time dateTime={s.started_at}>
                      {stampFmt.format(new Date(s.started_at))}
                    </time>
                  </span>
                </span>
                <span className="badge badge-ok">running</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="card">
        <div className="card-head">
          <h3>Live events</h3>
          <p>
            Newest first, kept while this screen is open — not a stored log.
            Nothing here survives a reload.
          </p>
        </div>
        {feed.length === 0 ? (
          <p className="no-match">
            {status === "polling"
              ? "The live stream is unavailable, so this screen is polling for sessions instead. Events are not shown."
              : "Nothing yet. Events appear here as they happen."}
          </p>
        ) : (
          <ul className="feed">
            {feed.map((e, i) => (
              <li key={`${e.at}-${i}`}>
                <span className="at">{stampFmt.format(new Date(e.at))}</span>
                {kindBadge(e.kind)}
                <span className="what">
                  {e.user && <b>{e.user}</b>}
                  {e.target && <> → {e.target}</>}
                  {e.source && <span className="muted"> from {e.source}</span>}
                  {e.detail && <span className="muted"> · {e.detail}</span>}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
