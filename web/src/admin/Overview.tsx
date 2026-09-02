import { useCallback, useEffect, useRef, useState } from "react";
import { Session, Storage, api, toMessage } from "../api";
import { ActionButton, ErrorLine, OkLine } from "./common";

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

/** formatBytes, insan okuyacak biçim. */
function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

/** formatAge, "3d 4h" gibi kaba ama okunur bir yaş. */
function formatAge(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export default function Overview() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [feed, setFeed] = useState<LiveEvent[]>([]);
  const [status, setStatus] = useState<Status>("connecting");
  const [error, setError] = useState("");
  // ⚠️ Başarı kanalı YOKTU: kapatma, ekran okuyucuya tamamen
  // sessiz kalırdı ve gören kullanıcı için de satırın kaybolması
  // dışında bir işaret olmazdı.
  const [okMsg, setOkMsg] = useState("");
  const [storage, setStorage] = useState<Storage | null>(null);

  // Oturum listesi olay geldikçe tazeleniyor ama arka arkaya gelen beş
  // olay beş istek açmasın diye kısa bir gecikmeyle toplanıyor.
  const refreshTimer = useRef<number | null>(null);

  // Söz DÖNÜYOR: çağıranın tazelemenin bitmesini bekleyebilmesi gerekiyor
  // (bkz. closeSession — bu fonksiyon başarıda hata satırını temizliyor).
  /*
   * ⚠️ DEPOLAMA, OTURUMLARLA AYNI TAZELEMEDE ÇEKİLİYOR.
   *
   * Ayrı bir zamanlayıcı, arşiv sıkışmasını oturum listesinden farklı
   * bir anda gösterirdi; operatör iki rakamı yan yana okuyup "bu
   * oturumlar neden birikiyor" diye soramazdı.
   *
   * Hatası oturum listesini DÜŞÜRMÜYOR: depolama okunamıyorsa kart
   * sebebini yazıyor, ekranın geri kalanı çalışmaya devam ediyor.
   */
  const loadStorage = useCallback(
    () =>
      api
        .storage()
        .then(setStorage)
        .catch(() => setStorage(null)),
    [],
  );

  const loadSessions = useCallback(
    () =>
      api
        .sessions()
        .then((v) => {
          setSessions(v);
          setError("");
        })
        .catch((e: unknown) => setError(toMessage(e))),
    [],
  );

  /*
   * closeSession, oturumu kapatır ve listeyi SUNUCUDAN tazeler.
   *
   * ⚠️ İYİMSER SİLME YOK. Satırı hemen listeden atmak, kapatma
   * başarısız olduğunda oturumu gizlerdi — operatör akan bir oturumu
   * kapanmış sanardı. Gerçeği sunucu söylüyor.
   *
   * ⚠️ OLAY AKIŞINI BEKLEMİYORUZ. SessionEnded artık ended_at
   * yazıldıktan SONRA yayınlanıyor (proxy.Session.Close), ama akış
   * sadece bu sürecin olaylarını taşıyor ve bağlantı kopmuş olabilir.
   * Doğrudan tazelemek, düğmenin cevabını akışın sağlığına bağlamıyor.
   */
  const closeSession = async (s: Session) => {
    setError("");
    setOkMsg("");
    try {
      await api.terminateSession(s.id);
      setOkMsg(`Closed ${s.user}'s session on ${s.target}.`);
      await loadSessions();
    } catch (e: unknown) {
      /*
       * ⚠️ ÖNCE TAZELE, SONRA HATAYI YAZ — ve bunu bir test yakaladı.
       *
       * loadSessions başarılı çekimde setError("") yapıyor. Hatayı önce
       * yazsaydık tazeleme onu SİLERDİ: kapatma başarısız olur, satır
       * yerinde durur ve ekranda tek bir işaret bulunmazdı. Operatör
       * "bastım, bir şey olmadı" ile "bastım, olmadı ve sebebi şu"
       * arasındaki farkı kaybederdi.
       */
      const msg = toMessage(e);
      await loadSessions();
      setError(msg);
    }
  };

  const scheduleRefresh = useCallback(() => {
    if (refreshTimer.current !== null) return;
    refreshTimer.current = window.setTimeout(() => {
      refreshTimer.current = null;
      loadSessions();
    }, 400);
  }, [loadSessions]);

  useEffect(() => {
    loadSessions();
    loadStorage();
  }, [loadSessions, loadStorage]);

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
    for (const k of [
      "session.started",
      "session.ended",
      "auth.ok",
      "auth.denied",
    ]) {
      es.addEventListener(k, onEvent as EventListener);
    }
    es.onerror = () => {
      // ⚠️ İKİ FARKLI HÂL. readyState CONNECTING ise tarayıcı kendi
      // yeniden bağlanıyor. CLOSED ise akış kalıcı olarak reddedildi
      // (rota yok, kapasite dolu, yetki gitti): burada sessizce boş bir
      // ekranda kalmak "hiçbir şey olmuyor" gibi okunurdu, oysa gerçek
      // "bakmıyorum".
      if (es && es.readyState === EventSource.CLOSED) {
        startPolling();
        return;
      }
      // ⚠️ YENİDEN BAĞLANIRKEN "Live" DEMEK YALAN. Ölçüldü: sunucu
      // yeniden başlatıldığında akış kopuyor, tarayıcı sessizce
      // yeniden denemeye giriyor ve rozet "Live" kalıyordu — operatör
      // dakikalarca donmuş sayılara canlıymış gibi bakıyordu. Kopuk
      // olduğunu söylemek, boş bir ekran göstermekten farklı: veri
      // hâlâ orada, yalnızca artık taze olmadığı biliniyor.
      setStatus("connecting");
    };

    return () => {
      es?.close();
      if (poll !== null) window.clearInterval(poll);
      if (refreshTimer.current !== null)
        window.clearTimeout(refreshTimer.current);
    };
  }, [loadSessions, scheduleRefresh]);

  /*
   * ⚠️ AÇIK SATIR ≠ AKAN OTURUM.
   *
   * ended_at'in boş olması "bitişini kaydetmedik" demek. postern SIGKILL
   * yerse o satır sonsuza dek boş kalıyor (ölçüldü) ve panel onu süresiz
   * "çalışıyor" gösteriyordu. Artık sunucu her satıra `running` koyuyor:
   * gerçeği yalnızca süreçteki defter biliyor.
   *
   * Akmayanı gizlemiyoruz — açık ama akmayan satır, bir çökmenin izi ve
   * operatörün görmesi gereken bir şey; yalnızca "çalışıyor" demiyoruz
   * ve kapatma düğmesini ona çizmiyoruz.
   */
  const openRows = sessions.filter((s) => !s.ended_at);
  const active = openRows.filter((s) => s.running !== false);
  const stranded = openRows.filter((s) => s.running === false);
  const denials = feed.filter((e) => e.kind === "auth.denied").length;

  // "Bugün" istemcinin saat diliminde: operatör ekrana kendi saatiyle
  // bakıyor ve sunucunun UTC günü onun günü değil.
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);
  const today = sessions.filter(
    (s) => new Date(s.started_at) >= startOfDay,
  ).length;

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
          {status === "live"
            ? "Live"
            : status === "connecting"
              ? "Connecting…"
              : "Polling"}
        </span>
      </div>

      <ErrorLine msg={error} />
      <OkLine msg={okMsg} />

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
          <span className="sub">
            most recent {sessions.length}, newest first
          </span>
        </div>
        <div className="stat">
          <span className="k">Recordings on disk</span>
          <span className="n">
            {storage?.recordings ? formatBytes(storage.recordings.bytes) : "—"}
          </span>
          <span className="sub">
            {storage?.recordings_error
              ? "could not be measured"
              : storage?.recordings
                ? `${storage.recordings.files} file${storage.recordings.files === 1 ? "" : "s"}`
                : "not measured"}
          </span>
        </div>
        {/*
          ⚠️ BEKLEYEN SAYISI DEĞİL, EN ESKİSİNİN YAŞI ÖNE ÇIKIYOR.
          Ölmüş bir yükleyicinin belirtisi sayının artması değil: sabit
          bir sayı da hiçbir şeyin ilerlemediği anlamına gelebilir.
          Yüklenemeyen kayıt budanmadığı için bu, diskin dolacağını
          haftalar öncesinden söyleyen tek işaret.
        */}
        <div className="stat">
          <span className="k">Waiting to archive</span>
          <span className="n">
            {storage?.archive_error ? "?" : (storage?.archive?.pending ?? "—")}
          </span>
          <span className="sub">
            {storage?.archive_error
              ? "could not be read"
              : !storage?.archive
                ? "not measured"
                : storage.archive.pending === 0
                  ? "nothing waiting"
                  : storage.archive.oldest_age_seconds !== undefined
                    ? `oldest ${formatAge(storage.archive.oldest_age_seconds)} — these cannot be pruned while they wait`
                    : "waiting"}
          </span>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h3>Active sessions</h3>
          {/*
            ⚠️ CÜMLE, DÜĞMENİN YAPMADIĞINI SÖYLÜYOR. Kapatma bağlantıyı
            düşürüyor ama erişimi almıyor: roller bağlanma anında
            çözülüyor ve hesaba dokunulmadığı için kişi hemen yeniden
            bağlanabiliyor. Olay anındaki bir yönetici "kestim, artık
            dışarıda" diye okursa, ekran ona yalan söylemiş olur.
          */}
          <p>
            Open right now. Closing one ends the connection; it does not take
            access away.
          </p>
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
                <span className="row-actions">
                  <span className="badge badge-ok">running</span>
                  <ActionButton
                    variant="danger"
                    /* ⚠️ "close", "kill" DEĞİL: paneldeki fiiller Revoke,
                       Deactivate, Delete, Remove — "kill" bu sözlükte yok. */
                    label={`close ${s.user}'s session on ${s.target}`}
                    /*
                      ⚠️ HİÇBİR ÇARE ADI VERİLMİYOR ve bu, ölçtükten
                      sonra alınmış bir karar. İlk metin "hesabı Users
                      sayfasından pasifleştirmek bunu durdurur" diyordu.
                      DOĞRU DEĞİL: dört giriş yolunun dördü de
                      ConfirmAccount çağırıyor ve o, 'inactive'i
                      'active'e geri çeviriyor (store/accountstate.go).
                      Yani pasifleştirme dizin/OIDC/parola ile girenleri
                      durdurmuyor. Operatörden güvenmesini istediğimiz
                      kutuya yarı doğru bir vaat koymak, hiçbir şey
                      dememekten kötü.
                    */
                    confirm={
                      `Close ${s.user}'s session on ${s.target}?\n\n` +
                      `The connection drops and the recording is kept. It does ` +
                      `not take access away: ${s.user} can reconnect straight ` +
                      `away unless you also remove what grants it.`
                    }
                    onClick={() => closeSession(s)}
                  >
                    Close
                  </ActionButton>
                </span>
              </li>
            ))}
          </ul>
        )}
        {stranded.length > 0 && (
          <p className="small muted stranded-note">
            {stranded.length === 1
              ? "1 more row is still open but nothing here is carrying it"
              : `${stranded.length} more rows are still open but nothing here is carrying them`}{" "}
            — left over from an earlier run of this bastion. They cannot be
            closed from here; a restart clears them.
          </p>
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
