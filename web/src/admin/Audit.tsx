import { useState } from "react";
import { api, LogEntry, Session } from "../api";
import { ActionButton, ErrorLine, ListState, useList } from "./common";
import CastPlayer from "./CastPlayer";
import DataTable, { Column } from "./DataTable";
import type { Resolved } from "../theme/mode";

/*
 * Sunucunun döndürdüğü en fazla satır sayısı (internal/httpapi/admin.go:
 * Sessions(…, 200) ve AdminLog(…, 500)). Panelde YAZILI duruyorlar:
 * denetim ekranında sessizce kırpılmış bir liste, operatöre "olan biten
 * bu kadar" dedirtir — oysa 201'inci oturum da olmuş olabilir ve onu
 * aramaya bile kalkmaz.
 *
 * ⚠️ SIRALAMA VE ARAMA İSTEMCİDE, dolayısıyla yalnızca GELEN satırlar
 * üzerinde. Sınıra dayanmış bir listede arama, elde olmayanı bulamaz —
 * kart eteğindeki uyarı tam da bunun için duruyor.
 */
const SESSION_CAP = 200;
const LOG_CAP = 500;

/*
 * Damgalar KISA biçimde yazılıyor ("28 Aug 09:31:56").
 *
 * toLocaleString() "8/28/2026, 9:31:56 AM" üretiyordu; iki damgalı bir
 * satır tabloyu ~200px genişletiyor ve sağdaki EYLEM sütununu yatay
 * kaydırmanın ardına itiyordu.
 */
const stampFmt = new Intl.DateTimeFormat(undefined, {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

/**
 * Timestamp renders an RFC3339 stamp compactly and keeps the exact
 * original in the title, for copying into a report or a log query.
 */
function Timestamp({ value }: { value: string }) {
  const d = new Date(value);
  // Ayrıştıramadığımız damgayı "Invalid Date" diye göstermek kaydın
  // kendisini gizlemek olurdu: ham değer hiç yoktan iyidir.
  if (Number.isNaN(d.getTime())) return <>{value}</>;
  return (
    <time dateTime={value} title={value}>
      {stampFmt.format(d)}
    </time>
  );
}

/**
 * sortableTime, sıralama için sayısal damga.
 *
 * ⚠️ METİN SIRALAMASI YANLIŞ OLURDU: gösterilen biçimde yıl yok ve
 * "28 Aug" ile "3 Sep" alfabetik sıralandığında Ağustos, Eylül'den
 * sonra gelir. Sıralama ham değerin zamanına bakıyor.
 */
function sortableTime(v: string | null): number {
  if (!v) return 0;
  const t = new Date(v).getTime();
  return Number.isNaN(t) ? 0 : t;
}

export function Sessions({ theme }: { theme: Resolved }) {
  const { items, error, denied, loading, refresh } = useList<Session>(api.sessions);
  // Oynatılan oturum. Aynı anda tek kayıt: iki terminali yan yana
  // izlemenin bir faydası yok, ikisini birden beslemenin maliyeti var.
  const [playing, setPlaying] = useState<string | null>(null);

  const columns: Column<Session>[] = [
    {
      key: "id",
      header: "ID",
      value: (s) => s.id,
      // Kısaltılmış kimliğin tamamı title'da: bir olayı sunucu
      // günlüğünde aratacak olan kişiye 12 hane yetmiyor.
      render: (s) => <code title={s.id}>{s.id.slice(0, 12)}…</code>,
    },
    { key: "user", header: "User", value: (s) => s.user },
    { key: "target", header: "Target", value: (s) => s.target },
    { key: "os_user", header: "OS user", value: (s) => s.os_user },
    { key: "src", header: "Src", value: (s) => s.src_ip },
    {
      key: "started",
      header: "Started",
      value: (s) => sortableTime(s.started_at),
      render: (s) => <Timestamp value={s.started_at} />,
    },
    {
      key: "ended",
      header: "Ended",
      // Süren oturum sıralamada EN SONA: 0 verseydik "hâlâ açık" olanlar
      // en eski oturumlarla karışırdı.
      value: (s) => (s.ended_at ? sortableTime(s.ended_at) : Number.MAX_SAFE_INTEGER),
      render: (s) =>
        s.ended_at ? (
          <Timestamp value={s.ended_at} />
        ) : (
          <span className="badge badge-ok">running</span>
        ),
    },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (s) => (
        <button
          onClick={() => setPlaying(s.id)}
          aria-label={`watch the recording of ${s.user} on ${s.target}, started ${s.started_at}`}
        >
          Watch
        </button>
      ),
    },
  ];

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Sessions</h2>
          <p className="page-sub">
            Every connection this bastion proxied, with the recording it kept.
          </p>
        </div>
        {/*
          Elle yenileme. Bu liste SÜREN oturumları da gösteriyor ama tek
          başına hiç tazelenmiyordu: açık bırakılmış bir sekme, o andan
          sonra bağlanan herkesi gizliyor ve "kimse bağlı değil" diyormuş
          gibi okunuyordu.
        */}
        <ActionButton onClick={refresh} label="refresh the session list">
          Refresh
        </ActionButton>
      </div>
      <ErrorLine msg={error} />

      {playing && (
        <CastPlayer sessionId={playing} theme={theme} onClose={() => setPlaying(null)} />
      )}

      <ListState
        loading={loading}
        denied={denied}
        empty={items.length === 0}
        emptyText="No sessions recorded — nobody has connected through this bastion yet."
      />

      {items.length > 0 && (
        <DataTable
          rows={items}
          columns={columns}
          rowKey={(s) => s.id}
          initialSort={{ key: "started", dir: "desc" }}
          noun="session"
          searchLabel="search sessions by user, target or address"
          searchPlaceholder="Search sessions…"
          foot={
            <p>
              postern lists at most the {SESSION_CAP} most recent sessions, and
              sorting and search work on what was returned.
              {items.length >= SESSION_CAP &&
                " This list is at that limit, so older sessions exist and are not shown here."}
            </p>
          }
        />
      )}
    </section>
  );
}

export function AdminLog() {
  const { items, error, denied, loading, refresh } = useList<LogEntry>(api.adminLog);

  const columns: Column<LogEntry>[] = [
    {
      key: "at",
      header: "At",
      value: (e) => sortableTime(e.at),
      render: (e) => <Timestamp value={e.at} />,
    },
    { key: "actor", header: "Actor", value: (e) => e.actor },
    {
      key: "via",
      header: "Via",
      value: (e) => e.via,
      render: (e) => <span className="badge">{e.via}</span>,
    },
    {
      key: "action",
      header: "Action",
      value: (e) => e.action,
      render: (e) => <code>{e.action}</code>,
    },
    { key: "entity", header: "Entity", value: (e) => e.entity },
    {
      key: "details",
      header: "Details",
      className: "wrap",
      value: (e) => e.details,
    },
  ];

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Admin log</h2>
          <p className="page-sub">
            Who changed what, and through which door — the CLI, the panel, the
            directory sync, or a first sign-in.
          </p>
        </div>
        <ActionButton onClick={refresh} label="refresh the admin log">
          Refresh
        </ActionButton>
      </div>
      <ErrorLine msg={error} />

      <ListState
        loading={loading}
        denied={denied}
        empty={items.length === 0}
        emptyText="No admin actions logged yet."
      />

      {items.length > 0 && (
        <DataTable
          rows={items}
          columns={columns}
          // ⚠️ Anahtar dizinden DEĞİL satırın kendi alanlarından. Liste
          // komple yeniden çekiliyor ve en yeni başta geliyor: yeni bir
          // kayıt eklendiğinde dizin anahtarları bir kayıyor ve React
          // eski satırın durumunu yeni satıra devrediyordu.
          rowKey={(e) => `${e.at}|${e.actor}|${e.via}|${e.action}|${e.entity}|${e.details}`}
          initialSort={{ key: "at", dir: "desc" }}
          noun="entry"
          searchLabel="search the admin log by actor, action or entity"
          searchPlaceholder="Search the log…"
          foot={
            <p>
              postern lists at most the {LOG_CAP} most recent entries, and
              sorting and search work on what was returned.
              {items.length >= LOG_CAP &&
                " This list is at that limit, so older entries exist and are not shown here."}
            </p>
          }
        />
      )}
    </section>
  );
}
