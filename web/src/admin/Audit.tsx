import { useState } from "react";
import { api, LogEntry, Session } from "../api";
import { ActionButton, ErrorLine, ListState, useList } from "./common";
import CastPlayer from "./CastPlayer";

/*
 * Sunucunun döndürdüğü en fazla satır sayısı (internal/httpapi/admin.go:
 * Sessions(…, 200) ve AdminLog(…, 500)). Panelde YAZILI duruyorlar:
 * denetim ekranında sessizce kırpılmış bir liste, operatöre "olan biten
 * bu kadar" dedirtir — oysa 201'inci oturum da olmuş olabilir ve onu
 * aramaya bile kalkmaz.
 *
 * Sunucu tarafını buradan değiştiremiyoruz; en azından söyleyebiliyoruz.
 */
const SESSION_CAP = 200;
const LOG_CAP = 500;

/**
 * Timestamp renders an RFC3339 stamp in the viewer's locale and keeps the
 * exact original in the title, for copying into a report or a log query.
 */
function Timestamp({ value }: { value: string }) {
  const d = new Date(value);
  // Ayrıştıramadığımız damgayı "Invalid Date" diye göstermek kaydın
  // kendisini gizlemek olurdu: ham değer hiç yoktan iyidir.
  if (Number.isNaN(d.getTime())) return <>{value}</>;
  return (
    <time dateTime={value} title={value}>
      {d.toLocaleString()}
    </time>
  );
}

export function Sessions() {
  const { items, error, denied, loading, refresh } = useList<Session>(api.sessions);
  // Oynatılan oturum. Aynı anda tek kayıt: iki terminali yan yana
  // izlemenin bir faydası yok, ikisini birden beslemenin maliyeti var.
  const [playing, setPlaying] = useState<string | null>(null);

  return (
    <section>
      <h2>Sessions</h2>
      <ErrorLine msg={error} />

      {/*
        Elle yenileme. Bu liste SÜREN oturumları da gösteriyor ama tek
        başına hiç tazelenmiyordu: açık bırakılmış bir sekme, o andan
        sonra bağlanan herkesi gizliyor ve "kimse bağlı değil" diyormuş
        gibi okunuyordu.
      */}
      <div className="field-row">
        <ActionButton onClick={refresh} label="refresh the session list">
          Refresh
        </ActionButton>
      </div>

      {playing && <CastPlayer sessionId={playing} onClose={() => setPlaying(null)} />}

      <ListState
        loading={loading}
        denied={denied}
        empty={items.length === 0}
        emptyText="No sessions recorded — nobody has connected through this bastion yet."
      />

      {items.length > 0 && (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>User</th>
                  <th>Target</th>
                  <th>OS user</th>
                  <th>Src</th>
                  <th>Started</th>
                  <th>Ended</th>
                  <th>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((s) => (
                  <tr key={s.id}>
                    {/* Kısaltılmış kimliğin tamamı title'da: bir olayı
                        sunucu günlüğünde aratacak olan kişiye 12 hane
                        yetmiyor. */}
                    <td>
                      <code title={s.id}>{s.id.slice(0, 12)}…</code>
                    </td>
                    <td>{s.user}</td>
                    <td>{s.target}</td>
                    <td>{s.os_user}</td>
                    <td>{s.src_ip}</td>
                    <td>
                      <Timestamp value={s.started_at} />
                    </td>
                    <td>{s.ended_at ? <Timestamp value={s.ended_at} /> : "running"}</td>
                    <td>
                      <button
                        onClick={() => setPlaying(s.id)}
                        aria-label={`watch the recording of ${s.user} on ${s.target}, started ${s.started_at}`}
                      >
                        watch
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="muted small">
            postern lists at most the {SESSION_CAP} most recent sessions.
            {items.length >= SESSION_CAP &&
              " This list is at that limit, so older sessions exist and are not shown here."}
          </p>
        </>
      )}
    </section>
  );
}

export function AdminLog() {
  const { items, error, denied, loading, refresh } = useList<LogEntry>(api.adminLog);

  return (
    <section>
      <h2>Admin log</h2>
      <ErrorLine msg={error} />

      <div className="field-row">
        <ActionButton onClick={refresh} label="refresh the admin log">
          Refresh
        </ActionButton>
      </div>

      <ListState
        loading={loading}
        denied={denied}
        empty={items.length === 0}
        emptyText="No admin actions logged yet."
      />

      {items.length > 0 && (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>At</th>
                  <th>Actor</th>
                  <th>Via</th>
                  <th>Action</th>
                  <th>Entity</th>
                  <th className="wrap">Details</th>
                </tr>
              </thead>
              <tbody>
                {items.map((e) => (
                  // ⚠️ Anahtar dizinden DEĞİL satırın kendi alanlarından.
                  // Liste komple yeniden çekiliyor ve en yeni başta
                  // geliyor: yeni bir kayıt eklendiğinde dizin anahtarları
                  // bir kayıyor, React da eski satırın durumunu yeni
                  // satıra devrediyordu.
                  <tr key={`${e.at}|${e.actor}|${e.via}|${e.action}|${e.entity}|${e.details}`}>
                    <td>
                      <Timestamp value={e.at} />
                    </td>
                    <td>{e.actor}</td>
                    <td>{e.via}</td>
                    <td>
                      <code>{e.action}</code>
                    </td>
                    <td>{e.entity}</td>
                    <td className="wrap">{e.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="muted small">
            postern lists at most the {LOG_CAP} most recent entries.
            {items.length >= LOG_CAP &&
              " This list is at that limit, so older entries exist and are not shown here."}
          </p>
        </>
      )}
    </section>
  );
}
