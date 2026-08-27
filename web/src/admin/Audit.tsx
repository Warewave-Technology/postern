import { useState } from "react";
import { api, LogEntry, Session } from "../api";
import { ErrorLine, td, th, useList } from "./common";
import CastPlayer from "./CastPlayer";

export function Sessions() {
  const { items, error } = useList<Session>(api.sessions);
  // Oynatılan oturum. Aynı anda tek kayıt: iki terminali yan yana
  // izlemenin bir faydası yok, ikisini birden beslemenin maliyeti var.
  const [playing, setPlaying] = useState<string | null>(null);

  return (
    <section>
      <h2>Sessions</h2>
      <ErrorLine msg={error} />

      {playing && <CastPlayer sessionId={playing} onClose={() => setPlaying(null)} />}

      <table style={{ borderCollapse: "collapse" }}>
        <thead><tr><th style={th}>ID</th><th style={th}>User</th><th style={th}>Target</th><th style={th}>OS user</th><th style={th}>Src</th><th style={th}>Started</th><th style={th}>Ended</th><th style={th} /></tr></thead>
        <tbody>
          {items.map((s) => (
            <tr key={s.id}>
              <td style={td}><code>{s.id.slice(0, 12)}…</code></td>
              <td style={td}>{s.user}</td>
              <td style={td}>{s.target}</td>
              <td style={td}>{s.os_user}</td>
              <td style={td}>{s.src_ip}</td>
              <td style={td}>{s.started_at}</td>
              <td style={td}>{s.ended_at ?? "running"}</td>
              <td style={td}>
                <button
                  onClick={() => setPlaying(s.id)}
                  aria-label={`watch session ${s.id}`}
                >
                  watch
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

export function AdminLog() {
  const { items, error } = useList<LogEntry>(api.adminLog);
  return (
    <section>
      <h2>Admin log</h2>
      <ErrorLine msg={error} />
      <table style={{ borderCollapse: "collapse" }}>
        <thead><tr><th style={th}>At</th><th style={th}>Actor</th><th style={th}>Via</th><th style={th}>Action</th><th style={th}>Entity</th><th style={th}>Details</th></tr></thead>
        <tbody>
          {items.map((e, i) => (
            <tr key={i}>
              <td style={td}>{e.at}</td>
              <td style={td}>{e.actor}</td>
              <td style={td}>{e.via}</td>
              <td style={td}><code>{e.action}</code></td>
              <td style={td}>{e.entity}</td>
              <td style={td}>{e.details}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
