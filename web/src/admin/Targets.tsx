import { useState } from "react";
import { api, Target } from "../api";
import { ErrorLine, td, th, useList } from "./common";

export default function Targets() {
  const { items, error, refresh, setError } = useList<Target>(api.targets);
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("22");
  const [hostKey, setHostKey] = useState("");

  const create = () =>
    api.createTarget({ name, host, port: Number(port), host_key: hostKey })
      .then(() => { setName(""); setHost(""); setPort("22"); setHostKey(""); refresh(); })
      .catch((e) => setError(e.message));

  return (
    <section>
      <h2>Targets</h2>
      <ErrorLine msg={error} />
      <table style={{ borderCollapse: "collapse" }}>
        <thead><tr><th style={th}>Name</th><th style={th}>Host</th><th style={th}>Port</th><th style={th}>Host key</th><th style={th} /></tr></thead>
        <tbody>
          {items.map((t) => (
            <tr key={t.name}>
              <td style={td}>{t.name}</td>
              <td style={td}>{t.host}</td>
              <td style={td}>{t.port}</td>
              <td style={td}><code>{t.fingerprint}</code></td>
              <td style={td}>
                <button onClick={() => api.deleteTarget(t.name).then(refresh).catch((e) => setError(e.message))}>
                  delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <h3>Register target</h3>
      <input placeholder="name" value={name} onChange={(e) => setName(e.target.value)} />{" "}
      <input placeholder="host" value={host} onChange={(e) => setHost(e.target.value)} />{" "}
      <input placeholder="port" size={4} value={port} onChange={(e) => setPort(e.target.value)} />
      <br />
      <textarea
        placeholder="host public key (ssh-ed25519 AAAA... — ssh-keyscan çıktısı)"
        rows={2} cols={70} value={hostKey} onChange={(e) => setHostKey(e.target.value)}
      />
      <br />
      <button onClick={create} disabled={!name || !host || !hostKey}>Register</button>
    </section>
  );
}
