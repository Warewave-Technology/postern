import { useState } from "react";
import { api, Role } from "../api";
import { ErrorLine, td, th, useList } from "./common";

export default function Roles() {
  const { items, error, refresh, setError } = useList<Role>(api.roles);
  const [name, setName] = useState("");

  return (
    <section>
      <h2>Roles</h2>
      <ErrorLine msg={error} />
      <table style={{ borderCollapse: "collapse" }}>
        <thead><tr><th style={th}>Name</th><th style={th}>Targets</th><th style={th} /></tr></thead>
        <tbody>
          {items.map((r) => (
            <tr key={r.name}>
              <td style={td}>{r.name}</td>
              <td style={td}>{r.targets.join(", ") || "—"}</td>
              <td style={td}>
                <button onClick={() => api.deleteRole(r.name).then(refresh).catch((e) => setError(e.message))}>
                  delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <h3>Add role</h3>
      <input placeholder="name" value={name} onChange={(e) => setName(e.target.value)} />{" "}
      <button
        onClick={() => api.createRole({ name }).then(() => { setName(""); refresh(); }).catch((e) => setError(e.message))}
        disabled={!name}
      >
        Create
      </button>
    </section>
  );
}
