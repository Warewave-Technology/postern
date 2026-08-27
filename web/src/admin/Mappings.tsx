import { useState } from "react";
import { api, Mapping, Role, UnmappedGroup } from "../api";
import { ErrorLine, td, th, useList } from "./common";

// IdP grubu → postern rolü eşlemesi.
//
// Eşlenmemiş gruplar bölümü bilerek AYNI sayfada: yöneticinin "IdP bana
// ne gönderiyor" sorusuyla "hangisini eşleyeyim" kararı yan yana
// durmalı. Warpgate'te bu bilgi hiçbir yerde olmadığı için insanlar
// claim'lerin geldiğini görüp neden rol oluşmadığını anlayamıyor.
export default function Mappings() {
  const { items, error, refresh, setError } = useList<Mapping>(api.mappings);
  const unmapped = useList<UnmappedGroup>(api.unmappedGroups);
  const roles = useList<Role>(api.roles);

  const [group, setGroup] = useState("");
  const [role, setRole] = useState("");

  const add = (g: string, r: string) =>
    api.addMapping(g, r)
      .then(() => { setGroup(""); refresh(); unmapped.refresh(); })
      .catch((e) => setError(e.message));

  return (
    <section>
      <h2>Group mappings</h2>
      <ErrorLine msg={error} />
      <table style={{ borderCollapse: "collapse" }}>
        <thead>
          <tr><th style={th}>IdP group</th><th style={th}>Role</th><th style={th}>Mapped by</th><th style={th} /></tr>
        </thead>
        <tbody>
          {items.map((m) => (
            <tr key={`${m.group}/${m.role}`}>
              <td style={td}>{m.group}</td>
              <td style={td}>{m.role}</td>
              <td style={td}>{m.created_by}</td>
              <td style={td}>
                <button onClick={() =>
                  api.removeMapping(m.group, m.role)
                    .then(() => refresh())
                    .catch((e) => setError(e.message))}>
                  remove
                </button>
              </td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr><td style={td} colSpan={4}>No mappings — nobody can sign in through the IdP yet.</td></tr>
          )}
        </tbody>
      </table>

      <h3>Add mapping</h3>
      <input placeholder="IdP group" value={group} onChange={(e) => setGroup(e.target.value)} />{" "}
      <select value={role} onChange={(e) => setRole(e.target.value)}>
        <option value="">select role…</option>
        {roles.items.map((r) => <option key={r.name} value={r.name}>{r.name}</option>)}
      </select>{" "}
      <button onClick={() => add(group, role)} disabled={!group || !role}>Map</button>

      <h3 style={{ marginTop: "2rem" }}>Groups seen but not mapped</h3>
      <p style={{ color: "#666", fontSize: "0.9rem" }}>
        These arrived in a login and matched no role. Mapping one grants access
        on the user's next sign-in.
      </p>
      <ErrorLine msg={unmapped.error} />
      {unmapped.items.length === 0 ? (
        <p>Nothing unmapped so far.</p>
      ) : (
        <table style={{ borderCollapse: "collapse" }}>
          <thead>
            <tr><th style={th}>Group</th><th style={th}>Times seen</th><th style={th}>Last seen</th><th style={th} /></tr>
          </thead>
          <tbody>
            {unmapped.items.map((g) => (
              <tr key={g.name}>
                <td style={td}>{g.name}</td>
                <td style={td}>{g.seen_count}</td>
                <td style={td}>{g.last_seen}</td>
                <td style={td}>
                  <button onClick={() => setGroup(g.name)}>use above</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
