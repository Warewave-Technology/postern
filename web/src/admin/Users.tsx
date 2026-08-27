import { useState } from "react";
import { api, User } from "../api";
import { ErrorLine, td, th, useList } from "./common";

export default function Users() {
  const { items, error, refresh, setError } = useList<User>(api.users);
  const [name, setName] = useState("");
  const [osUser, setOsUser] = useState("");
  const [email, setEmail] = useState("");

  const create = () =>
    api.createUser({ name, os_user: osUser, email: email || undefined })
      .then(() => { setName(""); setOsUser(""); setEmail(""); refresh(); })
      .catch((e) => setError(e.message));

  return (
    <section>
      <h2>Users</h2>
      <ErrorLine msg={error} />
      <table style={{ borderCollapse: "collapse" }}>
        <thead><tr><th style={th}>Name</th><th style={th}>OS user</th><th style={th}>Admin</th><th style={th}>Roles</th><th style={th}>Keys</th><th style={th} /></tr></thead>
        <tbody>
          {items.map((u) => (
            <tr key={u.name}>
              <td style={td}>{u.name}</td>
              <td style={td}>{u.os_user}</td>
              {/* Admin sütunu SALT OKUNUR: bayrak yalnızca hosttaki CLI'dan
                  değişir — panel kendine yetki dağıtamaz. */}
              <td style={td}>{u.admin ? "yes" : "—"}</td>
              <td style={td}>{u.roles.join(", ") || "—"}</td>
              <td style={td}>{u.keys}</td>
              <td style={td}>
                <button onClick={() => api.deleteUser(u.name).then(refresh).catch((e) => setError(e.message))}>
                  delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <h3>Add user</h3>
      <input placeholder="name" value={name} onChange={(e) => setName(e.target.value)} />{" "}
      <input placeholder="os user" value={osUser} onChange={(e) => setOsUser(e.target.value)} />{" "}
      <input placeholder="email (optional)" value={email} onChange={(e) => setEmail(e.target.value)} />{" "}
      <button onClick={create} disabled={!name || !osUser}>Create</button>
    </section>
  );
}
