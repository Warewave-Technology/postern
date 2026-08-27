import { useState } from "react";
import { api, LDAPTestResult, Setting } from "../api";
import { ErrorLine, td, th, useList } from "./common";

// LDAP alanları. Sıra yapılandırma sırasıyla aynı: önce bağlantı, sonra
// kullanıcı arama, sonra grup okuma.
const FIELDS: { key: string; label: string; hint: string; secret?: boolean }[] = [
  { key: "ldap.url", label: "URL", hint: "ldaps://ldap.example:636 — plain ldap:// only on loopback" },
  { key: "ldap.bind_dn", label: "Bind DN", hint: "postern's own service account, not a user" },
  { key: "ldap.bind_password", label: "Bind password", hint: "stored encrypted, never shown again", secret: true },
  { key: "ldap.user_base", label: "User base", hint: "ou=people,dc=example,dc=com" },
  { key: "ldap.user_filter", label: "User filter", hint: "(uid=%s) — %s is the IdP username" },
  { key: "ldap.group_attribute", label: "Group attribute", hint: "memberOf — leave empty to search groups instead" },
  { key: "ldap.group_base", label: "Group base", hint: "used when group attribute is empty" },
  { key: "ldap.group_filter", label: "Group filter", hint: "(&(objectClass=groupOfNames)(member=%s))" },
  { key: "ldap.group_name_from", label: "Group name from", hint: "cn (default) or dn" },
];

export default function Settings() {
  const { items, error, refresh, setError } = useList<Setting>(api.settings);
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [status, setStatus] = useState("");
  const [testUser, setTestUser] = useState("");
  const [test, setTest] = useState<LDAPTestResult | null>(null);

  const stored = (key: string) => items.find((s) => s.key === key);

  const save = (key: string) =>
    api.setSetting(key, edits[key] ?? "")
      .then((r) => {
        setEdits((e) => ({ ...e, [key]: "" }));
        setStatus(`saved — group source: ${r.source}`);
        refresh();
      })
      .catch((e) => setError(e.message));

  const runTest = () =>
    api.testLDAP(testUser || undefined)
      .then(setTest)
      .catch((e) => setError(e.message));

  return (
    <section>
      <h2>LDAP settings</h2>
      <p style={{ color: "#666", fontSize: "0.9rem" }}>
        Identity always comes from the identity provider. LDAP is only used to
        read group membership — postern never sees a user's password.
      </p>
      <ErrorLine msg={error} />
      {status && <p style={{ color: "green" }}>{status}</p>}

      <table style={{ borderCollapse: "collapse" }}>
        <thead>
          <tr><th style={th}>Setting</th><th style={th}>Stored</th><th style={th}>New value</th><th style={th} /></tr>
        </thead>
        <tbody>
          {FIELDS.map((f) => {
            const cur = stored(f.key);
            return (
              <tr key={f.key}>
                <td style={td}>
                  {f.label}
                  <div style={{ color: "#888", fontSize: "0.75rem" }}>{f.hint}</div>
                </td>
                {/* Sır saklanıyorsa maske görünür: "değer var" ile "değer
                    yok" ayırt edilebilsin diye boş bırakılmıyor. */}
                <td style={td}><code>{cur ? cur.value : "—"}</code></td>
                <td style={td}>
                  <input
                    type={f.secret ? "password" : "text"}
                    size={32}
                    value={edits[f.key] ?? ""}
                    onChange={(e) => setEdits({ ...edits, [f.key]: e.target.value })}
                  />
                </td>
                <td style={td}>
                  <button onClick={() => save(f.key)} disabled={(edits[f.key] ?? "") === ""}>save</button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <h3 style={{ marginTop: "2rem" }}>Test connection</h3>
      <p style={{ color: "#666", fontSize: "0.9rem" }}>
        A wrong base DN or bind password should surface here, not on someone's
        first login.
      </p>
      <input placeholder="username to look up (optional)" size={28}
             value={testUser} onChange={(e) => setTestUser(e.target.value)} />{" "}
      <button onClick={runTest}>Test</button>

      {test && (
        <div style={{ marginTop: "1rem" }}>
          {test.ok ? (
            <p style={{ color: "green" }}>Connection and bind: ok</p>
          ) : (
            <p style={{ color: "crimson" }}>Failed: {test.error}</p>
          )}
          {test.groups && (
            <ul>
              <li>groups: {test.groups.join(", ") || "—"}</li>
              <li>mapped to roles: {test.roles?.join(", ") || "—"}</li>
              <li>unmapped: {test.unmapped?.join(", ") || "—"}</li>
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
