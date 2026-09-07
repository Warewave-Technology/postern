import { useCallback, useEffect, useState } from "react";
import { api, PathRule, toMessage } from "../api";
import { ActionButton, ErrorLine } from "./common";

/**
 * PathRules — bir rolün SFTP yol kuralları.
 *
 * ⚠️ NİYE PANELDE OLMASI GEREKİYORDU. Kurallar bugüne kadar yalnızca
 * `postern role path set` ile yazılabiliyordu ve panelin dosya
 * tarayıcısı, kuralı olmayan bir hesapta kendini KAPATIYOR. Yani panel,
 * kullanıcıyı ancak bir kabuğa girip komut çalıştırarak çözebileceği bir
 * duvara götürüyordu. Kuralı doğuran ekranla kuralı yazan ekran aynı
 * yerde olmalı.
 *
 * ⚠️ BOŞ LİSTE "ERİŞİM YOK" DEĞİL. Kuralsız rol kısıtsız; ekran bunu
 * böyle yazıyor. Boş bir tabloyu "hiçbir yere erişemez" diye okumak,
 * yöneticiye koymadığı bir korumayı koymuş gibi gösterirdi — ve bu,
 * yanlış tarafa düşen bir yanılgı.
 */
export default function PathRules({ role }: { role: string }) {
  const [rules, setRules] = useState<PathRule[] | null>(null);
  const [error, setError] = useState("");
  const [prefix, setPrefix] = useState("");
  const [mode, setMode] = useState<"read" | "write" | "deny">("read");

  const load = useCallback(() => {
    api
      .rolePaths(role)
      .then((r) => {
        setRules(r);
        setError("");
      })
      .catch((e: unknown) => setError(toMessage(e)));
  }, [role]);

  useEffect(load, [load]);

  const add = () => {
    const p = prefix.trim();
    if (!p) return;
    api
      .setRolePath(role, {
        prefix: p,
        allow: mode !== "deny",
        can_write: mode === "write",
      })
      .then(() => {
        setPrefix("");
        load();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const remove = (p: string) =>
    api
      .deleteRolePath(role, p)
      .then(load)
      .catch((e: unknown) => setError(toMessage(e)));

  /*
   * ⚠️ SON KURALI SİLMEK KISITI KALDIRIYOR ve onay metni bunu SÖYLÜYOR.
   * "Remove /var/log?" diye sormak, tek kuralı silen yöneticiye
   * daraltma yaptığını düşündürürdü; oysa yaptığı şey rolü kısıtsız
   * bırakmak.
   */
  const removeConfirm = (p: string) =>
    rules?.length === 1
      ? `Remove "${p}"? It is the last rule on "${role}", so the role becomes unrestricted — every path opens for everyone holding it.`
      : `Remove the rule for "${p}" from the role "${role}"?`;

  return (
    <div className="pathrules">
      <ErrorLine msg={error} />

      {rules === null && <p className="muted">Loading…</p>}

      {rules?.length === 0 && (
        <p className="msg msg-warn" role="status">
          No rules — <strong>this role is unrestricted</strong> and reaches
          every path over SFTP. Adding the first rule starts the restriction.
        </p>
      )}

      {rules && rules.length > 0 && (
        <table className="pathrules-list">
          <thead>
            <tr>
              <th>Prefix</th>
              <th>Access</th>
              <th className="sr-only">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.prefix}>
                <td>
                  <code>{r.prefix}</code>
                </td>
                <td>
                  {!r.allow ? (
                    <span className="badge badge-danger">denied</span>
                  ) : r.can_write ? (
                    <span className="badge badge-warn">read-write</span>
                  ) : (
                    <span className="badge badge-ok">read-only</span>
                  )}
                </td>
                <td className="actions">
                  <ActionButton
                    onClick={() => remove(r.prefix)}
                    confirm={removeConfirm(r.prefix)}
                    label={`remove rule ${r.prefix} from role ${role}`}
                  >
                    Remove
                  </ActionButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="field-row">
        <label>
          Prefix
          <input
            value={prefix}
            placeholder="/var/log"
            onChange={(e) => setPrefix(e.target.value)}
          />
        </label>
        <label>
          Access
          <select
            value={mode}
            onChange={(e) => setMode(e.target.value as typeof mode)}
            aria-label={`access for the new rule on role ${role}`}
          >
            <option value="read">Read-only</option>
            <option value="write">Read-write</option>
            <option value="deny">Deny</option>
          </select>
        </label>
        <ActionButton variant="primary" onClick={add} disabled={!prefix.trim()}>
          Add rule
        </ActionButton>
      </div>

      {/*
        ⚠️ ÜÇ SÜRPRİZ BURADA YAZILI, çünkü üçü de kural yazarken fark
        edilmiyor ve sonradan "neden çalışmıyor" diye geliyor. Üçüncüsü —
        kuralsız rolün her şeyi açması — bağımsız bir denetimde eksik
        bulundu: README onu yazıyordu, kuralın YAZILDIĞI ekran yazmıyordu.
      */}
      <p className="pathrules-hint">
        The longest matching prefix wins, so <code>/home/dev/.ssh</code> as a
        deny carves a hole in an allowed <code>/home/dev</code>. Rules from all
        of a user's roles are pooled, and at equal length a deny beats an allow.
        A role with <strong>no rules at all is unrestricted</strong>, and one
        such role among a user's roles switches every rule here off.{" "}
        <strong>Links are resolved by the target, not by postern</strong>: a
        rule constrains the path the client writes, so a link inside an allowed
        directory can still lead somewhere no rule names.
      </p>
    </div>
  );
}
