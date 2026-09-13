import { useCallback, useEffect, useState } from "react";
import { Grant, GrantRequest, GrantResult, api, toMessage } from "../api";
import { ActionButton, ErrorLine, Timestamp, useList } from "./common";

/**
 * TemporaryAccess — bir hedefte süreli hesap açmak ve geri almak.
 *
 * ⚠️ FORM NE OLACAĞINI DÜĞMEDEN ÖNCE SÖYLÜYOR. "Grant" tek başına, hedefte
 * root'la bir hesap açılacağını ve süre dolunca hesabın, evinin ve
 * süreçlerinin silineceğini anlatmaz. Operatör tıklamadan önce bunu
 * okumalı; süre bittiğinde makinede olacak şey geri alınamaz.
 *
 * ⚠️ LİSTE KAYDIN KENDİSİ. Sunucu "durum" diye tek bir alan vermiyor;
 * revoked_at, revoke_error, applied_at ve expires_at'tan burada
 * türetiliyor. Geri alması başarısız olan bir hak yeşil değil kırmızı:
 * süresi dolmuş bir root hesabı makinede duruyor demek.
 */

const DURATIONS = [
  ["30m", "30 minutes"],
  ["1h", "1 hour"],
  ["4h", "4 hours"],
  ["8h", "8 hours"],
  ["24h", "24 hours"],
  ["168h", "7 days"],
] as const;

export default function TemporaryAccess({ name }: { name: string }) {
  const users = useList(api.users);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [now, setNow] = useState("");
  const [listError, setListError] = useState("");

  const [username, setUsername] = useState("");
  const [groups, setGroups] = useState("");
  const [duration, setDuration] = useState<string>("4h");
  const [commands, setCommands] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<GrantResult | null>(null);

  const load = useCallback(
    () =>
      api
        .grants(name)
        .then((v) => {
          setGrants(v.grants);
          setNow(v.now);
          setListError("");
        })
        .catch((e: unknown) => setListError(toMessage(e))),
    [name],
  );

  useEffect(() => {
    load();
  }, [load]);

  const request = (): GrantRequest => {
    const g: GrantRequest = {
      username,
      groups: groups
        .split(/[,\s]+/)
        .map((s) => s.trim())
        .filter(Boolean),
      duration,
    };
    const lines = commands
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    if (lines.length > 0) {
      g.sudo = {
        commands: lines.map((l) => {
          const [path, ...args] = l.split(/\s+/);
          return { path, args };
        }),
        acknowledged,
      };
    }
    return g;
  };

  const grant = () => {
    setError("");
    setResult(null);
    return api
      .createGrant(name, request())
      .then((r) => {
        setResult(r);
        setCommands("");
        setAcknowledged(false);
        return load();
      })
      .catch((e: unknown) => {
        setError(toMessage(e));
        // ⚠️ Başarısız hak da listede: yarım kalan hesap kayda girdi ve
        // süpürücü toplayacak. Liste tazelenmezse operatör onu görmez.
        return load();
      });
  };

  const revoke = (id: string) => {
    setError("");
    setResult(null);
    return api
      .revokeGrant(id)
      .then((r) => {
        setResult(r);
        return load();
      })
      .catch((e: unknown) => {
        setError(toMessage(e));
        return load();
      });
  };

  return (
    <div className="card">
      <div className="card-head">
        <h3>Temporary access</h3>
        <p>
          Open an account on this host for one person, for a fixed time. postern
          creates it through its management account, adds it to the groups below
          and to <code>postern-jit</code>, and — when the time is up or you end
          it early — closes their sessions, kills what the account is running,
          and deletes the account, its home and its sudo rule. Both are written
          to the admin log first.
        </p>
      </div>
      <div className="card-body">
        <ErrorLine msg={error} />
        {result && <Outcome r={result} />}

        <div className="field-row">
          <label>
            Person
            <select
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            >
              <option value="">choose…</option>
              {(users.items ?? []).map((u) => (
                <option key={u.name} value={u.name}>
                  {u.name} (account {u.os_user})
                </option>
              ))}
            </select>
          </label>
          <label>
            Groups
            <input
              value={groups}
              onChange={(e) => setGroups(e.target.value)}
              placeholder="dba, docker"
            />
          </label>
          <label>
            For
            <select
              value={duration}
              onChange={(e) => setDuration(e.target.value)}
            >
              {DURATIONS.map(([v, label]) => (
                <option key={v} value={v}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        </div>

        {/*
          Sudo kuralı isteğe bağlı ve satır satır: ilk kelime mutlak yol,
          gerisi sabit argümanlar. Panelde kural düzenleyici yok; sunucu
          kaçış riskini kendisi ölçüp reddediyor ve cümlesi buraya düşüyor.
        */}
        <div className="field-row">
          <label>
            Commands the account may run with sudo (optional, one per line)
            <textarea
              value={commands}
              onChange={(e) => setCommands(e.target.value)}
              rows={3}
              placeholder={
                "/usr/bin/systemctl restart nginx\n/usr/bin/journalctl -u nginx"
              }
            />
          </label>
        </div>
        {commands.trim() !== "" && (
          <label className="check">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
            />
            I have read the escape-risk warning if postern raises one, and
            accept it
          </label>
        )}

        <div className="card-actions">
          <ActionButton
            variant="primary"
            onClick={grant}
            disabled={!username}
            confirm={`Open an account for ${username || "this person"} on ${name} for ${
              DURATIONS.find(([v]) => v === duration)?.[1] ?? duration
            }? postern signs in as its management account to create it, and will delete the account, its home directory and its processes when the time is up.`}
            label={`grant temporary access on ${name}`}
          >
            Grant access
          </ActionButton>
        </div>

        <ErrorLine msg={listError} />
      </div>

      {/* ⚠️ TABLO KARTIN DOĞRUDAN ÇOCUĞU, card-body'nin içinde DEĞİL —
          SecurityKeys'teki ölçümün aynısı: gövdenin dolgusu içinde tablo
          kartı taşırıyor ve son sütun (durum) kesiliyordu (ekrana
          bakılarak görüldü). */}
      <GrantTable grants={grants} now={now} onRevoke={revoke} />
    </div>
  );
}

function Outcome({ r }: { r: GrantResult }) {
  const ok = r.steps.every((s) => s.outcome === "done");
  return (
    <>
      <p className={ok ? "msg msg-ok" : "msg msg-warn"} role="status">
        {r.summary}
        {r.sessions_closed !== undefined && r.sessions_closed > 0 && (
          <> — {r.sessions_closed} open session(s) closed</>
        )}
      </p>
      {r.steps.length > 0 && (
        <details className="run-log" open={!ok}>
          <summary>What ran on the host</summary>
          <ul className="run-list">
            {r.steps.map((s, i) => (
              <li key={i}>
                <code>{s.kind}</code>
                <span className={s.outcome === "done" ? "" : "bad"}>
                  {s.outcome}
                </span>
                <span className="run-reason">{s.error || s.why}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </>
  );
}

/*
 * grantState, kaydın alanlarından tek bir cümle ve bir vurgu sınıfı türetir.
 * Sıra önemli: geri alınmış hak "başarısız" değil; başarısız geri alma
 * "vadesi doldu"dan önce gelir çünkü daha acil.
 */
export function grantState(
  g: Grant,
  now: string,
): { text: string; cls: string } {
  if (g.revoked_at) return { text: "revoked", cls: "" };
  if (g.revoke_error)
    return {
      text: `revocation failing (attempt ${g.revoke_attempts}): ${g.revoke_error}`,
      cls: "bad",
    };
  if (!g.applied_at)
    return { text: "not fully applied — will be cleaned up", cls: "warn" };
  if (now && new Date(g.expires_at).getTime() <= new Date(now).getTime())
    return { text: "expired — being revoked", cls: "warn" };
  return { text: "active", cls: "" };
}

function GrantTable({
  grants,
  now,
  onRevoke,
}: {
  grants: Grant[];
  now: string;
  onRevoke: (id: string) => Promise<unknown>;
}) {
  if (grants.length === 0) {
    return (
      <p className="no-match">
        No temporary access has been granted on this host.
      </p>
    );
  }
  /*
   * ⚠️ BEŞ SÜTUN VE KAYDIRMA SARMALAYICISI — ölçüldü: altı sütunlu tablo
   * masaüstünde bile kartın sütununa (≈660px) sığmıyor ve kart overflow'u
   * gizlediği için durum ile düğme kesiliyordu. Hesap adı kişinin altına
   * indi; geniş içerik kendi kabında kayıyor (.table-wrap), sayfa değil.
   */
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Person</th>
            <th>Groups</th>
            <th>Until</th>
            <th className="state">State</th>
            <th className="actions"></th>
          </tr>
        </thead>
        <tbody>
          {grants.map((g) => {
            const st = grantState(g, now);
            return (
              <tr key={g.id}>
                <td>
                  {g.username}
                  <br />
                  <code className="small">{g.os_user}</code>
                </td>
                <td>{g.groups.length ? g.groups.join(", ") : "—"}</td>
                <td>
                  {g.revoked_at ? (
                    <Timestamp value={g.revoked_at} />
                  ) : (
                    <Timestamp value={g.expires_at} />
                  )}
                </td>
                <td className={"state " + st.cls}>{st.text}</td>
                <td className="actions">
                  {!g.revoked_at && (
                    <ActionButton
                      variant="danger"
                      onClick={() => onRevoke(g.id)}
                      confirm={`End ${g.username}'s access to this host now? Their open sessions are closed and the account ${g.os_user}, its home and its processes are removed.`}
                      label={`revoke ${g.username}'s temporary access`}
                    >
                      Revoke
                    </ActionButton>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
