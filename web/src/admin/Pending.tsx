import { useEffect, useState } from "react";
import { PendingUser, api, toMessage } from "../api";
import { ActionButton, ErrorLine, OkLine } from "./common";

/**
 * Onay kuyruğu.
 *
 * ⚠️ EKRANIN SÖYLEMEK ZORUNDA OLDUĞU ÜÇ ŞEY:
 *
 *   1. Listedeki ad, e-posta ve gruplar KAYNAĞIN o anki sözü — karar
 *      onlara değil, değişmez kimliğe bağlanıyor. Ad değişince satır
 *      değişmiyor.
 *   2. Onay ROL VERMİYOR: roller kişinin bir sonraki girişinde canlı
 *      kaynaktan çözülüyor. "Onayladım ama hiçbir yere giremiyor"
 *      şaşkınlığı buradan doğar.
 *   3. Red YAPIŞKAN: kişi yeniden başvuramaz, adını değiştirse bile.
 *      Geri almanın yolu var ve görünür olmalı.
 */
export default function Pending() {
  const [rows, setRows] = useState<PendingUser[] | null>(null);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");
  const [reasons, setReasons] = useState<Record<string, string>>({});

  const load = () =>
    api
      .pending()
      .then(setRows)
      .catch((e: unknown) => setError(toMessage(e)));

  useEffect(() => {
    void load();
    // yalnızca ilk çizimde
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const run = (p: Promise<unknown>, msg: string) => {
    setError("");
    setDone("");
    return p
      .then(() => {
        setDone(msg);
        return load();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const waiting = (rows ?? []).filter((r) => r.state === "waiting");
  const decided = (rows ?? []).filter((r) => r.state !== "waiting");

  const card = (p: PendingUser) => (
    <div className="card" key={p.id}>
      <div className="card-body">
        <dl className="kv">
          <dt>name in the source</dt>
          <dd>
            {p.username}{" "}
            <span className="badge">
              {p.source === "dir" ? "directory" : "identity provider"}
            </span>
          </dd>
          {p.email !== "" && (
            <>
              <dt>email</dt>
              <dd>{p.email}</dd>
            </>
          )}
          <dt>groups seen</dt>
          <dd>
            {p.seen_groups.length ? (
              <code>{p.seen_groups.join(", ")}</code>
            ) : (
              <span className="muted">none</span>
            )}
          </dd>
          {/*
            ⚠️ Kimlik gösteriliyor çünkü karar ONUN üzerine veriliyor.
            Operatör "bu gerçekten o kişi mi" sorusunu ancak kaynakta
            aynı değeri görerek cevaplayabilir.
          */}
          <dt>identity</dt>
          <dd>
            <code>{p.subject}</code>
          </dd>
          <dt>first seen</dt>
          <dd>{new Date(p.first_seen).toLocaleString()}</dd>
          <dt>last tried</dt>
          <dd>{new Date(p.last_seen).toLocaleString()}</dd>
          {p.state === "rejected" && (
            <>
              <dt>declined</dt>
              <dd>
                {p.reason} — {p.decided_by}
              </dd>
            </>
          )}
        </dl>

        {p.state === "waiting" ? (
          <>
            <div className="wizard-nav">
              <ActionButton
                variant="primary"
                label={`approve ${p.username}`}
                confirm={
                  `Create an account for ${p.username}?\n\n` +
                  `They get no roles from this: roles are read from the source ` +
                  `at their next sign-in.`
                }
                onClick={() =>
                  run(
                    api.approvePending(p.id),
                    `account created for ${p.username}`,
                  )
                }
              >
                Approve
              </ActionButton>
              <span className="spacer" />
              <ActionButton
                variant="danger"
                label={`decline ${p.username}`}
                disabled={!(reasons[p.id] ?? "").trim()}
                onClick={() =>
                  run(
                    api.rejectPending(p.id, reasons[p.id] ?? ""),
                    `declined ${p.username}`,
                  )
                }
              >
                Decline
              </ActionButton>
            </div>
            <div className="wfield">
              <label className="wfield-label" htmlFor={`why-${p.id}`}>
                Reason for declining
              </label>
              <input
                id={`why-${p.id}`}
                value={reasons[p.id] ?? ""}
                onChange={(e) =>
                  setReasons({ ...reasons, [p.id]: e.target.value })
                }
              />
              {/* Gerekçe zorunlu ve sebebi burada yazıyor. */}
              <p className="wfield-hint">
                Required. Whoever sees this identity apply again is probably not
                you, and a decision with no reason is one they cannot act on.
              </p>
            </div>
          </>
        ) : (
          <div className="wizard-nav">
            <span className="note">
              This identity cannot apply again — not even under a different name
              in the source, because the decision is recorded against the
              identity rather than the name.
            </span>
            <span className="spacer" />
            <ActionButton
              label={`let ${p.username} apply again`}
              confirm={`Forget the decision about ${p.username}? They will be able to apply again.`}
              onClick={() =>
                run(api.forgetPending(p.id), `${p.username} may apply again`)
              }
            >
              Let them apply again
            </ActionButton>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>
            Pending{" "}
            {waiting.length > 0 && (
              <span className="badge badge-ok">{waiting.length}</span>
            )}
          </h2>
          <p className="page-sub">
            People the source authenticated who have no account here yet. They
            were told their account is waiting. Approving creates the account
            and binds it to their identity — <b>it grants no roles</b>; those
            are read from the source when they next sign in.
          </p>
        </div>
      </div>

      <ErrorLine msg={error} />
      <OkLine msg={done} />

      {rows === null ? (
        <p className="muted">loading…</p>
      ) : rows.length === 0 ? (
        <p className="note">
          Nobody is waiting. People land here only while accounts do not open on
          their own — see <b>Sign-in</b> for that switch.
        </p>
      ) : (
        <>
          {waiting.map(card)}
          {decided.length > 0 && (
            <>
              <h3>Declined</h3>
              {decided.map(card)}
            </>
          )}
        </>
      )}
    </section>
  );
}
