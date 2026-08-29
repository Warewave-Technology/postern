import { useCallback, useEffect, useState } from "react";
import { MyKeys as MyKeysData, api, toMessage } from "./api";
import { ErrorLine, OkLine } from "./admin/common";

/*
 * MyKeys — kullanıcının kendi SSH anahtarları.
 *
 * NEDEN BURADA: SSH'a anahtarla giriliyor, ama anahtar ekleyen tek uç
 * yöneticideydi. Dizini olan bir kurumda bu, her kullanıcı için
 * yöneticinin tek tek anahtar girmesi demekti — dizinden kaçınmak için
 * kurulan sistemin geri getirdiği elle iş.
 *
 * ⚠️ İLK ANAHTAR SERBEST, SONRAKİLER YENİDEN DOĞRULAMA İSTER. Anahtarı
 * olmayan kullanıcı zaten SSH'a giremiyor; ilk anahtar normal akış.
 * Anahtarı OLAN bir hesaba ikinci anahtar eklemek ise oturumu ele
 * geçiren birinin kalıcılık kurma hamlesi — parola değişse bile yaşayan
 * bir giriş bırakır.
 */
export default function MyKeys() {
  const [data, setData] = useState<MyKeysData | null>(null);
  const [entry, setEntry] = useState("");
  const [reauth, setReauth] = useState("");
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(
    () =>
      api
        .myKeys()
        .then(setData)
        .catch((e: unknown) => setError(toMessage(e))),
    [],
  );
  useEffect(() => {
    load();
  }, [load]);

  const add = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    setOk("");
    api
      .addMyKey(entry.trim(), reauth)
      .then(() => {
        setEntry("");
        setReauth("");
        setOk("key added");
        return load();
      })
      .catch((err: unknown) => setError(toMessage(err)))
      .finally(() => setBusy(false));
  };

  if (!data) return null;

  const needsReauth = data.reauth_required;
  const blocked = needsReauth && !data.reauth_possible;

  return (
    <div className="card mykeys">
      <div className="card-head">
        <h3>Your SSH keys</h3>
        <p>
          These are the keys that let you open a session through this bastion.
          What they can reach is decided by your roles, not by the key.
        </p>
      </div>

      <div className="card-body">
        <ErrorLine msg={error} />
        <OkLine msg={ok} />

        {data.keys.length === 0 ? (
          <p className="state">
            No key yet — add one below to connect over SSH.
          </p>
        ) : (
          <ul className="key-list">
            {data.keys.map((k) => (
              <li key={k.fingerprint}>
                <code>{k.fingerprint}</code>
                {k.comment && <span className="muted"> {k.comment}</span>}
                <span className="muted">
                  {" "}
                  · added {k.added_at.slice(0, 10)}
                </span>
              </li>
            ))}
          </ul>
        )}

        {blocked ? (
          /*
           * Uydurma bir onay yerine dürüst bir yol. Bu hesabın kimliği
           * başka bir yerden geliyor ve postern'in yeniden
           * doğrulayabileceği bir sırrı yok — boş yere sır sormak,
           * kullanıcıyı asla geçemeyeceği bir kutuya bakmaya zorlardı.
           */
          <p className="msg msg-warn" role="status">
            This account already has a key, and postern has no credential of its
            own to re-check you with. Ask an administrator to add another one.
          </p>
        ) : (
          <form className="key-form" onSubmit={add}>
            <label>
              Public key
              <textarea
                rows={3}
                value={entry}
                placeholder="ssh-ed25519 AAAA… you@laptop"
                onChange={(e) => setEntry(e.target.value)}
              />
            </label>

            {needsReauth && (
              <label>
                Confirm with your sign-in secret
                <input
                  type="password"
                  autoComplete="one-time-code"
                  value={reauth}
                  onChange={(e) => setReauth(e.target.value)}
                />
                <span className="wfield-hint">
                  You already have a key. Adding another one is how someone with
                  a stolen session would keep access, so postern asks again.
                </span>
              </label>
            )}

            <button
              className="btn btn-primary"
              disabled={busy || !entry.trim() || (needsReauth && !reauth)}
            >
              {busy ? "Adding…" : "Add key"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
