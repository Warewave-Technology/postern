import { useState } from "react";
import { PasswordPolicy, api, toMessage } from "./api";

/**
 * Zorunlu parola değişikliği.
 *
 * ⚠️ BU EKRAN GÖRÜNÜRKEN OTURUM KISITLI: sunucu yalnızca /api/me ve bu
 * ekranın çağırdığı uca izin veriyor (weblogin.go'daki
 * changePasswordAllowed). Yani buradaki "başka bir yere gidemezsin"
 * hissi ekranın kibarlığı değil, uçlardaki gerçeğin yansıması.
 *
 * ⚠️ KURAL SUNUCUDAN GELİYOR, BURADA YAZILI DEĞİL. Politikayı ekrana
 * kopyalamak bir güvenlik kontrolünün ikinci kopyası olurdu ve iki
 * kopyadan biri er ya da geç geride kalır — kullanıcı "12 karakter"
 * yazan bir ekrana bakarken sunucu 16 isterdi.
 */
export default function ChangePassword({
  name,
  policy,
  onDone,
}: {
  name: string;
  policy?: PasswordPolicy;
  onDone: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const min = policy?.min_length ?? 12;
  const tooShort = next.length > 0 && next.length < min;
  const mismatch = again.length > 0 && next !== again;
  const ready = current !== "" && next !== "" && next === again && !tooShort;

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!ready || busy) return;
    setError("");
    setBusy(true);
    api
      .changePassword(current, next)
      .then(onDone)
      .catch((err: unknown) => setError(toMessage(err)))
      .finally(() => setBusy(false));
  };

  return (
    <div className="setup-gate">
      <form className="card change-password" onSubmit={submit}>
        <h2>Set your password</h2>
        <p className="page-sub">
          The value you signed in with was created by an administrator, so
          somebody else has seen it. Choose one only you know — the panel opens
          once you do.
        </p>

        {error && <p className="msg err">{error}</p>}

        <label>
          Current sign-in value
          <input
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            autoFocus
          />
        </label>

        <label>
          New password
          <input
            type="password"
            autoComplete="new-password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
          />
        </label>

        <label>
          New password again
          <input
            type="password"
            autoComplete="new-password"
            value={again}
            onChange={(e) => setAgain(e.target.value)}
          />
        </label>

        {tooShort && <p className="msg warn">At least {min} characters.</p>}
        {mismatch && <p className="msg warn">The two do not match.</p>}

        <ul className="policy-list">
          <li>At least {min} characters</li>
          <li>Not one of the most commonly chosen passwords</li>
          <li>Must not contain “{name}”</li>
          <li>Not a run of neighbouring keys (qwerty…, abcdef…, 123456…)</li>
        </ul>

        <button className="primary" disabled={!ready || busy}>
          {busy ? "Setting…" : "Set password and continue"}
        </button>

        <p className="page-sub">
          Signing out will not skip this — the panel stays closed until the
          password is changed.
        </p>
      </form>
    </div>
  );
}
