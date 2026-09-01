import { useCallback, useEffect, useState } from "react";
import { MyKeys as MyKeysData, api, toMessage } from "./api";
import { ActionButton, ErrorLine, OkLine } from "./admin/common";

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
  // TOTP kodu: yerel sırrı olmayan hesapların yeniden doğrulama yolu.
  const [code, setCode] = useState("");
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

  /*
   * ⚠️ SİLME YENİDEN DOĞRULAMA İSTEMİYOR ve bu kasıtlı: erişimi
   * AZALTAN bir işlem. Ele geçirilmiş bir anahtarı kaldırmanın önüne
   * bir sır sormak koymak, tam da acele edilmesi gereken anda
   * yavaşlatırdı. Gerekçenin tamamı handleRemoveMyKey'de.
   */
  const remove = (fingerprint: string) => {
    setError("");
    setOk("");
    return api
      .removeMyKeyByFingerprint(fingerprint)
      .then(() => {
        setOk("key removed");
        return load();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const add = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    setOk("");
    api
      .addMyKey(entry.trim(), reauth, code)
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
  // Hangi kanıt isteniyor: kod mu, sır mı?
  const byCode = Boolean(data.reauth_totp);
  const proof = byCode ? code : reauth;

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
          <ul className="key-list-admin">
            {data.keys.map((k) => (
              <li key={k.fingerprint}>
                <div>
                  <code className="fp">{k.fingerprint}</code>
                  <span className="muted small">
                    {k.comment ? ` ${k.comment} · ` : " "}
                    added {k.added_at.slice(0, 10)}
                  </span>
                </div>
                {/*
                  ⚠️ KENDİ ANAHTARINI KALDIRABİLMEK.

                  Uç ve denetim satırı ilk günden vardı ama panelde
                  çağıran yoktu — üstelik silme ucu anahtarın METNİNİ
                  istiyordu ve liste ucu metni hiç döndürmüyor. Yani
                  anahtarının ele geçtiğini fark eden kullanıcı onu
                  iptal edemiyordu; bu dosyanın kendi gerekçesi ikinci
                  anahtarı "saldırganın kalıcılık kurma hamlesi" diye
                  tanımlarken.

                  Silme yeniden doğrulama İSTEMİYOR ve bu kasıtlı
                  (gerekçe uçta): erişimi AZALTAN bir işlem ve ele
                  geçirilmiş bir anahtarı hızlıca kaldırabilmek gerekiyor.
                */}
                <ActionButton
                  variant="danger"
                  onClick={() => remove(k.fingerprint)}
                  confirm={`Remove this key? If it is your last one you can no longer connect over SSH until an administrator adds one for you.`}
                  label={`remove key ${k.fingerprint}`}
                >
                  Remove
                </ActionButton>
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
          /*
           * ⚠️ ARTIK ÇIKMAZ DEĞİL. Eskiden burada tek yol "yöneticine
           * sor" idi ve dizin kullanan bir kurumda bu, herkes demekti.
           * Kimlik doğrulayıcı bağlamak kullanıcının kendi elinde.
           */
          <p className="msg msg-warn" role="status">
            This account already has a key, and postern has no credential of its
            own to re-check you with. Set up an authenticator above, and you can
            add keys yourself.
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
                {byCode
                  ? "Code from your authenticator"
                  : "Confirm with your sign-in secret"}
                <input
                  type={byCode ? "text" : "password"}
                  inputMode={byCode ? "numeric" : undefined}
                  autoComplete="one-time-code"
                  value={proof}
                  onChange={(e) =>
                    byCode ? setCode(e.target.value) : setReauth(e.target.value)
                  }
                />
                <span className="wfield-hint">
                  You already have a key. Adding another one is how someone with
                  a stolen session would keep access, so postern asks again.
                </span>
              </label>
            )}

            <button
              className="btn btn-primary"
              disabled={busy || !entry.trim() || (needsReauth && !proof)}
            >
              {busy ? "Adding…" : "Add key"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
