import { useCallback, useEffect, useState } from "react";
import { SecurityKeys as Keys, api, toMessage } from "./api";
import { ActionButton, ErrorLine } from "./admin/common";
import { attestationToJSON, supported, toCreationOptions } from "./webauthn";
import { toast } from "./toast";

/*
 * SecurityKeys — kimlik avına dayanıklı ikinci faktör.
 *
 * NEDEN VAR: panel postern'in kontrol düzlemi ve tek ikinci faktörü
 * TOTP'ydi. Kod, sahte bir sayfaya yazılıp otuz saniye içinde gerçek
 * sunucuya aktarılabiliyor; kullanıcı tarafında bunu fark ettirecek
 * hiçbir şey yok. Güvenlik anahtarının imzası KAYNAĞA bağlı olduğu için
 * aktarılamıyor.
 *
 * ⚠️ SSH TARAFI BUNU ZATEN DESTEKLİYOR (sshalg: sk-ssh-ed25519,
 * sk-ecdsa-sha2-nistp256). Eksik olan yalnızca paneldi — yani bu kart
 * yeni bir güvence eklemiyor, panelin SSH'ın zaten olduğu yere
 * gelmesini sağlıyor.
 */
export default function SecurityKeys() {
  const [keys, setKeys] = useState<Keys | null>(null);
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api
      .webauthnList()
      .then(setKeys)
      .catch((e: unknown) => setError(toMessage(e)));
  }, []);

  useEffect(load, [load]);

  const register = () => {
    setBusy(true);
    setError("");
    api
      .webauthnBegin()
      .then((options) =>
        navigator.credentials.create({
          publicKey: toCreationOptions(options),
        }),
      )
      .then((c) => {
        if (!c) throw new Error("no credential");
        return api.webauthnFinish(name, attestationToJSON(c as PublicKeyCredential));
      })
      .then((added) => {
        toast(`${added.name} registered`);
        setName("");
        load();
      })
      .catch((e: unknown) => {
        /*
         * ⚠️ İPTAL BİR ARIZA DEĞİL. Kullanıcı anahtarı takmaktan
         * vazgeçtiğinde tarayıcı bir hata fırlatıyor; onu kırmızı bir
         * satır olarak çizmek, kendi kararını bir arıza sanmasına yol
         * açardı.
         */
        const msg = toMessage(e);
        if (/not allowed|abort|cancel/i.test(msg)) {
          setError("");
          return;
        }
        setError(msg);
      })
      .finally(() => setBusy(false));
  };

  const remove = (id: string, label: string) => {
    api
      .webauthnRemove(id)
      .then(() => {
        toast(`${label} removed`);
        load();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const setOnly = (only: boolean) => {
    api
      .webauthnOnly(only)
      .then(() => {
        load();
        toast(
          only
            ? "codes are no longer accepted on this account"
            : "codes are accepted again",
        );
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  if (!supported()) {
    return (
      <section className="card">
        <h2>Security keys</h2>
        <p className="muted">
          This browser cannot use security keys. Open the panel in a browser
          that supports WebAuthn to register one.
        </p>
      </section>
    );
  }

  const list = keys?.credentials ?? [];

  return (
    <section className="card">
      <h2>Security keys</h2>
      <ErrorLine msg={error} />

      <p className="muted">
        A security key signs a challenge that is tied to this site's address,
        so a page pretending to be postern cannot use it. A code can be typed
        into that page and replayed within thirty seconds.
      </p>

      {list.length === 0 ? (
        <p className="muted">No security key is registered on this account.</p>
      ) : (
        <table className="tight">
          <thead>
            <tr>
              <th>Name</th>
              <th>Added</th>
              <th>Last used</th>
              <th className="actions">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {list.map((k) => (
              <tr key={k.id}>
                <td>{k.name}</td>
                <td>{new Date(k.created_at).toLocaleDateString()}</td>
                <td>
                  {/* ⚠️ "Hiç kullanılmadı" ile "bugün kullanıldı" AYRI:
                      kaybolan anahtarı silecek kişi buna bakıyor. */}
                  {k.last_used_at
                    ? new Date(k.last_used_at).toLocaleDateString()
                    : "never"}
                </td>
                <td className="actions">
                  <ActionButton
                    onClick={() => remove(k.id, k.name)}
                    label={`remove ${k.name}`}
                  >
                    Remove
                  </ActionButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <label>
        Name this key
        <input
          value={name}
          placeholder="work laptop"
          onChange={(e) => setName(e.target.value)}
        />
      </label>
      <ActionButton onClick={register} label="register a security key">
        {busy ? "Waiting for the key…" : "Register a security key"}
      </ActionButton>

      {list.length > 0 && (
        <div className="stop">
          {/*
            ⚠️ BU KUTU BİR UYARI, BİR AYAR DEĞİL — VE SÖYLEDİĞİ ŞEY
            ÖLÇÜLEBİLİR: kod açıkken hesabın kimlik avına dayanıklılığı
            KODUNKİ kadar, çünkü saldırgan anahtarı hiç sormadan kodu
            ister. Bunu yazmadan bir anahtar kaydettirmek, kullanıcıya
            kazanmadığı bir güvence satmak olurdu.
          */}
          <b>{keys?.only ? "Codes are off" : "Codes are still accepted"}</b>
          <p>
            {keys?.only
              ? "This account signs in with a security key only. If you lose every key you have registered, an administrator has to reset this — there are no recovery codes."
              : "While your authenticator code still works, this account is as phishable as that code: an attacker who copies your password can ask for the code and never touch the key."}
          </p>
          <ActionButton
            onClick={() => setOnly(!keys?.only)}
            label={keys?.only ? "accept codes again" : "stop accepting codes"}
          >
            {keys?.only ? "Accept codes again" : "Stop accepting codes"}
          </ActionButton>
        </div>
      )}
    </section>
  );
}
