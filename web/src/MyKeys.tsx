import { useCallback, useEffect, useState } from "react";
import { MyKeys as MyKeysData, api, toMessage } from "./api";
import { ActionButton, ErrorLine } from "./admin/common";
import Modal from "./admin/Modal";
import { toast } from "./toast";

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
/*
 * canAdd, YENİ anahtar eklenebilir mi (auth.public_key_login).
 *
 * ⚠️ LİSTE VE İPTAL BUNA BAĞLI DEĞİL — bilerek. Sunucu yalnızca EKLEMEYİ
 * kapatıyor (mykeys.go); okuma ve silme uçları açık kalıyor. Bileşenin
 * tamamını bu bayrağa bağlamak, ayar kapatıldığında ELİNDE ANAHTAR OLAN
 * kullanıcıyı onları görmekten de iptal etmekten de mahrum bırakıyordu —
 * ve iptal, bu ekrandaki acil olan işlem. Kapalı olan yalnızca form.
 */
export default function MyKeys({ canAdd = true }: { canAdd?: boolean }) {
  const [data, setData] = useState<MyKeysData | null>(null);
  const [entry, setEntry] = useState("");
  const [reauth, setReauth] = useState("");
  // TOTP kodu: yerel sırrı olmayan hesapların yeniden doğrulama yolu.
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  /*
   * ⚠️ EKLEME HATASI AYRI DURUMDA.
   *
   * Tek bir hata durumu paylaşılınca aynı metin İKİ YERDE birden
   * çiziliyordu: kartta ve modalın içinde. Ayrılması yalnızca kozmetik
   * değil — silme hatası kartta, ekleme hatası formun yanında
   * görünmeli, yoksa modal kapandığında silme hatası da onunla
   * kaybolurdu.
   */
  const [addError, setAddError] = useState("");
  const [busy, setBusy] = useState(false);
  /*
   * ⚠️ EKLEME FORMU MODALDA.
   *
   * Kalıcı olarak listenin altında duruyordu ve sayfanın işi
   * "anahtarlarım" listesini göstermek; ekleme yılda birkaç kez
   * yapılan bir eylem. Sürekli açık bir form hem listeyi aşağı
   * itiyor hem "bu kart ne için" sorusunu bulanıklaştırıyordu —
   * yönetim ekranlarındaki formların modala alınma gerekçesinin
   * aynısı (admin/Modal.tsx).
   */
  const [adding, setAdding] = useState(false);

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
    return api
      .removeMyKeyByFingerprint(fingerprint)
      .then(() => {
        toast("Key removed");
        return load();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const add = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setAddError("");
    api
      .addMyKey(entry.trim(), reauth, code)
      .then(() => {
        setEntry("");
        setReauth("");
        setCode("");
        setAdding(false);
        // Modal kapandığı için onay satır içinde kalamaz: kapanan
        // kutuyla birlikte kaybolurdu.
        toast("Key added");
        return load();
      })
      .catch((err: unknown) => setAddError(toMessage(err)))
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

        {data.keys.length === 0 ? (
          <p className="state">No key yet — add one to connect over SSH.</p>
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

        {!canAdd ? (
          /*
           * ⚠️ KAPALI, BOZUK DEĞİL. Form çizilseydi sunucu isteği 409
           * ile reddeder ve kullanıcı özelliği bozuk sanırdı.
           */
          <p className="msg msg-warn" role="status">
            Key-based sign-in is switched off on this bastion, so no new key can
            be added. The keys above still exist and can still be removed.
          </p>
        ) : blocked ? (
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
          <ActionButton
            onClick={() => {
              setAddError("");
              setAdding(true);
            }}
            label="add another SSH key"
          >
            Add key
          </ActionButton>
        )}
      </div>

      {/*
        ⚠️ MODAL YALNIZCA EKLEME MÜMKÜNKEN VAR.
        
        Kapalı bir <dialog> çocuklarını DOM'da tutuyor; koşulsuz
        çizmek, anahtar ekleyemeyecek bir hesapta bile ekleme formunu
        belgede bırakırdı. Gerçek tarayıcıda erişilemez ama var
        olmaması gereken bir şeyin var olmaması daha iyi.
      */}
      {canAdd && !blocked && (
        <Modal
          open={adding}
          title="Add an SSH key"
          description="The public key of a pair you hold. postern never sees the private half."
          onClose={() => setAdding(false)}
        >
          {/*
          ⚠️ HATA MODALIN İÇİNDE. Dışarıda bıraksaydık modal kapanmadan
          görünmez, kapandığında ise sebebi kaybolurdu.
        */}
          <ErrorLine msg={addError} />
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
        </Modal>
      )}
    </div>
  );
}
