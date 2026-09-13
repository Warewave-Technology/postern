import { useCallback, useEffect, useState } from "react";
import { SecurityKeys as Keys, api, toMessage } from "./api";
import { ActionButton, ErrorLine, Timestamp } from "./admin/common";
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
      <div className="card">
        <div className="card-head">
          <h3>Security keys</h3>
          <p>
            This browser cannot use security keys. Open the panel in a browser
            that supports WebAuthn to register one.
          </p>
        </div>
      </div>
    );
  }

  const list = keys?.credentials ?? [];

  return (
    <div className="card">
      {/*
        ⚠️ KART YAPISI PROJENİN KENDİ DESENİ: card-head başlığı ve
        açıklamayı, card-body içeriği, card-actions düğmeleri taşıyor
        (bkz. MyKeys). İlk yazdığımda bunları kullanmamıştım ve kart
        öbürlerinin yanında yamalı duruyordu — etiket ile düğme aynı
        satıra düşmüştü, çünkü `label` inline-flex.
      */}
      <div className="card-head">
        <h3>Security keys</h3>
        <p>
          A security key signs a challenge that is tied to this site's address,
          so a page pretending to be postern cannot use it. A code can be typed
          into that page and replayed within thirty seconds.
        </p>
      </div>

      {/* ⚠️ TABLO KARTIN DOĞRUDAN ÇOCUĞU. `.card`ın kendi dolgusu yok
          (Audit'teki not); tabloyu `.card-body` içine koyunca iki kat
          dolgu oluşuyor ve son sütundaki düğme kartın kenarına
          taşıyordu — ölçüldü, ekrana bakarak görüldü.
          ⚠️ VE KAYDIRMA SARMALAYICISINDA: 390px'te dört sütun karta
          sığmıyor ve sarmalayıcı yokken SAYFANIN KENDİSİ yatay
          kayıyordu (ölçüldü, 708px'e kadar). */}
      {list.length === 0 ? (
        <div className="card-body">
          <ErrorLine msg={error} />
          <p className="state">No security key is registered on this account.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
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
                  {/* Timestamp, toLocaleDateString() DEĞİL: panelin geri
                      kalanı "13 Sep 12:12:00" yazıyor; burası "9/13/2026"
                      diyordu. Tam değer title'da duruyor. */}
                  <td>
                    <Timestamp value={k.created_at} />
                  </td>
                  <td>
                    {/* ⚠️ "Hiç kullanılmadı" ile bir tarih AYRI: kaybolan
                        anahtarı silecek kişi tam olarak buna bakıyor. */}
                    {k.last_used_at ? <Timestamp value={k.last_used_at} /> : "never"}
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
        </div>
      )}

      <div className="card-body">
        {list.length > 0 && <ErrorLine msg={error} />}

        <div className="field-row">
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
        </div>

        {list.length > 0 && (
          /* ⚠️ msg-warn, PROJENİN uyarı sınıfı. İlk yazdığımda site
             belgelerindeki `.stop` sınıfını kullanmıştım ve o sınıf
             panel CSS'inde HİÇ YOK: blok stilsiz çiziliyordu. */
          <p className="msg msg-warn" role="status">
            {/* ⚠️ ÖZET CÜMLE KALIN VE ÖNDE. Kullanıcı kartın tamamını
                okumuyor; "kodlar hâlâ kabul ediliyor" bilgisi bir
                paragrafın içinde kaybolursa, kazanılmamış bir güven
                duygusu bırakır. */}
            <b>{keys?.only ? "Codes are off." : "Codes are still accepted."}</b>{" "}
            {keys?.only
              ? "This account signs in with a security key only. If you lose every key you have registered, an administrator has to reset this — there are no recovery codes."
              : "Your authenticator code still works, so this account is as phishable as that code: an attacker who copies your password can ask for the code and never touch the key."}
          </p>
        )}

        {list.length > 0 && (
          <div className="card-actions">
            <ActionButton
              onClick={() => setOnly(!keys?.only)}
              label={keys?.only ? "accept codes again" : "stop accepting codes"}
            >
              {keys?.only ? "Accept codes again" : "Stop accepting codes"}
            </ActionButton>
          </div>
        )}
      </div>
    </div>
  );
}
