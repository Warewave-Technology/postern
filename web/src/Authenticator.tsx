import { useCallback, useEffect, useState } from "react";
import { api, TOTPStatus, toMessage } from "./api";
import QRCode from "./QRCode";
import { ActionButton, ErrorLine } from "./admin/common";
import Modal from "./admin/Modal";
import { toast } from "./toast";

/*
 * Authenticator — kullanıcının kendi ikinci faktörü.
 *
 * NEDEN VAR: ikinci bir SSH anahtarı eklemek yeniden doğrulama istiyor
 * (MyKeys'teki gerekçe). Ama postern yalnızca YEREL parolayı
 * doğrulayabildiği için, dizinden ya da kimlik sağlayıcıdan gelen
 * hesaplara verilen cevap "yöneticine sor" idi — yani dizin kullanan
 * kurumlarda, yani asıl hedef kurulumda, kimse kendi anahtarını
 * yönetemiyordu. Bu ekran o çıkmazı kaldırıyor.
 */

// group, sırrı elle yazılabilir hâle getirir: 32 karakterlik kesintisiz
// bir dizgiyi telefona doğru geçirmek gözle mümkün değil.
function group(secret: string): string {
  return (secret.match(/.{1,4}/g) ?? []).join(" ");
}

export default function Authenticator() {
  const [status, setStatus] = useState<TOTPStatus | null>(null);
  const [secret, setSecret] = useState<{
    secret: string;
    uri: string;
    qr: string[];
  } | null>(null);
  const [reauth, setReauth] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [removing, setRemoving] = useState(false);
  /*
   * ⚠️ KURULUM MODALDA.
   *
   * QR, kurulum anahtarı ve kod alanı karta gömülüyken kart üç katına
   * çıkıyor ve "ikinci faktörüm var mı" sorusunun cevabı o yığının
   * altında kayboluyordu. Kurulum bir kez yapılan bir eylem; kalıcı
   * ekranda durmasının gerekçesi yok (admin/Modal.tsx).
   */
  const [setting, setSetting] = useState(false);

  const load = useCallback(
    () =>
      api
        .totpStatus()
        .then(setStatus)
        .catch((e: unknown) => setError(toMessage(e))),
    [],
  );

  useEffect(() => {
    void load();
  }, [load]);

  if (!status) return null;

  const run = (p: Promise<unknown>, done: string) => {
    setBusy(true);
    setError("");
    return p
      .then(() => {
        // Modal kapanıyor: onay satır içinde kalamaz, kutuyla
        // birlikte kaybolurdu.
        toast(done);
        setCode("");
        setReauth("");
        return load();
      })
      .catch((e: unknown) => setError(toMessage(e)))
      .finally(() => setBusy(false));
  };

  const begin = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    api
      .totpBegin(reauth)
      .then((s) => {
        setSecret(s);
        setReauth("");
        return load();
      })
      .catch((e: unknown) => setError(toMessage(e)))
      .finally(() => setBusy(false));
  };

  return (
    <div className="card mykeys">
      <div className="card-head">
        <h3>Authenticator</h3>
        <p>
          A one-time code app, so that you can add a further SSH key without
          asking an administrator.
        </p>
      </div>

      <div className="card-body">
        {/*
          ⚠️ KART YALNIZCA DURUMU VE İKİ DÜĞMEYİ TAŞIYOR.
          
          Kurulum akışı (QR, kurulum anahtarı, kod) ve kapatma formu
          buradaydı ve kartı üç katına çıkarıyordu — "ikinci faktörüm
          var mı" sorusunun cevabı o yığının altında kayboluyordu.
          İkisi de ara sıra yapılan eylemler, modalın işi tam olarak bu.
        */}
        <ErrorLine msg={error} />

        {status.enrolled ? (
          <>
            {/*
              ⚠️ "NE ZAMANDAN BERİ" DE YAZIYOR.

              Kullanıcı için asıl soru "bu benim bağladığım cihaz mı" —
              ve o soruya yalnızca son kullanım değil, BAĞLANMA tarihi
              cevap veriyor. Beklemediği bir tarih gören kişi,
              faktörünü kapatıp yenisini bağlar.
            */}
            <p className="state">
              Active
              {status.confirmed_at
                ? ` since ${new Date(status.confirmed_at).toLocaleDateString()}`
                : ""}
              {status.last_used_at
                ? ` — last used ${new Date(status.last_used_at).toLocaleString()}`
                : " — not used yet"}
              .
            </p>
            <ActionButton
              variant="danger"
              onClick={() => {
                setError("");
                setCode("");
                setRemoving(true);
              }}
              label="turn off the authenticator on this account"
            >
              Turn off
            </ActionButton>
          </>
        ) : !status.can_begin ? (
          /*
           * ⚠️ TAZE GİRİŞ İSTENİYOR ve sebebi yazıyor. Sebebi
           * söylemeyen bir ret, kullanıcıya "bozuk" gibi görünür ve
           * yöneticiye gider — bu ekranın kaldırmak için var olduğu
           * şeyin ta kendisi.
           */
          <p className="msg msg-warn" role="status">
            {status.needs_fresh_login
              ? "Sign in again and come back: linking an authenticator needs a recent sign-in, so that a stolen session cannot add one."
              : "This account cannot enrol an authenticator right now."}
          </p>
        ) : (
          <>
            <p className="state">
              {status.pending
                ? "An enrolment was started but never finished. Starting again replaces it."
                : "Not set up yet."}
            </p>
            <ActionButton
              onClick={() => {
                setError("");
                setReauth("");
                setCode("");
                setSecret(null);
                setSetting(true);
              }}
              label="set up an authenticator app"
            >
              Set up
            </ActionButton>
          </>
        )}
      </div>

      {/* Kurulum: önce kanıt, sonra QR ve kod — tek modalın iki adımı. */}
      {!status.enrolled && status.can_begin && (
        <Modal
          open={setting}
          title="Set up an authenticator"
          description="A one-time code app, so that you can add a further SSH key without asking an administrator."
          onClose={() => {
            setSetting(false);
            setSecret(null);
          }}
        >
          <ErrorLine msg={error} />

          {!secret ? (
            <form className="key-form" onSubmit={begin}>
              {!status.needs_fresh_login && (
                <label>
                  Confirm with your sign-in secret
                  <input
                    type="password"
                    autoComplete="current-password"
                    value={reauth}
                    onChange={(e) => setReauth(e.target.value)}
                  />
                </label>
              )}
              <button
                className="btn btn-primary"
                disabled={busy || (!status.needs_fresh_login && !reauth)}
              >
                {busy ? "Starting…" : "Continue"}
              </button>
            </form>
          ) : (
            <form
              className="key-form"
              onSubmit={(e) => {
                e.preventDefault();
                void run(
                  api.totpConfirm(code),
                  "Authenticator is now active.",
                ).then(() => {
                  setSecret(null);
                  setSetting(false);
                });
              }}
            >
              <p className="state">
                Scan this with your authenticator app, then enter the code it
                shows.
              </p>
              {/*
                ⚠️ QR VE ELLE GİRİŞ BİRLİKTE DURUYOR.

                QR normal yol. Ama elle giriş kaldırılamaz: kamerası
                olmayan bir masaüstünden kurulum yapan ya da kodu başka
                bir cihaza geçiren kullanıcı, tek yol QR olsaydı burada
                kalırdı.
              */}
              {secret.qr.length > 0 && (
                <div className="qr-wrap">
                  <QRCode
                    rows={secret.qr}
                    label="Enrolment QR code — scan it with your authenticator app"
                  />
                </div>
              )}
              <label>
                Setup key
                <code className="totp-secret">{group(secret.secret)}</code>
                <span className="wfield-hint">
                  Can't scan? Type this into your app instead, or open{" "}
                  <a href={secret.uri}>the enrolment link</a> on the phone
                  itself. It is shown once.
                </span>
              </label>
              <label>
                Code from the app
                <input
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
              </label>
              <button className="btn btn-primary" disabled={busy || !code}>
                {busy ? "Checking…" : "Activate"}
              </button>
            </form>
          )}
        </Modal>
      )}

      {/* Kapatma: kod istiyor (gerekçe aşağıda). */}
      {status.enrolled && (
        <Modal
          open={removing}
          title="Turn off the authenticator"
          onClose={() => {
            setRemoving(false);
            setCode("");
          }}
        >
          <ErrorLine msg={error} />
          <form
            className="key-form"
            onSubmit={(e) => {
              e.preventDefault();
              void run(api.totpDisable(code), "Authenticator turned off.").then(
                () => setRemoving(false),
              );
            }}
          >
            <label>
              Current code
              <input
                inputMode="numeric"
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
              {/*
                ⚠️ Kapatmak da kod istiyor. İstemeseydi, oturumu çalan
                biri faktörü kapatıp yerine kendininkini bağlardı — yani
                faktör, onu atlatmak isteyen için engel olmaktan çıkardı.
              */}
              <span className="wfield-hint">
                Turning it off needs a code, so that someone who took over your
                session cannot simply remove it.
              </span>
            </label>
            <button className="btn btn-danger" disabled={busy || !code}>
              {busy ? "Turning off…" : "Confirm"}
            </button>
          </form>
        </Modal>
      )}
    </div>
  );
}
