import { useState } from "react";
import { ManageCheck, api, toMessage } from "../api";
import { ActionButton, ErrorLine, Timestamp } from "./common";

/**
 * ManageAccess — postern bu hedefi kendi yönetim hesabıyla açabiliyor mu.
 *
 * ⚠️ KART, KONTROLÜN NE YAPTIĞINI DÜĞMEDEN ÖNCE SÖYLÜYOR. Düğme hedefte
 * parolasız root tutan bir hesaba giriş yapıyor; "Check" kelimesi tek
 * başına bunu anlatmaz. Kontrol hiçbir şey değiştirmiyor ve bu da
 * yazılı, çünkü operatörün tıklamadan önce soracağı soru tam olarak bu.
 *
 * ⚠️ SONUÇ SAYFADA KALMIYOR, SAKLANMIYOR. "Yönetilebilir" bir ölçüm anı;
 * onu hedefin kalıcı bir özelliği gibi göstermek, sonradan visudo'su
 * kaldırılmış bir makineyi yeşil gösterirdi. Her denetim yeniden soruyor
 * ve ne zaman sorulduğunu yazıyor.
 */
export default function ManageAccess({
  name,
  enabled,
}: {
  name: string;
  enabled: boolean;
}) {
  const [result, setResult] = useState<ManageCheck | null>(null);
  const [error, setError] = useState("");

  const check = () => {
    setError("");
    return api
      .checkManagement(name)
      .then(setResult)
      .catch((e: unknown) => {
        setResult(null);
        setError(toMessage(e));
      });
  };

  return (
    <div className="card">
      <div className="card-head">
        <h3>Management</h3>
        <p>
          Whether postern can configure accounts and sudo on this host through
          its own management account. A check signs a two-minute certificate,
          signs in as <code>postern</code> and reads which tools the host has.
          It changes nothing, and it is recorded in the admin log.
        </p>
      </div>
      <div className="card-body">
        {!enabled ? (
          // ⚠️ "Kapalı" ile "bozuk" AYRI ŞEYLER — Identified kartındaki
          // kuralın aynısı. Düğmesiz boş bir kart, kapalı bir özelliği
          // çalışmayan bir özellik gibi gösterirdi.
          // ⚠️ Anahtar–değer çiftleri kod olarak yazılmıyor: dar kartta
          // "postern_manage_host:" ile "true" ayrı satırlara kırılıyordu
          // (ekrana bakılarak görüldü).
          <p className="no-match">
            Management is switched off on this bastion. Turn on{" "}
            <code>manage.enabled</code> in <code>postern.yaml</code> to check
            hosts where the <code>postern_target</code> group created the
            management account.
          </p>
        ) : (
          <>
            <ErrorLine msg={error} />
            {result && <Outcome r={result} />}
            <div className="card-actions">
              <ActionButton
                onClick={check}
                label={`check management access to ${name}`}
              >
                {result ? "Check again" : "Check management access"}
              </ActionButton>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function Outcome({ r }: { r: ManageCheck }) {
  const found = Object.values(r.tools ?? {})
    .filter(Boolean)
    .map((p) => p.split("/").pop());

  return (
    <>
      {r.manageable ? (
        <p className="msg msg-ok" role="status">
          postern signed in with its own certificate and can manage this host.
        </p>
      ) : (
        // Metin sunucudan geliyor ve aşamaya göre farklı iş söylüyor:
        // CA'ya güvenmeyen hedef, eksik araç ve cevap vermeyen makine.
        <p className="msg msg-warn" role="status">
          {r.reason}
        </p>
      )}

      <dl className="kv">
        {r.stage === "done" && (
          <>
            <dt>Family</dt>
            <dd>{r.family || "not recognised"}</dd>
            <dt>Found</dt>
            <dd>{found.length ? found.join(", ") : "none of the tools"}</dd>
            {r.missing.length > 0 && (
              <>
                <dt>Missing</dt>
                <dd className="bad">{r.missing.join(", ")}</dd>
              </>
            )}
          </>
        )}
        {/*
          ⚠️ CA HER SONUÇTA GÖRÜNÜYOR. Reddin en sık sebebi hedefin başka
          bir CA'ya güvenmesi; operatörün hedefteki postern_ca.pub ile
          karşılaştıracağı satır bu.
        */}
        <dt>Bastion CA</dt>
        <dd>{r.ca_fingerprint}</dd>
        <dt>Checked</dt>
        <dd>
          <Timestamp value={r.checked_at} />
        </dd>
      </dl>

      {/*
        ⚠️ HAM METİN KATLANIYOR. Operatöre yapacağı işi üstteki cümle
        söylüyor; bağlantının kendi hata zinciri uzun, teknik ve çoğu
        zaman gereksiz. Kartın gövdesinde düz metin olarak durduğunda
        cümleyle yarışıyordu (ekrana bakılarak görüldü).
      */}
      {r.detail && (
        <details className="run-log">
          <summary>What the connection reported</summary>
          <p className="note">{r.detail}</p>
        </details>
      )}
    </>
  );
}
