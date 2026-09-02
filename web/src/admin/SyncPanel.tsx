import { useCallback, useEffect, useState } from "react";
import { SyncRun, SyncSettings, api, toMessage } from "../api";
import { ActionButton, ErrorLine, OkLine } from "./common";

/**
 * SyncPanel — dizin senkronizasyonu.
 *
 * NEDEN LDAP SAYFASINDA: senkronizasyon bir LDAP özelliği. Dizini
 * kimin, nasıl okuduğunu ayarlayan ekranla, o dizine bakıp YETKİ İPTAL
 * EDEN döngüyü ayarlayan ekran ayrı yerlerde durunca, ikincisinin var
 * olduğunu bilmeyen bir operatör LDAP'ı kurup işinin bittiğini sanıyordu.
 *
 * ⚠️ EKRANIN TONU KASITLI. Bu döngü kullanıcıların erişimini KENDİLİĞİNDEN
 * kaldırıyor. Uyarı süs değil: açmadan önce dry_run ile koşturmak doğru
 * yol ve bunu söylemeyen bir arayüz, operatörü kör bir anahtara
 * bastırıyor demektir.
 */

type Field = {
  key: string;
  label: string;
  hint: string;
  get: (s: SyncSettings) => string;
};

/*
 * ⚠️ PATLAMA YARIÇAPI TAVANLARI BU LİSTEDE YOK — VE OLMAMASI BİR KARAR.
 *
 * max_zero_fraction, min_zero_floor, max_unknown_fraction ve
 * max_revoke_per_run burada dört kutuydu. Sunucu tarafındaki
 * SyncConfig yorumu ise bunu bir güvenlik değişmezi olarak ilan
 * ediyordu: "tavanı yükseltebilmek için host'a erişmek gerekmeli."
 * Yorum bir garanti veriyor, panel onu bozuyordu.
 *
 * Otomatik toplu yetki iptalinin üst sınırını, ele geçirilmiş bir panel
 * oturumu yükseltebilmemeli — panelden `is_admin` verilmemesiyle ve
 * arşiv hedefinin panelden değiştirilememesiyle aynı raf. Burada kalan
 * dördü tavan değil ritim: ne sıklıkta, ne kadar bekleyerek, ve
 * yazmadan mı.
 */
const LIMITS: Field[] = [
  {
    key: "sync.interval",
    label: "Interval",
    hint: "how long between runs — 15m, 1h",
    get: (s) => s.interval,
  },
  {
    key: "sync.grace",
    label: "Grace",
    hint: "how long someone may be missing from the directory before their access is revoked. A short replication lag or a maintenance window must not cost anyone their roles.",
    get: (s) => s.grace,
  },
];

export default function SyncPanel({ ldapReady }: { ldapReady: boolean }) {
  const [s, setS] = useState<SyncSettings | null>(null);
  const [runs, setRuns] = useState<SyncRun[]>([]);
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");

  const load = useCallback(
    () =>
      Promise.all([
        api.syncSettings().then((v) => {
          setS(v);
          setError(v.error ?? "");
        }),
        // Koşu geçmişi ayrı düşebilir: ayarlar okunuyorsa ekran
        // çizilmeli, geçmişin gelmemesi tüm paneli boş bırakmamalı.
        api.syncRuns(10).then(setRuns, () => setRuns([])),
      ]).catch((e: unknown) => setError(toMessage(e))),
    [],
  );

  useEffect(() => {
    load();
  }, [load]);

  const write = (key: string, value: string) => {
    setOk("");
    return api
      .setSetting(key, value)
      .then(() => {
        setEdits((e) => {
          const n = { ...e };
          delete n[key];
          return n;
        });
        setOk("saved");
        return load();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  if (!s) return <p className="state">Loading…</p>;

  const overridden = new Set(s.overridden);

  return (
    <div className="card">
      <div className="card-head">
        <h3>Directory sync</h3>
        <p>
          Re-reads every user&apos;s groups on a timer and applies the result —
          including taking roles away from people the directory no longer places
          in them.
        </p>
      </div>

      <div className="card-body">
        <ErrorLine msg={error} />
        <OkLine msg={ok} />

        {/*
          ⚠️ KOŞULARIN SONUCU EKRANDA. Patlama yarıçapı korumaları bir
          koşuyu iptal ettiğinde bunun tek izi sync_runs tablosuydu ve
          onu okuyan tek şey host üzerindeki bir komuttu — yani "hiç
          kimsenin yetkisi iptal edilmiyor" hâli panelden TAMAMEN
          görünmüyordu. Sessiz bir güvenlik arızasının en pahalı biçimi.
        */}
        {runs[0]?.outcome === "aborted" && (
          <p className="msg msg-warn" role="status">
            <b>
              The last run was stopped by a safety ceiling and applied nothing.
            </b>{" "}
            {runs[0].reason} — until this clears, nobody is being revoked.
          </p>
        )}
        {runs.length >= 3 && runs.slice(0, 3).every((r) => r.dry_run) && (
          <p className="msg msg-warn" role="status">
            <b>The last three runs were dry runs.</b> Decisions were computed
            and reported, and nothing was written. Turn dry run off when you are
            done watching.
          </p>
        )}

        {!ldapReady && (
          <p className="msg msg-warn" role="status">
            No directory is configured, so nothing runs. These settings take
            effect once LDAP is set up.
          </p>
        )}

        {/*
          ⚠️ UYARI, AÇMA DÜĞMESİNİN ÜSTÜNDE. Altında olsaydı, düğmeye
          basan kişi onu okumadan basmış olurdu.
        */}
        <div className="danger-note">
          <b>This loop revokes access on its own.</b> Run it with <b>dry run</b>{" "}
          on for a while first and read <code>postern sync status</code>: it
          computes and reports every decision without writing anything.
        </div>

        {/*
          ⚠️ TAVANLARIN NEREDE OLDUĞU YAZILIYOR.
          Dört kutuyu buradan kaldırmak yetmez: nereye gittiklerini
          söylemeyen bir ekran, operatörü olmayan bir düğmeyi aramaya
          bırakır — ve bu deponun kuralı, kaldırılan yeteneğin sessiz
          kalmamasıdır.
        */}
        <p className="small muted">
          A directory that answers wrongly — half-migrated, mid-outage, a filter
          typo — would otherwise take everyone&apos;s access at once, so the
          loop has four ceilings on how much one run may revoke. They are set in
          the config file (<code>sync.max_revoke_per_run</code> and its three
          siblings) and deliberately cannot be raised from here: a stolen panel
          session must not be able to lift the limit on automatic bulk
          revocation.
        </p>

        <div className="sync-toggles">
          <label className="toggle">
            <input
              type="checkbox"
              checked={s.enabled}
              onChange={(e) => write("sync.enabled", String(e.target.checked))}
            />
            <span>
              <b>Enabled</b>
              <span className="toggle-hint">
                the loop runs on the interval below
              </span>
            </span>
          </label>

          <label className="toggle">
            <input
              type="checkbox"
              checked={s.dry_run}
              onChange={(e) => write("sync.dry_run", String(e.target.checked))}
            />
            <span>
              <b>Dry run</b>
              <span className="toggle-hint">
                decide and report, write nothing
              </span>
            </span>
          </label>
        </div>

        {s.enabled && !s.dry_run && (
          <p className="msg msg-warn" role="status">
            Live: the next run can revoke roles.
          </p>
        )}

        {runs.length > 0 && (
          <details className="run-log">
            <summary>Recent runs ({runs.length})</summary>
            <ul className="run-list">
              {runs.map((r) => (
                <li key={r.id}>
                  <span
                    className={
                      r.outcome === "ok" ? "tag tag-ok" : "tag tag-warn"
                    }
                  >
                    {r.outcome}
                  </span>
                  <code>{r.started_at}</code>
                  <span className="muted">
                    {r.considered} considered · {r.revoked} revoked ·{" "}
                    {r.unknown} unknown{r.dry_run ? " · dry run" : ""}
                  </span>
                  {r.reason && <div className="run-reason">{r.reason}</div>}
                </li>
              ))}
            </ul>
          </details>
        )}

        <div className="wizard-form">
          {LIMITS.map((f) => {
            const typed = edits[f.key];
            const current = f.get(s);
            return (
              <div className="wfield" key={f.key}>
                <label className="wfield-label" htmlFor={`sy-${f.key}`}>
                  {f.label}
                  {/* Değerin NEREDEN geldiğini söylemek şart: "ayarlanmamış"
                      demek, dosyadan gelen bir değerle koşan bir döngü için
                      yanlış bilgi olurdu. */}
                  <span className="wfield-req">
                    {overridden.has(f.key) ? "panel" : "config file"}
                  </span>
                </label>
                <input
                  id={`sy-${f.key}`}
                  value={typed ?? current}
                  onChange={(e) =>
                    setEdits({ ...edits, [f.key]: e.target.value })
                  }
                />
                <p className="wfield-hint">{f.hint}</p>
                {typed !== undefined && typed !== current && (
                  <div className="wfield-state">
                    <ActionButton
                      variant="primary"
                      onClick={() => write(f.key, typed.trim())}
                      label={`save ${f.key}`}
                    >
                      Save
                    </ActionButton>
                    <button
                      className="btn-quiet"
                      onClick={() =>
                        setEdits((e) => {
                          const n = { ...e };
                          delete n[f.key];
                          return n;
                        })
                      }
                    >
                      Cancel
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
