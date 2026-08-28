import { useCallback, useEffect, useState } from "react";
import { TargetDetail as Detail, api, toMessage } from "../api";
import { ActionButton, ErrorLine, OkLine } from "./common";
import { BackIcon } from "../icons";

/**
 * TargetDetail — bir hedefin kendi sayfası.
 *
 * NEDEN AYRI SAYFA: tablo satırı adres, parmak izi, etiketler, hangi
 * rollerin eriştiği, son oturumlar ve el sıkışmada öğrenilenleri birden
 * taşıyamıyor. Denendi: satır okunmaz hâle geliyor ve birincil eylem
 * yatay kaydırmanın ardına düşüyordu.
 */

const stampFmt = new Intl.DateTimeFormat(undefined, {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

function Stamp({ value }: { value?: string }) {
  if (!value) return <span className="muted">—</span>;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return <>{value}</>;
  return (
    <time dateTime={value} title={value}>
      {stampFmt.format(d)}
    </time>
  );
}

export default function TargetDetail({
  name,
  onBack,
}: {
  name: string;
  onBack: () => void;
}) {
  const [t, setT] = useState<Detail | null>(null);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const [loading, setLoading] = useState(true);
  const [lk, setLk] = useState("");
  const [lv, setLv] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    return api
      .targetDetail(name)
      .then((v) => {
        setT(v);
        setError("");
      })
      .catch((e: unknown) => setError(toMessage(e)))
      .finally(() => setLoading(false));
  }, [name]);

  useEffect(() => {
    load();
  }, [load]);

  const addLabel = () => {
    setOk("");
    return api
      .setTargetLabel(name, lk.trim(), lv.trim())
      .then(() => {
        setLk("");
        setLv("");
        setOk("label saved");
        return load();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const removeLabel = (key: string) => {
    setOk("");
    return api
      .removeTargetLabel(name, key)
      .then(load)
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const remove = () => {
    setOk("");
    return api
      .deleteTarget(name)
      // Silinen hedefin sayfasında kalmak anlamsız: listeye dön.
      .then(onBack)
      .catch((e: unknown) => setError(toMessage(e)));
  };

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <button className="btn-quiet back-link" onClick={onBack}>
            <BackIcon />
            All targets
          </button>
          <h2>{name}</h2>
          <p className="page-sub">
            Everything postern knows about this host — what you configured, and
            what it told us when we last connected.
          </p>
        </div>
        <ActionButton
          variant="danger"
          onClick={remove}
          confirm={`Delete target ${name}? Nobody will be able to open a session to it, and its pinned host key is gone with it.`}
          label={`delete target ${name}`}
        >
          Delete target
        </ActionButton>
      </div>

      <ErrorLine msg={error} />
      <OkLine msg={ok} />

      {loading && !t && <p className="state">Loading…</p>}

      {t && (
        <div className="detail-grid">
          {/*
            ⚠️ SÜTUNLAR AÇIKÇA YAZILI, auto-fit ile AKMIYOR.

            Kartlar tek bir auto-fit ızgarasına bırakıldığında sıraları
            ekran genişliğine göre değişiyor, yükseklikleri birbirini
            itiyor ve aynı sayfa her açılışta başka görünüyordu. Burada
            hangi kartın nerede duracağı sabit: solda "bu makine nedir",
            sağda "nasıl düzenlenmiş ve kim erişiyor", altta geçmiş.
          */}
          <div className="detail-main">
              <div className="card">
                <div className="card-head">
                  <h3>Configuration</h3>
                <p>What an operator entered. postern holds the host to this.</p>
              </div>
              <div className="card-body">
                <dl className="kv">
                  <dt>Address</dt>
                  <dd>
                    {t.host}:{t.port}
                  </dd>
                  <dt>Host key</dt>
                  <dd>{t.fingerprint}</dd>
                  <dt>Key type</dt>
                  <dd>{t.facts.host_key_type || "—"}</dd>
                </dl>
              </div>
            </div>

            <div className="card">
              <div className="card-head">
                <h3>Observed</h3>
                {/*
                  Bu ayrımı yazmak önemli: aşağıdakiler yapılandırma değil,
                  makinenin el sıkışmada söyledikleri.

                  ⚠️ Metin "postern hedefte hiçbir şey çalıştırmaz" DİYORDU;
                  target_probe eklendikten sonra bu artık her kurulumda
                  doğru değil. Bir güven ifadesinin koşullu hale geldiği an
                  düzeltilmesi gerekir — yoksa panel, kurumun kendi
                  politikasına aykırı bir şey söylemeye başlar.
                */}
                <p>
                  Read from the SSH handshake. Nothing is executed on the target
                  to collect any of this.
                </p>
              </div>
              <div className="card-body">
                <dl className="kv">
                  <dt>SSH banner</dt>
                  <dd>{t.facts.server_version || "not seen yet"}</dd>
                  <dt>Last reached</dt>
                  <dd>
                    <Stamp value={t.facts.last_seen_at} />
                  </dd>
                  <dt>Handshake</dt>
                  <dd>{t.facts.connect_ms ? `${t.facts.connect_ms} ms` : "—"}</dd>
                </dl>

                {/* Başarı, önceki HATAYI SİLMİYOR: "en son ne zaman
                    çalıştı" ile "en son neden çalışmadı" ayrı sorular. */}
                {t.facts.last_error && (
                  <p className="msg msg-warn" role="status">
                    last failure <Stamp value={t.facts.last_error_at} /> —{" "}
                    {t.facts.last_error}
                  </p>
                )}
              </div>
            </div>

            {/*
              AYRI KART, "Observed"ın içinde değil.

              Yukarıdaki kart hedefe DOKUNMADAN öğrenilenleri gösteriyor;
              burası ancak target_probe.enabled ile, hedefte komut
              çalıştırılarak elde ediliyor. İkisini aynı kutuya koymak,
              operatörün "bu satırı öğrenmek için makineye dokunduk mu"
              sorusunu cevapsız bırakırdı — ve o soru, denetim
              politikasının tam ortasında duruyor.
            */}
            <div className="card">
              <div className="card-head">
                <h3>Identified</h3>
                <p>
                  Requires <code>target_probe</code>. postern runs a fixed,
                  read-only command set on the connecting user&apos;s own
                  connection — so it appears in the target&apos;s logs under
                  their account, and every run is in the admin log.
                </p>
              </div>
              <div className="card-body">
                {t.facts.probed_at ? (
                  <dl className="kv">
                    <dt>OS</dt>
                    <dd>{t.facts.os_name || "—"}</dd>
                    <dt>Kernel</dt>
                    <dd>{t.facts.kernel || "—"}</dd>
                    <dt>Identified</dt>
                    <dd>
                      <Stamp value={t.facts.probed_at} />
                    </dd>
                  </dl>
                ) : (
                  // ⚠️ "Bilmiyoruz" ile "sormadık" AYRI ŞEYLER. Boş bir
                  // kutu, kapalı bir özelliği bozuk bir özellik gibi
                  // gösterirdi.
                  <p className="no-match">
                    This host has not been identified. Either{" "}
                    <code>target_probe</code> is switched off on this bastion, or
                    nobody has connected since it was turned on.
                  </p>
                )}
              </div>
            </div>

          </div>

          <div className="detail-side">
              <div className="card">
                <div className="card-head">
                  <h3>Labels</h3>
                <p>
                  Notes for finding this host. A label grants nothing — access
                  comes only from a role.
                </p>
              </div>
              <div className="card-body">
                <div className="chips">
                  {Object.keys(t.labels).length === 0 && (
                    <span className="muted small">no labels</span>
                  )}
                  {Object.entries(t.labels).map(([k, v]) => (
                    <span key={k} className="label-chip">
                      <span className="k">{k}</span>
                      <span className="v">{v}</span>
                      <ActionButton
                        onClick={() => removeLabel(k)}
                        label={`remove label ${k} from ${name}`}
                      >
                        ×
                      </ActionButton>
                    </span>
                  ))}
                </div>

                <div className="field-row" style={{ marginTop: "0.9rem" }}>
                  <label>
                    Key
                    <input
                      value={lk}
                      onChange={(e) => setLk(e.target.value)}
                      placeholder="env"
                    />
                  </label>
                  <label>
                    Value
                    <input
                      value={lv}
                      onChange={(e) => setLv(e.target.value)}
                      placeholder="prod"
                    />
                  </label>
                  <ActionButton
                    variant="primary"
                    onClick={addLabel}
                    disabled={!lk.trim()}
                    label={`add a label to ${name}`}
                  >
                    Add label
                  </ActionButton>
                </div>
              </div>
            </div>

            <div className="card">
              <div className="card-head">
                <h3>Reached by</h3>
                <p>
                  The roles that grant this target. Anyone holding one of them can
                  open a session here.
                </p>
              </div>
              <div className="card-body">
                {t.granted_by.length === 0 ? (
                  <p className="msg msg-warn" role="status">
                    No role grants this target, so nobody can reach it.
                  </p>
                ) : (
                  <div className="chips">
                    {t.granted_by.map((r) => (
                      <span key={r} className="chip">
                        <code>{r}</code>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>

          </div>

          <div className="card detail-wide">
            <div className="card-head">
              <h3>Recent sessions</h3>
              <p>The last connections opened to this host.</p>
            </div>
            {t.recent_sessions.length === 0 ? (
              <p className="no-match">No session has been opened to this host.</p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>
                        <span className="th-pad">User</span>
                      </th>
                      <th>
                        <span className="th-pad">OS user</span>
                      </th>
                      <th>
                        <span className="th-pad">Src</span>
                      </th>
                      <th>
                        <span className="th-pad">Started</span>
                      </th>
                      <th>
                        <span className="th-pad">Ended</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {t.recent_sessions.map((s) => (
                      <tr key={s.id}>
                        <td>{s.user}</td>
                        <td>{s.os_user}</td>
                        <td>{s.src_ip}</td>
                        <td>
                          <Stamp value={s.started_at} />
                        </td>
                        <td>
                          {s.ended_at ? (
                            <Stamp value={s.ended_at} />
                          ) : (
                            <span className="badge badge-ok">running</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
