import { useCallback, useEffect, useMemo, useState } from "react";
import {
  DiscoveredMachine,
  DiscoveryOverview,
  DiscoveryProbe,
  DiscoverySource,
  DiscoverySourceInput,
  MachineRef,
  Registered,
  Group,
  api,
  toMessage,
} from "../api";
import { ActionButton, ErrorLine, ListState, Timestamp, useList } from "./common";
import DataTable, { Column } from "./DataTable";
import GrowingTable from "./GrowingTable";
import Modal from "./Modal";
import MultiSelect from "./MultiSelect";

/*
 * Discovery — panelden keşif: kaynaklar, koşuları ve buldukları makineler.
 *
 * ⚠️ KOŞU HEDEF YAZMIYOR. CLI'daki `postern discover --apply` yazıyor,
 * çünkü orada önizlemeyi bir insan okuyup onaylıyor; zamanlayıcının okuru
 * yok. Bulunan makine burada bir satır; hedef olması "Register" ile ve
 * yöneticinin rolleri, etiketleri ve özet ekranında parmak izini görüp
 * onaylamasıyla oluyor. Sanallaştırma platformunda VM açabilen biri
 * böylece postern'de kimsenin erişebileceği bir makine yaratamıyor.
 *
 * ⚠️ DURUM SATIRDAN TÜRETİLİYOR (machineState): sunucu "durum" diye tek
 * bir alan vermiyor; yok sayılmış, kayıp, kayıtlı-ama-anahtarı-değişmiş,
 * engelli ve yeni birbirinden ayrı ve ilk ikisi seçilebilir ama
 * kaydedilemez. Anahtarı değişen makine KIRMIZI: hedefe dokunulmadı ve
 * "makine yenilendi" mi "makine değişti" mi kararını insan verecek.
 */

const SCHEDULES: [number, string][] = [
  [0, "Only when asked"],
  [300, "Every 5 minutes"],
  [900, "Every 15 minutes"],
  [3600, "Every hour"],
  [21600, "Every 6 hours"],
  [86400, "Every day"],
];

export type MachineState = {
  text: "new" | "registered" | "key changed" | "blocked" | "missing" | "ignored";
  cls: string;
  registrable: boolean;
};

export function machineState(m: DiscoveredMachine): MachineState {
  if (m.ignored) return { text: "ignored", cls: "badge badge-mono", registrable: false };
  if (m.missing_since) return { text: "missing", cls: "badge badge-danger", registrable: false };
  if (m.target) {
    if (m.problem) return { text: "key changed", cls: "badge badge-danger", registrable: false };
    return { text: "registered", cls: "badge badge-ok", registrable: false };
  }
  if (m.problem || !m.fingerprint) return { text: "blocked", cls: "badge badge-warn", registrable: false };
  return { text: "new", cls: "badge badge-info", registrable: true };
}

/** LabelRow, etiket tablosunun tek satırı. */
export type LabelRow = { key: string; value: string };

/*
 * ⚠️ ANAHTAR KURALI SUNUCUNUNKİYLE AYNI (store.ValidateLabel). Panelde
 * daha gevşek bir kural, yazdırıp sonra reddedilen bir etiket demek;
 * daha katı bir kural, sunucunun kabul ettiği bir adı yazdırmamak.
 */
const labelKeyRe = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$/;

/*
 * labelsOf, tablo satırlarını etiket haritasına çevirir ve okunur bir
 * hata döner.
 *
 * ⚠️ SERBEST METİN YERİNE TABLO. Kutuya "env=prod" yazdırmak, yazım
 * biçimini öğretilmesi gereken bir şeye çeviriyordu: eşittir unutulunca
 * satır sessizce düşüyor, yer tutucu yazılmış sanılıyordu (kullanıcı
 * söyledi). İki alan, hangi parçanın anahtar hangisinin değer olduğunu
 * kendisi söylüyor.
 */
export function labelsOf(rows: LabelRow[]): { labels: Record<string, string>; error: string } {
  const labels: Record<string, string> = {};
  for (const r of rows) {
    const key = r.key.trim();
    const value = r.value.trim();
    if (key === "" && value === "") continue;
    if (key === "") return { labels, error: `"${value}" has no key` };
    if (!labelKeyRe.test(key)) {
      return {
        labels,
        error: `label key "${key}" is not allowed: letters, digits, dot, dash or underscore (max 63)`,
      };
    }
    if (key in labels) return { labels, error: `label key "${key}" is written twice` };
    labels[key] = value;
  }

  return { labels, error: "" };
}

const keyOf = (m: MachineRef) => `${m.source_id}/${m.ref}`;

export default function Discovery() {
  const [overview, setOverview] = useState<DiscoveryOverview | null>(null);
  const [listError, setListError] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [editing, setEditing] = useState<DiscoverySource | null | "new">(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [showOffline, setShowOffline] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [round, setRound] = useState(0);

  const load = useCallback(
    () =>
      api
        .discovery()
        .then((v) => {
          setOverview(v);
          setListError("");
        })
        .catch((e: unknown) => setListError(toMessage(e)))
        .finally(() => setLoading(false)),
    [],
  );
  useEffect(() => {
    load();
  }, [load]);

  // Koşu arka planda: biri sürerken liste birkaç saniyede bir tazeleniyor
  // ki "Run now"a basan yönetici sonucu görmek için sayfayı yenilemesin.
  const anyRunning = overview?.sources.some((s) => s.running) ?? false;
  useEffect(() => {
    if (!anyRunning) return;
    const t = setInterval(() => void load(), 3000);
    return () => clearInterval(t);
  }, [anyRunning, load]);

  const machines = overview?.machines ?? [];
  const byKey = useMemo(() => new Map(machines.map((m) => [keyOf(m), m])), [machines]);
  const chosen = selected.map((k) => byKey.get(k)).filter((m): m is DiscoveredMachine => !!m);
  const registrable = chosen.filter((m) => machineState(m).registrable);

  const setIgnored = async (ignored: boolean) => {
    setError("");
    const refs = chosen
      .filter((m) => m.ignored !== ignored)
      .map((m) => ({ source_id: m.source_id, ref: m.ref }));
    try {
      await api.ignoreDiscovered(refs, ignored);
      setSelected([]);
      await load();
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  const runNow = (s: DiscoverySource) => {
    setError("");
    return api
      .runDiscoverySource(s.id)
      .then(() => load())
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const remove = (s: DiscoverySource) => {
    setError("");
    return api
      .deleteDiscoverySource(s.id)
      .then(() => load())
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const columns: Column<DiscoveredMachine>[] = [
    {
      key: "name",
      header: "Machine",
      className: "wrap",
      value: (m) => `${m.name} ${m.ref}`,
      render: (m) => (
        <>
          {m.name}
          <br />
          <code className="small">{m.ref}</code>
          {/*
            ⚠️ "KAPALI OLDUĞU İÇİN ANAHTARI OKUNAMADI" SATIRA YAZILMIYOR.
            Kapalı makineler zaten listelenmiyor (aşağıdaki süzgeç) ve o
            cümleyi her satıra koymak, gerçekten bakılacak sorunları
            gürültüye boğuyordu — yirmi dört satırın yirmi ikisi aynı
            cümleyi tekrar ediyordu (kullanıcı ekrana bakıp söyledi).
          */}
          {m.problem && !m.problem.startsWith("not running") && (
            <div className="small muted">{m.problem}</div>
          )}
        </>
      ),
    },
    { key: "source", header: "Source", className: "wrap", value: (m) => m.source },
    {
      key: "host",
      header: "Address",
      className: "wrap",
      value: (m) => m.host || m.name,
      render: (m) => (
        <>
          {/* Adres yoksa adı ikinci kez yazmıyoruz: aynı hücrede aynı
              kelime, sütunu okunmaz yapıyordu. */}
          {m.host || (
            <span className="muted" title={`no address reported; postern would try ${m.name}`}>
              —
            </span>
          )}
          {m.fingerprint && (
            <>
              <br />
              {/* Tam parmak izi özet adımında; burada kısaltılmış, tamamı başlıkta. */}
              <code className="small" title={m.fingerprint}>
                {m.fingerprint.length > 20 ? `${m.fingerprint.slice(0, 20)}…` : m.fingerprint}
              </code>
            </>
          )}
        </>
      ),
    },
    {
      key: "group",
      header: "Tag group",
      className: "wrap",
      value: (m) => m.group ?? "",
      render: (m) =>
        m.group ? (
          m.group
        ) : (
          <span className="muted">{m.tags.length ? `untagged (${m.tags.join(", ")})` : "untagged"}</span>
        ),
    },
    {
      key: "state",
      header: "State",
      className: "grant-state",
      value: (m) => machineState(m).text,
      render: (m) => {
        const st = machineState(m);
        return (
          <>
            <span className={st.cls}>{st.text}</span>
            {m.target && (
              <>
                {" "}
                <span className="small">as {m.target}</span>
              </>
            )}
            {m.missing_since && (
              <div className="small muted">
                not reported since <Timestamp value={m.missing_since} />
              </div>
            )}
          </>
        );
      },
    },
    {
      key: "seen",
      header: "Last seen",
      value: (m) => m.last_seen,
      render: (m) => <Timestamp value={m.last_seen} />,
    },
  ];

  const sources = overview?.sources ?? [];

  /*
   * ⚠️ KAPALI MAKİNELER LİSTEDE DEĞİL, SAYIDA.
   *
   * Kapalı bir makinenin host anahtarı okunamıyor, yani kaydedilemiyor da;
   * listede yapılabilecek hiçbir şeyi olmayan satırlar olarak duruyorlardı
   * ve yirmi dört makinelik bir kümede yirmi ikisi oydu (kullanıcı ekrana
   * bakıp söyledi). Saklamak sessizce silmek değil: kaç tane olduğu
   * yazıyor ve tek tıkla listeye giriyorlar.
   */
  const offline = (overview?.machines ?? []).filter((m) => !m.running && !m.target);
  const listed = showOffline ? machines : machines.filter((m) => m.running || !!m.target);

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Discovery</h2>
          <p className="page-sub">
            Sources are hypervisors postern reads on a schedule. What they report lands
            here as machines, with the host key postern read from each; a machine becomes a
            target only when you register it. Discovery never grants anyone access on its
            own.
          </p>
        </div>
        <ActionButton
          variant="primary"
          onClick={() => setEditing("new")}
          disabled={overview !== null && !overview.secrets_available}
        >
          Add source
        </ActionButton>
      </div>

      {overview && !overview.secrets_available && (
        <p className="msg msg-warn">
          The bastion has no secret key, so a source's credentials cannot be stored. Set{" "}
          <code>secret_key_file</code> in the configuration and restart postern.
        </p>
      )}
      <ErrorLine msg={error} />

      <h3>Sources</h3>
      <ListState
        loading={loading}
        denied={false}
        failed={listError !== ""}
        empty={!loading && !listError && sources.length === 0}
        emptyText="No source yet. Add a Proxmox cluster or a vCenter and postern will list its machines here."
      />
      <ErrorLine msg={listError} />
      {sources.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Address</th>
                <th>Schedule</th>
                <th>Last run</th>
                <th className="actions">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {sources.map((s) => (
                <tr key={s.id}>
                  <td className="wrap">
                    {s.name}
                    {!s.enabled && (
                      <>
                        {" "}
                        <span className="badge badge-mono">disabled</span>
                      </>
                    )}
                    {s.insecure && (
                      <>
                        {" "}
                        <span className="badge badge-danger" title="TLS verification is off">
                          unverified TLS
                        </span>
                      </>
                    )}
                  </td>
                  <td>{s.kind}</td>
                  <td className="wrap">
                    <code className="small">{s.url}</code>
                    <div className="small muted">
                      tag key {s.tag_key}
                      {s.name_pattern ? `, names ${s.name_pattern}` : ""}
                    </div>
                  </td>
                  <td>{SCHEDULES.find(([v]) => v === s.interval_seconds)?.[1] ?? `every ${s.interval_seconds}s`}</td>
                  <td className="wrap">
                    <LastRun s={s} />
                  </td>
                  <td className="actions">
                    <ActionButton
                      onClick={() => runNow(s)}
                      disabled={s.running}
                      label={`run ${s.name} now`}
                    >
                      Run now
                    </ActionButton>{" "}
                    <ActionButton onClick={() => setEditing(s)} label={`edit ${s.name}`}>
                      Edit
                    </ActionButton>{" "}
                    <ActionButton
                      variant="danger"
                      onClick={() => remove(s)}
                      confirm={`Remove source ${s.name}? Its list of discovered machines goes with it. Targets already registered stay.`}
                      label={`remove ${s.name}`}
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

      <h3>Machines</h3>
      {machines.length === 0 ? (
        !loading &&
        !listError && (
          <p className="muted">
            {sources.length === 0
              ? "Machines appear here after a source has run."
              : "No machine yet. Run a source, or wait for its schedule."}
          </p>
        )
      ) : (
        <>
          <div className="page-actions">
            <ActionButton
              variant="primary"
              onClick={() => {
                setRound((r) => r + 1);
                setRegistering(true);
              }}
              disabled={registrable.length === 0}
            >
              Register {registrable.length > 0 ? `${registrable.length} selected` : "selected"}…
            </ActionButton>
            <ActionButton
              onClick={() => setIgnored(true)}
              disabled={!chosen.some((m) => !m.ignored)}
            >
              Ignore selected
            </ActionButton>
            <ActionButton
              onClick={() => setIgnored(false)}
              disabled={!chosen.some((m) => m.ignored)}
            >
              Stop ignoring
            </ActionButton>
            {chosen.length > registrable.length && chosen.length > 0 && (
              <span className="small muted">
                {chosen.length - registrable.length} of the selected cannot be registered
                (already registered, missing, ignored or blocked).
              </span>
            )}
          </div>
          {offline.length > 0 && (
            <p className="muted small">
              {offline.length} machine{offline.length === 1 ? " is" : "s are"} powered off, so
              postern cannot read {offline.length === 1 ? "its" : "their"} host key and
              {offline.length === 1 ? " it" : " they"} cannot be registered.{" "}
              <button className="btn-quiet" onClick={() => setShowOffline((v) => !v)}>
                {showOffline ? "Hide them" : "Show them anyway"}
              </button>
            </p>
          )}
          <DataTable
            rows={listed}
            columns={columns}
            rowKey={keyOf}
            selection={{ selected, onChange: setSelected, label: (m) => `select ${m.name}` }}
            initialSort={{ key: "name", dir: "asc" }}
            searchLabel="Search machines"
            searchPlaceholder="Search by name, address, source, tag or state…"
            extraSearch={(m) => `${m.tags.join(" ")} ${m.problem ?? ""} ${m.target ?? ""}`}
            noun="machine"
          />
        </>
      )}

      <Modal
        open={editing !== null}
        title={editing === "new" ? "Add a discovery source" : `Edit ${editing?.name ?? ""}`}
        onClose={() => setEditing(null)}
        wide
      >
        {editing !== null && (
          <SourceForm
            source={editing === "new" ? null : editing}
            minInterval={overview?.min_interval_seconds ?? 300}
            onSaved={async () => {
              setEditing(null);
              await load();
            }}
          />
        )}
      </Modal>

      <Modal
        open={registering}
        title={`Register ${registrable.length} machine(s)`}
        description="Each becomes a target with the host key discovery read, joins the groups you pick, and carries the labels you add. Nothing is written until the last step."
        onClose={() => setRegistering(false)}
        wide
      >
        {registering && (
          <RegisterWizard
            key={round}
            machines={registrable}
            onDone={async () => {
              setSelected([]);
              await load();
            }}
            onClose={() => setRegistering(false)}
          />
        )}
      </Modal>
    </section>
  );
}

function LastRun({ s }: { s: DiscoverySource }) {
  if (s.running) return <span className="badge badge-info">running</span>;
  const r = s.last_run;
  if (!r) return <span className="muted">never</span>;
  return (
    <>
      <span className={r.outcome === "ok" ? "badge badge-ok" : r.outcome === "failed" ? "badge badge-danger" : "badge badge-info"}>
        {r.outcome}
      </span>{" "}
      <Timestamp value={r.started_at} />
      <div className="small muted">
        {r.outcome === "failed"
          ? r.reason
          : `${r.seen} seen, ${r.new_machines} new, ${r.missing} missing, ${r.key_changed} key changed, ${r.unreachable} unreachable`}
      </div>
    </>
  );
}

/*
 * SourceForm — kaynak ekleme/düzenleme, dört bölüm: platform, kimlik,
 * ne bulunacak, program. Kaydetmeden önce "Test connection" formdaki
 * değerlerle kaynağa bağlanıp saydığını söylüyor; hiçbir şey yazmıyor.
 *
 * ⚠️ SIR ALANI DÜZENLEMEDE BOŞ GELİYOR ve boş gönderilirse kayıtlı sır
 * KALIYOR: panel sırrı hiç okumuyor, dolayısıyla "değiştirmedim"i
 * söylemenin tek yolu boş bırakmak. Test de aynı kuralla: id + boş sır =
 * kayıtlı sırla dene. Tür düzenlemede değişmiyor — makine kimlikleri
 * türe özgü ("qemu/101" bir vSphere makinesi olamaz).
 *
 * ⚠️ ETİKET ANAHTARI TESTTE GÖRÜNÜYOR. CLI'da ölçülen arıza: yanlış
 * anahtar hata vermiyor, her makine sessizce etiketsiz kalıyor. Test
 * "0 machine(s) carry the tag, tags seen: …" diyor ve sarı çiziyor.
 */
function SourceForm({
  source,
  minInterval,
  onSaved,
}: {
  source: DiscoverySource | null;
  minInterval: number;
  onSaved: () => Promise<void>;
}) {
  const [kind, setKind] = useState<"proxmox" | "vsphere">(source?.kind ?? "proxmox");
  const [name, setName] = useState(source?.name ?? "");
  const [url, setUrl] = useState(source?.url ?? "");
  const [username, setUsername] = useState(source?.username ?? "");
  const [secret, setSecret] = useState("");
  const [tagKey, setTagKey] = useState(source?.tag_key ?? "group");
  const [namePattern, setNamePattern] = useState(source?.name_pattern ?? "");
  const [port, setPort] = useState(String(source?.port ?? 22));
  const [node, setNode] = useState(source?.node ?? "");
  const [interval, setIntervalSeconds] = useState(source?.interval_seconds ?? 3600);
  const [caPem, setCaPem] = useState(source?.ca_pem ?? "");
  const [insecure, setInsecure] = useState(source?.insecure ?? false);
  const [enabled, setEnabled] = useState(source?.enabled ?? true);
  const [error, setError] = useState("");
  const [probe, setProbe] = useState<DiscoveryProbe | null>(null);
  const [probeError, setProbeError] = useState("");

  const proxmox = kind === "proxmox";
  const input = (): DiscoverySourceInput => ({
    name: name.trim(),
    kind,
    url: url.trim(),
    username: username.trim(),
    secret,
    ca_pem: caPem.trim(),
    insecure,
    node: proxmox ? node.trim() : "",
    tag_key: tagKey.trim(),
    name_pattern: namePattern.trim(),
    port: Number(port) || 22,
    interval_seconds: interval,
    enabled,
  });

  const test = async () => {
    setProbeError("");
    setProbe(null);
    try {
      setProbe(await api.testDiscoverySource({ ...input(), id: source?.id }));
    } catch (e: unknown) {
      setProbeError(toMessage(e));
    }
  };

  const save = async () => {
    setError("");
    try {
      if (source) await api.updateDiscoverySource(source.id, input());
      else await api.createDiscoverySource(input());
      await onSaved();
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  const key = tagKey.trim() || "group";
  const platform = proxmox ? "Proxmox" : "vCenter";

  return (
    <>
      <div className="form-section" role="group" aria-labelledby="src-platform">
        <h4 id="src-platform">Platform</h4>
        <div className="form-grid cols-3">
          <label>
            Kind
            <select
              value={kind}
              disabled={source !== null}
              onChange={(e) => setKind(e.target.value as "proxmox" | "vsphere")}
            >
              <option value="proxmox">Proxmox VE</option>
              <option value="vsphere">vSphere (vCenter)</option>
            </select>
          </label>
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="lab cluster" />
          </label>
          <label>
            Address
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={proxmox ? "https://pve.example:8006" : "https://vcenter.example"}
            />
          </label>
        </div>
      </div>

      <div className="form-section" role="group" aria-labelledby="src-credentials">
        <h4 id="src-credentials">How postern signs in</h4>
        <div className="form-grid cols-2">
          <label>
            {proxmox ? "API token id" : "vCenter user"}
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={proxmox ? "postern@pve!discovery" : "postern@vsphere.local"}
            />
          </label>
          <label>
            {proxmox ? "API token secret" : "Password"}
            <input
              type="password"
              autoComplete="off"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder={source?.secret_set ? "unchanged unless you type a new one" : ""}
            />
          </label>
          <label className="span-all">
            CA certificate (PEM)
            <textarea
              rows={3}
              value={caPem}
              onChange={(e) => setCaPem(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE----- … leave empty to trust the system roots"
            />
          </label>
          <label className="check span-all">
            <input type="checkbox" checked={insecure} onChange={(e) => setInsecure(e.target.checked)} />
            Skip TLS verification. Anyone between postern and {platform} can then decide which
            machines appear here and with which tags. Paste the CA certificate instead.
          </label>
        </div>
        <p className="muted small">
          {proxmox
            ? "A read-only token is enough: it needs VM.Audit and nothing else."
            : "Use a read-only account; postern only lists machines and their tags."}
        </p>
      </div>

      <div className="form-section" role="group" aria-labelledby="src-scope">
        <h4 id="src-scope">What to discover</h4>
        <div className={proxmox ? "form-grid cols-4" : "form-grid cols-3"}>
          <label>
            Tag key
            <input value={tagKey} onChange={(e) => setTagKey(e.target.value)} />
          </label>
          <label>
            Name pattern
            <input
              value={namePattern}
              onChange={(e) => setNamePattern(e.target.value)}
              placeholder="web-*, db-* (empty: every machine)"
            />
          </label>
          {proxmox && (
            <label>
              Node
              <input value={node} onChange={(e) => setNode(e.target.value)} placeholder="all nodes" />
            </label>
          )}
          <label>
            SSH port
            <input value={port} inputMode="numeric" onChange={(e) => setPort(e.target.value)} />
          </label>
        </div>
        <p className="muted small">
          {proxmox
            ? `Proxmox tags cannot contain = or :, so a machine's group is written as ${key}_<group>, e.g. ${key}_ops. A machine without that tag is listed as untagged.`
            : `The tag key names a tag category in vCenter; the tag in that category is the group. A machine without one is listed as untagged.`}
        </p>
      </div>

      <div className="form-section" role="group" aria-labelledby="src-schedule">
        <h4 id="src-schedule">Schedule</h4>
        <div className="form-grid cols-2">
          <label>
            Runs
            <select value={interval} onChange={(e) => setIntervalSeconds(Number(e.target.value))}>
              {SCHEDULES.filter(([v]) => v === 0 || v >= minInterval).map(([v, label]) => (
                <option key={v} value={v}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label className="check">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Enabled — a disabled source keeps its machines but is not run on schedule
          </label>
        </div>
      </div>

      {probe && <ProbeResult probe={probe} platform={platform} tagKey={key} pattern={namePattern.trim()} />}
      <ErrorLine msg={probeError} />
      <ErrorLine msg={error} />
      <div className="form-actions">
        <ActionButton onClick={test} disabled={!url.trim()}>
          Test connection
        </ActionButton>
        <span className="muted small">
          Signs in with the values above and counts what {platform} reports. Nothing is saved.
        </span>
        <span className="form-push">
          <ActionButton variant="primary" onClick={save}>
            {source ? "Save changes" : "Save source"}
          </ActionButton>
        </span>
      </div>
    </>
  );
}

/* Test bağlantısının cümlesi: etiket anahtarı hiçbir makinede yoksa sarı. */
function ProbeResult({
  probe,
  platform,
  tagKey,
  pattern,
}: {
  probe: DiscoveryProbe;
  platform: string;
  tagKey: string;
  pattern: string;
}) {
  const untagged = probe.machines > 0 && probe.tagged === 0;
  return (
    <p className={untagged ? "msg msg-warn" : "msg msg-ok"} role="status">
      Reached {platform}: {probe.machines} machine(s), {probe.running} running, {probe.with_address} with an
      address{pattern ? `, ${probe.matching} matching "${pattern}"` : ""}. {probe.tagged} carry a "{tagKey}" tag
      {probe.groups.length ? ` (groups: ${probe.groups.join(", ")})` : ""}.
      {untagged && probe.tags.length > 0
        ? ` Not one machine carries that key — the tags actually seen were ${probe.tags.join(", ")}.`
        : untagged
          ? " These machines carry no tags at all."
          : ""}
    </p>
  );
}

/*
 * RegisterWizard — üç adım: roller, etiketler, özet → kayıt.
 *
 * ⚠️ ÖZET EKRANI PARMAK İZİNİ GÖSTERİYOR ve kayıt o anahtarı sabitliyor
 * (sunucu yeniden taramıyor). Yönetici neyi onayladıysa o yazılıyor.
 */
/**
 * LabelTable — anahtar/değer satırları, doldukça büyüyen tabloda.
 *
 * ⚠️ BÜYÜME KURALI GrowingTable'DA, BURADA DEĞİL: aynı davranış sudo
 * komutlarında da lazım ve iki kopya zamanla ayrışır.
 */
function LabelTable({
  rows,
  onChange,
}: {
  rows: LabelRow[];
  onChange: (rows: LabelRow[]) => void;
}) {
  return (
    <GrowingTable<LabelRow>
      rows={rows}
      onChange={onChange}
      empty={{ key: "", value: "" }}
      removeLabel={(n) => `remove label row ${n}`}
      columns={[
        { key: "key", header: "Key", placeholder: "env", label: (n) => `label key ${n}` },
        { key: "value", header: "Value", placeholder: "prod", label: (n) => `label value ${n}` },
      ]}
    />
  );
}

function RegisterWizard({
  machines,
  onDone,
  onClose,
}: {
  machines: DiscoveredMachine[];
  onDone: () => Promise<void>;
  onClose: () => void;
}) {
  const groups = useList<Group>(api.groups);
  const [step, setStep] = useState(0);
  /*
   * ⚠️ MAKİNENİN ETİKETİNDEKİ ROL SEÇİLİ GELİYOR. Platformda "role_web"
   * yazan bir makineyi kaydederken aynı rolü bir kez daha elle seçtirmek,
   * zaten verilmiş bir bilgiyi ikinci kez sormak demekti (kullanıcı
   * söyledi). Seçili gelen rol bir çip olarak duruyor, yani kaldırılabilir:
   * öneri, dayatma değil.
   *
   * Yalnızca postern'de VAR OLAN roller seçiliyor; henüz olmayan bir rol
   * adı seçim kutusunda yok, onu aşağıdaki onay kutusu açıyor.
   */
  const [chosenRoles, setChosenRoles] = useState<string[]>([]);
  const [tagRoles, setTagRoles] = useState(true);
  const [preselected, setPreselected] = useState(false);
  // Sonda hep boş bir satır duruyor; dolduruldukça yenisi açılıyor.
  const [labelRows, setLabelRows] = useState<LabelRow[]>([{ key: "", value: "" }]);
  const [results, setResults] = useState<Registered[] | null>(null);
  const [error, setError] = useState("");

  const parsed = labelsOf(labelRows);
  const tagRoleNames = Array.from(new Set(machines.map((m) => m.group).filter((r): r is string => !!r)));
  const missingRoles = tagRoleNames.filter((r) => !groups.items.some((x) => x.name === r));

  // Roller yüklendiğinde bir KEZ: etiketin söylediği ve postern'de var
  // olan roller seçili gelsin. Sonraki seçimler kullanıcının.
  useEffect(() => {
    if (preselected || groups.items.length === 0) return;
    setPreselected(true);
    const known = tagRoleNames.filter((r) => groups.items.some((x) => x.name === r));
    if (known.length > 0) setChosenRoles(known);
  }, [preselected, groups.items, tagRoleNames]);

  const register = async () => {
    setError("");
    try {
      const r = await api.registerDiscovered({
        machines: machines.map((m) => ({ source_id: m.source_id, ref: m.ref })),
        groups: chosenRoles,
        tag_roles: tagRoles,
        labels: parsed.labels,
      });
      setResults(r.results);
    } catch (e: unknown) {
      setError(toMessage(e));
    }
    await onDone();
  };

  if (results) {
    return (
      <>
        <ul className="host-outcomes">
          {results.map((r) => (
            <li key={`${r.source_id}/${r.ref}`}>
              <h4>{r.name || r.ref}</h4>
              {r.error ? (
                <ErrorLine msg={r.error} />
              ) : (
                <p className="small">
                  registered as <code>{r.target}</code>
                  {r.groups?.length ? `, granted to ${r.groups.join(", ")}` : ", granted to no group"}
                  {r.created_roles?.length ? ` (created ${r.created_roles.join(", ")})` : ""}
                </p>
              )}
            </li>
          ))}
        </ul>
        <ErrorLine msg={error} />
        <div className="page-actions">
          <ActionButton onClick={onClose}>Done</ActionButton>
        </div>
      </>
    );
  }

  return (
    <>
      <p className="muted small">Step {step + 1} of 3</p>
      {step === 0 && (
        <>
          <div className="field-row">
            <MultiSelect
              label="Groups"
              placeholder="Search groups…"
              options={groups.items.map((r) => ({ value: r.name, label: r.name }))}
              value={chosenRoles}
              onChange={setChosenRoles}
              note="Every registered machine is granted to these groups. Access comes from the people assigned to a group, which this does not change."
            />
            <ErrorLine msg={groups.error} />
          </div>
          <label className="check">
            <input type="checkbox" checked={tagRoles} onChange={(e) => setTagRoles(e.target.checked)} />
            Also grant each machine to the group its tag names
            {tagRoleNames.length
              ? ` (${tagRoleNames.join(", ")}${missingRoles.length ? `; ${missingRoles.join(", ")} would be created` : ""})`
              : " (none of the selected machines carries a group tag)"}
          </label>
        </>
      )}
      {step === 1 && (
        <>
          <LabelTable rows={labelRows} onChange={setLabelRows} />
          <ErrorLine msg={parsed.error} />
          <p className="muted small">
            {Object.keys(parsed.labels).length === 0
              ? "Labels are optional: leave the rows empty to attach none."
              : `${Object.keys(parsed.labels).length} label${
                  Object.keys(parsed.labels).length === 1 ? "" : "s"
                } will be attached to each machine.`}
          </p>
        </>
      )}
      {step === 2 && (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Machine</th>
                  <th>Address</th>
                  <th>Tags</th>
                  <th>Host key</th>
                  <th>Groups</th>
                </tr>
              </thead>
              <tbody>
                {machines.map((m) => (
                  <tr key={keyOf(m)}>
                    <td className="wrap">{m.name}</td>
                    <td className="wrap">{m.host || m.name}</td>
                    {/* ⚠️ PLATFORMUN ETİKETLERİ ÖZETTE. Rolün nereden geldiği
                        ("role_web" etiketi) yalnızca listede görünüyordu; onay
                        ekranında görünmeyince kaydeden kişi neye dayanarak rol
                        verildiğini göremiyordu. */}
                    <td className="wrap">
                      {m.tags.length ? (
                        <span className="chips">
                          {m.tags.map((t) => (
                            <span key={t} className="chip">
                              {t}
                            </span>
                          ))}
                        </span>
                      ) : (
                        <span className="muted">none</span>
                      )}
                    </td>
                    <td className="wrap">
                      <code className="small">{m.fingerprint}</code>
                    </td>
                    <td className="wrap">
                      {/* ⚠️ TEKİLLEŞTİRİLİYOR: seçilen rol ile etiketin söylediği
                          rol aynı olduğunda özet "developer, developer" yazıyordu.
                          Sunucu zaten tek kez veriyor; yanlış olan ekrandı. */}
                      {Array.from(
                        new Set([...chosenRoles, ...(tagRoles && m.group ? [m.group] : [])]),
                      ).join(", ") || (
                        <span className="muted">none</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="muted small">
            {Object.keys(parsed.labels).length === 0 ? (
              "No labels will be attached."
            ) : (
              <>
                Labels attached to each machine:{" "}
                <span className="chips">
                  {Object.entries(parsed.labels).map(([k, v]) => (
                    <span key={k} className="chip">
                      {k}={v}
                    </span>
                  ))}
                </span>
              </>
            )}
          </p>
          <p className="muted small">
            The host keys above are pinned as shown; postern does not re-read them now.
          </p>
        </>
      )}
      <ErrorLine msg={error} />
      <div className="page-actions">
        {step > 0 && <ActionButton onClick={() => setStep(step - 1)}>Back</ActionButton>}
        {step < 2 && (
          <ActionButton
            variant="primary"
            onClick={() => setStep(step + 1)}
            disabled={step === 1 && parsed.error !== ""}
          >
            Next
          </ActionButton>
        )}
        {step === 2 && (
          <ActionButton variant="primary" onClick={register}>
            Register {machines.length} machine(s)
          </ActionButton>
        )}
      </div>
    </>
  );
}
