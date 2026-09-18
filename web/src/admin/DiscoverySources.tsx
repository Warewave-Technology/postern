import { useCallback, useEffect, useState } from "react";
import {
  DiscoveryOverview,
  DiscoveryProbe,
  DiscoverySource,
  DiscoverySourceInput,
  api,
  toMessage,
} from "../api";
import { ActionButton, ErrorLine, ListState, Timestamp } from "./common";
import Modal from "./Modal";

/*
 * DiscoverySources — postern'in makineleri OKUDUĞU yerler.
 *
 * ⚠️ MAKİNELERDEN AYRI BİR EKRAN. İkisi bir sayfada alt alta iki tablo
 * olarak duruyordu ve hangisinin ne olduğu karışıyordu (kullanıcı
 * söyledi). İlişkileri gerçek ama yönleri ters: burası "nereden
 * okuyoruz", öbürü "orada ne bulduk". Aynı ekranda iki tablo, üstteki
 * satıra bakıp alttakinin eylemine basmayı kolaylaştırıyordu — ve bu
 * ekrandaki eylemlerden biri bir kaynağı, bulduğu bütün makinelerle
 * birlikte siliyor.
 *
 * ⚠️ BU EKRAN HİÇBİR ŞEYE ERİŞİM VERMİYOR. Bir kaynak eklemek, makine
 * listesi üretmekten ibaret; o makinelerin hedef olması ayrı bir ekranda
 * ve insan onayıyla oluyor. Sanallaştırma platformunda VM açabilen biri
 * böylece postern'de kimsenin erişebileceği bir makine yaratamıyor.
 */

const SCHEDULES: [number, string][] = [
  [0, "Only when asked"],
  [300, "Every 5 minutes"],
  [900, "Every 15 minutes"],
  [3600, "Every hour"],
  [21600, "Every 6 hours"],
  [86400, "Every day"],
];

export default function DiscoverySources() {
  const [overview, setOverview] = useState<DiscoveryOverview | null>(null);
  const [listError, setListError] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState<DiscoverySource | null | "new">(null);

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

  const sources = overview?.sources ?? [];

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

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Discovery sources</h2>
          <p className="page-sub">
            Hypervisors postern reads on a schedule — a Proxmox cluster or a
            vCenter. Reading one only produces a list; a machine becomes a
            target, and reachable, on the Discovery screen and only when you
            register it there.
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
          The bastion has no secret key, so a source's credentials cannot be
          stored. Set <code>secret_key_file</code> in the configuration and
          restart postern.
        </p>
      )}
      <ErrorLine msg={error} />

      <ListState
        loading={loading}
        denied={false}
        failed={listError !== ""}
        empty={!loading && !listError && sources.length === 0}
        emptyText="No source yet. Add a Proxmox cluster or a vCenter and postern will list its machines on the Discovery screen."
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
                        <span
                          className="badge badge-danger"
                          title="TLS verification is off"
                        >
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
                  <td>
                    {SCHEDULES.find(([v]) => v === s.interval_seconds)?.[1] ??
                      `every ${s.interval_seconds}s`}
                  </td>
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
                    <ActionButton
                      onClick={() => setEditing(s)}
                      label={`edit ${s.name}`}
                    >
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

      <Modal
        open={editing !== null}
        title={
          editing === "new"
            ? "Add a discovery source"
            : `Edit ${editing?.name ?? ""}`
        }
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
    </section>
  );
}

function LastRun({ s }: { s: DiscoverySource }) {
  if (s.running) return <span className="badge badge-info">running</span>;
  const r = s.last_run;
  if (!r) return <span className="muted">never</span>;
  return (
    <>
      <span
        className={
          r.outcome === "ok"
            ? "badge badge-ok"
            : r.outcome === "failed"
              ? "badge badge-danger"
              : "badge badge-info"
        }
      >
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
  const [kind, setKind] = useState<"proxmox" | "vsphere">(
    source?.kind ?? "proxmox",
  );
  const [name, setName] = useState(source?.name ?? "");
  const [url, setUrl] = useState(source?.url ?? "");
  const [username, setUsername] = useState(source?.username ?? "");
  const [secret, setSecret] = useState("");
  const [tagKey, setTagKey] = useState(source?.tag_key ?? "group");
  const [namePattern, setNamePattern] = useState(source?.name_pattern ?? "");
  const [port, setPort] = useState(String(source?.port ?? 22));
  const [node, setNode] = useState(source?.node ?? "");
  const [interval, setIntervalSeconds] = useState(
    source?.interval_seconds ?? 3600,
  );
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
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="lab cluster"
            />
          </label>
          <label>
            Address
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={
                proxmox ? "https://pve.example:8006" : "https://vcenter.example"
              }
            />
          </label>
        </div>
      </div>

      <div
        className="form-section"
        role="group"
        aria-labelledby="src-credentials"
      >
        <h4 id="src-credentials">How postern signs in</h4>
        <div className="form-grid cols-2">
          <label>
            {proxmox ? "API token id" : "vCenter user"}
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={
                proxmox ? "postern@pve!discovery" : "postern@vsphere.local"
              }
            />
          </label>
          <label>
            {proxmox ? "API token secret" : "Password"}
            <input
              type="password"
              autoComplete="off"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder={
                source?.secret_set ? "unchanged unless you type a new one" : ""
              }
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
            <input
              type="checkbox"
              checked={insecure}
              onChange={(e) => setInsecure(e.target.checked)}
            />
            Skip TLS verification. Anyone between postern and {platform} can
            then decide which machines appear here and with which tags. Paste
            the CA certificate instead.
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
              <input
                value={node}
                onChange={(e) => setNode(e.target.value)}
                placeholder="all nodes"
              />
            </label>
          )}
          <label>
            SSH port
            <input
              value={port}
              inputMode="numeric"
              onChange={(e) => setPort(e.target.value)}
            />
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
            <select
              value={interval}
              onChange={(e) => setIntervalSeconds(Number(e.target.value))}
            >
              {SCHEDULES.filter(([v]) => v === 0 || v >= minInterval).map(
                ([v, label]) => (
                  <option key={v} value={v}>
                    {label}
                  </option>
                ),
              )}
            </select>
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            Enabled — a disabled source keeps its machines but is not run on
            schedule
          </label>
        </div>
      </div>

      {probe && (
        <ProbeResult
          probe={probe}
          platform={platform}
          tagKey={key}
          pattern={namePattern.trim()}
        />
      )}
      <ErrorLine msg={probeError} />
      <ErrorLine msg={error} />
      <div className="form-actions">
        <ActionButton onClick={test} disabled={!url.trim()}>
          Test connection
        </ActionButton>
        <span className="muted small">
          Signs in with the values above and counts what {platform} reports.
          Nothing is saved.
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
      Reached {platform}: {probe.machines} machine(s), {probe.running} running,{" "}
      {probe.with_address} with an address
      {pattern ? `, ${probe.matching} matching "${pattern}"` : ""}.{" "}
      {probe.tagged} carry a "{tagKey}" tag
      {probe.groups.length ? ` (groups: ${probe.groups.join(", ")})` : ""}.
      {untagged && probe.tags.length > 0
        ? ` Not one machine carries that key — the tags actually seen were ${probe.tags.join(", ")}.`
        : untagged
          ? " These machines carry no tags at all."
          : ""}
    </p>
  );
}
