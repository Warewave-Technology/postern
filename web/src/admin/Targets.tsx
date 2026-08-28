import { useState } from "react";
import { api, Target, toMessage } from "../api";
import { ActionButton, ErrorLine, ListState, OkLine, useList } from "./common";
import DataTable, { Column } from "./DataTable";

/**
 * parseLabels, "env=prod, team=data" biçimini çiftlere çevirir.
 *
 * Kayıt formunda tek bir kutu var: üç etiket için üç ayrı satır
 * açtırmak, en sık yapılan işi en yorucu iş yapardı. Ayraç hem virgül
 * hem boşluk — operatörün hangisini yazacağını hatırlamak zorunda
 * kalmaması için.
 */
export function parseLabels(text: string): { labels: Record<string, string>; bad: string[] } {
  const labels: Record<string, string> = {};
  const bad: string[] = [];
  for (const part of text.split(/[,\s]+/)) {
    if (!part) continue;
    const i = part.indexOf("=");
    // "=" YOKSA hata: sessizce atmak, yazdığı etiketin kaydolduğunu
    // sanan operatör bırakırdı.
    if (i <= 0 || i === part.length - 1) {
      bad.push(part);
      continue;
    }
    labels[part.slice(0, i)] = part.slice(i + 1);
  }
  return { labels, bad };
}

function labelText(t: Target): string {
  return Object.entries(t.labels)
    .map(([k, v]) => `${k}=${v}`)
    .join(" ");
}

export default function Targets() {
  const { items, error, denied, loading, refresh, setError } = useList<Target>(api.targets);
  const [ok, setOk] = useState("");
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("22");
  const [hostKey, setHostKey] = useState("");
  const [labelText0, setLabelText0] = useState("");

  // Satır içi etiket formu: aynı anda tek satır açık. Her satırda iki
  // kutu göstermek tabloyu okunmaz yapardı.
  const [editing, setEditing] = useState<string | null>(null);
  const [lk, setLk] = useState("");
  const [lv, setLv] = useState("");

  // Number("") 0, Number("22x") NaN veriyor ve JSON.stringify NaN'ı null
  // yazıyor: iki durumda da sunucuya port 0 gidiyordu, yani hiçbir yere
  // bağlanamayan bir hedef hatasız kaydediliyordu.
  const portNum = Number(port);
  const portOk = Number.isInteger(portNum) && portNum > 0 && portNum <= 65535;

  const parsed = parseLabels(labelText0);
  const labelsOk = parsed.bad.length === 0;

  const create = () => {
    setOk("");
    return api
      .createTarget({
        name,
        host,
        port: portNum,
        host_key: hostKey.trim(),
        labels: parsed.labels,
      })
      .then(() => {
        setOk(`${name} registered — the fingerprint in the table is what postern will hold it to.`);
        setName("");
        setHost("");
        setPort("22");
        setHostKey("");
        setLabelText0("");
        return refresh();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const remove = (t: Target) => {
    setOk("");
    // ⚠️ toMessage: eskiden e.message doğrudan yazılıyordu ve Error
    // olmayan bir reddediş boş satır çiziyordu — BAŞARISIZ bir silme
    // ekranda başarılı olanla aynı görünüyordu.
    return api
      .deleteTarget(t.name)
      .then(refresh)
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const addLabel = (t: Target) => {
    setOk("");
    return api
      .setTargetLabel(t.name, lk.trim(), lv.trim())
      .then(() => {
        setLk("");
        setLv("");
        return refresh();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const removeLabel = (t: Target, key: string) => {
    setOk("");
    return api
      .removeTargetLabel(t.name, key)
      .then(refresh)
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const columns: Column<Target>[] = [
    { key: "name", header: "Name", value: (t) => t.name },
    {
      key: "address",
      header: "Address",
      value: (t) => `${t.host}:${t.port}`,
      render: (t) => (
        <code>
          {t.host}:{t.port}
        </code>
      ),
    },
    {
      key: "labels",
      header: "Labels",
      className: "wrap",
      // Sıralama etiket METNİNE göre: "hiç etiketi olmayanlar" bir uçta
      // toplansın diye boş dize en başa düşüyor.
      value: labelText,
      render: (t) => {
        const entries = Object.entries(t.labels);
        return (
          <div className="chips">
            {entries.length === 0 && editing !== t.name && (
              <span className="muted">no labels</span>
            )}
            {entries.map(([k, v]) => (
              <span key={k} className="label-chip">
                <span className="k">{k}</span>
                <span className="v">{v}</span>
                <ActionButton
                  onClick={() => removeLabel(t, k)}
                  label={`remove label ${k} from ${t.name}`}
                >
                  ×
                </ActionButton>
              </span>
            ))}
            {editing === t.name ? (
              <span className="cell-form">
                <input
                  aria-label={`new label key for ${t.name}`}
                  placeholder="key"
                  size={8}
                  value={lk}
                  onChange={(e) => setLk(e.target.value)}
                />
                <input
                  aria-label={`new label value for ${t.name}`}
                  placeholder="value"
                  size={8}
                  value={lv}
                  onChange={(e) => setLv(e.target.value)}
                />
                <ActionButton
                  variant="primary"
                  onClick={() => addLabel(t)}
                  disabled={!lk.trim()}
                  label={`add label to ${t.name}`}
                >
                  Add
                </ActionButton>
                <button className="btn-quiet" onClick={() => setEditing(null)}>
                  Done
                </button>
              </span>
            ) : (
              <button
                className="btn-quiet"
                onClick={() => {
                  setEditing(t.name);
                  // Kutuları TEMİZLE: önceki satırın değeri kalırsa
                  // etiket yanlış hedefe iliştirilir.
                  setLk("");
                  setLv("");
                }}
                aria-label={`add a label to ${t.name}`}
              >
                + label
              </button>
            )}
          </div>
        );
      },
    },
    {
      key: "fingerprint",
      header: "Host key",
      value: (t) => t.fingerprint,
      // ⚠️ KISALTILIYOR. Tam parmak izi 50 karakter ve tabloyu ~250px
      // genişletip sağdaki Delete'i yatay kaydırmanın ardına itiyordu —
      // ekranın işini yapmak için önce ekranı kaydırmak gerekiyordu.
      // Tamamı title'da ve arama tam değer üzerinde çalışıyor, yani
      // parmak izini yapıştırıp arayan kişi hedefini buluyor.
      render: (t) => (
        <code title={t.fingerprint}>
          {t.fingerprint.length > 24
            ? `${t.fingerprint.slice(0, 14)}…${t.fingerprint.slice(-6)}`
            : t.fingerprint}
        </code>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (t) => (
        <ActionButton
          variant="danger"
          onClick={() => remove(t)}
          confirm={`Delete target ${t.name} (${t.host}:${t.port})? Nobody will be able to open a session to it, and its pinned host key is gone with it.`}
          label={`delete target ${t.name}`}
        >
          Delete
        </ActionButton>
      ),
    },
  ];

  return (
    <section>
      <div className="page-head">
        <h2>Targets</h2>
        <p className="page-sub">
          The hosts postern will open sessions to. Each one is pinned to a host
          key, so a machine that later presents a different key is no longer
          that target.
        </p>
      </div>
      <ErrorLine msg={error} />
      <OkLine msg={ok} />

      <ListState
        loading={loading}
        denied={denied}
        empty={items.length === 0}
        emptyText="No targets registered — until one is, nobody can open a session through this bastion."
      />

      {items.length > 0 && (
        <DataTable
          rows={items}
          columns={columns}
          rowKey={(t) => t.name}
          initialSort={{ key: "name", dir: "asc" }}
          noun="target"
          searchLabel="search targets by name, address or label"
          searchPlaceholder="Search targets, or a label like env=prod…"
        />
      )}

      <div className="panel">
        <h3>Register target</h3>
        <p className="note">
          Everything here comes off the machine itself; nothing is guessed.
        </p>

        <div className="field-row">
          <label>
            Name
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="prod-db"
            />
          </label>
          <label>
            Host
            <input
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="10.0.0.5"
            />
          </label>
          <label>
            Port
            <input
              value={port}
              onChange={(e) => setPort(e.target.value)}
              inputMode="numeric"
              size={4}
            />
          </label>
        </div>

        <div className="field-row">
          <label style={{ flexBasis: "100%" }}>
            Labels (optional)
            <input
              value={labelText0}
              onChange={(e) => setLabelText0(e.target.value)}
              placeholder="env=prod team=payments"
            />
          </label>
        </div>
        {!labelsOk && (
          <p className="msg msg-warn" role="status">
            {parsed.bad.join(", ")} — write each label as <code>key=value</code>.
          </p>
        )}

        {/*
          Bu formun asıl güvenlik alanı burası: host key hedefin
          kimliğini ÇİVİLİYOR, yani sonradan başka bir anahtar sunan bir
          makine artık o hedef sayılmıyor. Tahmin edilemez ve elle
          uydurulamaz, makinenin kendisinden okunması gerekir.

          Başlık label'ın İÇİNDE değil: inline-flex label textarea'yı
          doğal (20 sütunluk) genişliğine hapsediyor, htmlFor bağı ise
          erişilebilir adı aynı şekilde verip tam genişliği koruyor.
        */}
        <label htmlFor="target-host-key">Host public key</label>
        {/*
          cols YOK: cols={70} telefonda alanı ekrandan taşırıp SAYFAYI
          yatay kaydırtıyordu; stil dosyası textarea'ya zaten width:100%
          veriyor.
        */}
        <textarea
          id="target-host-key"
          rows={2}
          value={hostKey}
          onChange={(e) => setHostKey(e.target.value)}
          placeholder="ssh-ed25519 AAAA…"
        />
        <p className="note">
          This key pins the target&apos;s identity — postern checks it on every
          connection, so it has to come off the host itself, not from memory:{" "}
          <code>
            ssh-keyscan -p {portOk ? portNum : 22} {host || "<host>"}
          </code>
        </p>

        <ActionButton
          variant="primary"
          onClick={create}
          disabled={!name || !host || !hostKey.trim() || !portOk || !labelsOk}
        >
          Register target
        </ActionButton>
      </div>
    </section>
  );
}
