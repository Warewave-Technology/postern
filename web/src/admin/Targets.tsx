import { useState } from "react";
import { ScannedKey, api, Target, toMessage } from "../api";
import { ActionButton, ErrorLine, ListState, OkLine, useList } from "./common";
import DataTable, { Column } from "./DataTable";
import TargetDetail from "./TargetDetail";
import Modal from "./Modal";
import { matches, parse } from "../query";

/**
 * parseLabels, "env=prod, team=data" biçimini çiftlere çevirir.
 *
 * Kayıt formunda tek bir kutu var: üç etiket için üç ayrı satır
 * açtırmak, en sık yapılan işi en yorucu iş yapardı. Ayraç hem virgül
 * hem boşluk — operatörün hangisini yazacağını hatırlamak zorunda
 * kalmaması için.
 */
export function parseLabels(text: string): {
  labels: Record<string, string>;
  bad: string[];
} {
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
  const { items, error, denied, loading, failed, refresh, setError } =
    useList<Target>(api.targets);
  // Seçili hedef: kendi sayfası açılıyor. Tablo satırı adres, parmak
  // izi, etiketler, roller ve gözlemleri birden taşıyamıyor.
  const [selected, setSelected] = useState<string | null>(null);
  // Kayıt formu MODALDA: sayfanın işi listeyi göstermek.
  const [adding, setAdding] = useState(false);

  /*
   * Taranmış anahtar ve onayı.
   *
   * ⚠️ scan DOLUYSA confirmed ŞART. Anahtar yapıştırıldığında operatör
   * onu zaten bir yerden getirmiş oluyor — bilinçli bir eylem. Tarandığında
   * ise makineyi postern seçti ve karşılaştırma yapılmadı: onay kutusu,
   * o karşılaştırmanın yapıldığını söyleyen tek şey. Kutusuz bir "tara ve
   * kaydet" akışı, ağ yolundaki birinin sunduğu anahtarı tek tıkla
   * pinletirdi.
   */
  const [scan, setScan] = useState<ScannedKey | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanErr, setScanErr] = useState("");
  const [confirmed, setConfirmed] = useState(false);

  const doScan = () => {
    setScanErr("");
    setScanning(true);
    return api
      .scanHostKey(host.trim(), portNum)
      .then((k) => {
        setScan(k);
        setHostKey(k.authorized_key);
        // Her yeni taramada onay SIFIRLANIR: önceki anahtar için
        // verilen onay yenisini kapsamaz.
        setConfirmed(false);
      })
      .catch((e: unknown) => {
        setScan(null);
        setScanErr(toMessage(e));
      })
      .finally(() => setScanning(false));
  };
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
    return (
      api
        .createTarget({
          name,
          host,
          port: portNum,
          host_key: hostKey.trim(),
          labels: parsed.labels,
        })
        .then(() => {
          setOk(
            `${name} registered — the fingerprint in the table is what postern will hold it to.`,
          );
          setName("");
          setHost("");
          setPort("22");
          setHostKey("");
          setLabelText0("");
          return refresh().then(() => true);
        })
        // ⚠️ BAŞARIYI DÖNDÜRÜYOR. Hatada modal AÇIK kalmalı: kapanan bir
        // modal, arkadaki hata satırını görmeyen kullanıcıya kaydın
        // tuttuğunu düşündürür — ve host key gibi elle yapıştırılan bir
        // alanı ikinci kez doldurtmak, o kullanıcıyı panele küstürür.
        .catch((e: unknown) => {
          setError(toMessage(e));
          return false;
        })
    );
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
    {
      key: "name",
      header: "Name",
      value: (t) => t.name,
      // Ad bir BAĞLANTI: satırın tamamını tıklanabilir yapmak, satır
      // içindeki sil/etiket düğmeleriyle çakışırdı.
      render: (t) => (
        <button className="link-cell" onClick={() => setSelected(t.name)}>
          {t.name}
        </button>
      ),
    },
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

  if (selected) {
    return (
      <TargetDetail
        name={selected}
        onBack={() => {
          setSelected(null);
          // Detay sayfasında etiket eklenmiş ya da hedef silinmiş
          // olabilir: listeye eski hâliyle dönmek yanlış bilgi verirdi.
          refresh();
        }}
      />
    );
  }

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Targets</h2>
          <p className="page-sub">
            The hosts postern will open sessions to. Each one is pinned to a
            host key, so a machine that later presents a different key is no
            longer that target.
          </p>
        </div>
        <button className="btn-primary" onClick={() => setAdding(true)}>
          Register target
        </button>
      </div>
      <ErrorLine msg={error} />
      <OkLine msg={ok} />

      <ListState
        loading={loading}
        denied={denied}
        failed={failed}
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
          searchLabel="filter targets by name or label"
          searchPlaceholder="name: web and env: prod"
          // Sorgu dili: alansız alt dize araması "prod" yazan operatörün
          // adında mı etiketinde mi aradığını ayırt edemiyordu.
          match={(t, q) =>
            matches(parse(q), {
              name: t.name,
              labels: t.labels,
              extra: {
                host: t.host,
                port: String(t.port),
                fingerprint: t.fingerprint,
              },
            })
          }
        />
      )}

      <Modal
        open={adding}
        onClose={() => {
          setAdding(false);
          setScan(null);
          setScanErr("");
          setConfirmed(false);
        }}
        title="Register target"
        description="Everything here comes off the machine itself; nothing is guessed."
      >
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
            {parsed.bad.join(", ")} — write each label as <code>key=value</code>
            .
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
        <div className="field-row">
          <ActionButton
            onClick={doScan}
            disabled={!host.trim() || !portOk || scanning}
            label="fetch the host key from this address"
          >
            {scanning ? "Fetching…" : "Fetch host key"}
          </ActionButton>
          <span className="note" style={{ flex: 1, minWidth: "12rem" }}>
            Reads the key the machine offers right now. You still have to
            confirm it.{" "}
            {/* Tarama da sunucuda koşuyor: adresi postern çözüyor ve
                postern'in ağından bağlanıyor. Bunu yazmamak, kendi
                makinesinde ulaşılan bir adı deneyen operatörü
                şaşırtıyordu. */}
            postern connects <b>from the bastion</b>, so the address has to work
            there.
          </span>
        </div>

        <ErrorLine msg={scanErr} />

        {scan && (
          /*
            ⚠️ BU BİR DOĞRULAMA DEĞİL, BİR SORU — ve metin bunu söylüyor.
            İlk SSH bağlantısındaki soruyla aynı: anahtar bu, doğru mu?
            Postern bunu ağdan aldı ve ağdan gelen her şey gibi
            sorgulanabilir; onay kutusu, karşılaştırmanın yapıldığını
            söyleyen tek kayıt.
          */
          <div className="keycheck">
            <p className="keycheck-q">Is this the right key?</p>
            <p className="keycheck-fp">
              <code>{scan.fingerprint}</code>
            </p>
            <p className="note">
              {scan.key_type} · offered by {host}:{portOk ? portNum : "?"} just
              now. postern read this over the network and nothing has verified
              it.
              {scan.key_file && (
                <>
                  {" "}
                  Compare it with the host itself:{" "}
                  <code>ssh-keygen -lf {scan.key_file}</code>
                </>
              )}
            </p>

            {/*
              ⚠️ İKİ ÇAKIŞMA AYRI SESLE. Aynı makinenin başka TÜRDEN
              anahtarı sık ve masum; aynı türde BAŞKA anahtar ise
              alarmdır. İkisini aynı kırmızıyla söylemek, alarmı
              işe yaramaz yapardı.
            */}
            {scan.conflicts_with && scan.conflict_kind === "different-type" && (
              <p className="msg msg-warn" role="status">
                {scan.conflicts_with} is already registered at this address with
                a key of a different type. Probably the same machine — but you
                are about to pin a second, separate identity for it.
              </p>
            )}
            {scan.conflicts_with && scan.conflict_kind !== "different-type" && (
              <p className="msg msg-error" role="alert">
                {scan.conflicts_with} is already registered at this address with
                a <b>different key of the same type</b>. Either the host was
                rebuilt, or this is not the machine you think it is. Do not
                confirm until you know which.
              </p>
            )}

            <label className="keycheck-ok">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
              />
              This matches the fingerprint on the host
            </label>
          </div>
        )}

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
          onChange={(e) => {
            setHostKey(e.target.value);
            // Elle değiştirildiyse artık "taranmış" değil: onay kutusu
            // kalkıyor, çünkü onaylanan parmak izi bu değil.
            if (scan && e.target.value.trim() !== scan.authorized_key)
              setScan(null);
          }}
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
          onClick={() => create().then((ok) => ok && setAdding(false))}
          disabled={
            !name ||
            !host ||
            !hostKey.trim() ||
            !portOk ||
            !labelsOk ||
            // Taranmış anahtar ONAYSIZ kaydedilemez.
            (scan !== null && !confirmed)
          }
        >
          Register target
        </ActionButton>
      </Modal>
    </section>
  );
}
