import { useState } from "react";
import { api, Target, toMessage } from "../api";
import { ActionButton, ErrorLine, ListState, OkLine, useList } from "./common";

export default function Targets() {
  const { items, error, denied, loading, refresh, setError } = useList<Target>(api.targets);
  const [ok, setOk] = useState("");
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("22");
  const [hostKey, setHostKey] = useState("");

  // Number("") 0, Number("22x") NaN veriyor ve JSON.stringify NaN'ı null
  // yazıyor: iki durumda da sunucuya port 0 gidiyordu, yani hiçbir yere
  // bağlanamayan bir hedef hatasız kaydediliyordu. Düğme geçerli bir
  // port görmeden açılmıyor.
  const portNum = Number(port);
  const portOk = Number.isInteger(portNum) && portNum > 0 && portNum <= 65535;

  const create = () => {
    setOk("");
    return api
      .createTarget({ name, host, port: portNum, host_key: hostKey.trim() })
      .then(() => {
        setOk(`${name} registered — the fingerprint in the table is what postern will hold it to.`);
        setName("");
        setHost("");
        setPort("22");
        setHostKey("");
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
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Host</th>
                  <th>Port</th>
                  <th>Host key</th>
                  <th className="actions">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((t) => (
                  <tr key={t.name}>
                    <td>{t.name}</td>
                    <td>{t.host}</td>
                    <td>{t.port}</td>
                    <td>
                      <code>{t.fingerprint}</code>
                    </td>
                    <td className="actions">
                      <ActionButton
                        variant="danger"
                        onClick={() => remove(t)}
                        confirm={`Delete target ${t.name} (${t.host}:${t.port})? Nobody will be able to open a session to it, and its pinned host key is gone with it.`}
                        label={`delete target ${t.name}`}
                      >
                        Delete
                      </ActionButton>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
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

        {/*
          Bu formun asıl güvenlik alanı burası: host key hedefin
          kimliğini ÇİVİLİYOR, yani sonradan başka bir anahtar sunan bir
          makine artık o hedef sayılmıyor. Tahmin edilemez ve elle
          uydurulamaz, makinenin kendisinden okunması gerekir — alanın
          zorunlu olması ve altındaki komutun yazması bu yüzden: boş ya
          da uydurma bir anahtarla kayıt, doğrulanmamış bir hedefi
          doğrulanmış gibi gösterirdi.

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
        <p className="muted small">
          This key pins the target&apos;s identity — postern checks it on every
          connection, so it has to come off the host itself, not from memory:{" "}
          <code>
            ssh-keyscan -p {portOk ? portNum : 22} {host || "<host>"}
          </code>
        </p>

        <ActionButton
          variant="primary"
          onClick={create}
          disabled={!name || !host || !hostKey.trim() || !portOk}
        >
          Register target
        </ActionButton>
      </div>
    </section>
  );
}
