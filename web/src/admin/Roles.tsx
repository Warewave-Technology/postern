import { useState } from "react";
import { api, Role, Target, toMessage } from "../api";
import {
  ActionButton,
  ErrorLine,
  ListState,
  WarnLine,
  useList,
} from "./common";
import DataTable, { Column } from "./DataTable";
import Modal from "./Modal";

export default function Roles() {
  const { items, error, denied, loading, failed, refresh, setError } =
    useList<Role>(api.roles);
  // Hedefler ayrıca çekiliyor: adı elle yazdırmak, tek harf yanlışında
  // "target not found" veren bir grant demekti. Kutu yalnızca gerçekten
  // kayıtlı hedefleri sunuyor.
  const targets = useList<Target>(api.targets);

  const [name, setName] = useState("");
  // Ekleme formu MODALDA: sayfanın işi listeyi göstermek, ekleme ara
  // sıra yapılan bir eylem ve listenin altında kalıcı durması hem
  // listeyi aşağı itiyor hem sayfanın ne için olduğunu bulanıklaştırıyordu.
  const [adding, setAdding] = useState(false);
  // Seçim SATIR BAŞINA tutuluyor; tek ortak state, bir satırda seçilen
  // hedefi bütün satırlarda seçili gösterirdi.
  const [picked, setPicked] = useState<Record<string, string>>({});

  // ⚠️ BAŞARIYI DÖNDÜRÜYOR. Hata durumunda modal AÇIK kalmalı: kapanan
  // bir modal, arkadaki hata satırını görmeyen kullanıcıya işlemin
  // tuttuğunu düşündürür ve aynı adı bir daha yazdırır.
  const create = () =>
    api
      .createRole({ name: name.trim() })
      .then(() => {
        setName("");
        return refresh().then(() => true);
      })
      .catch((e: unknown) => {
        setError(toMessage(e));
        return false;
      });

  const grant = (role: string, target: string) =>
    api
      .grantTarget(role, target)
      .then(() => {
        setPicked((p) => ({ ...p, [role]: "" }));
        return refresh();
      })
      .catch((e: unknown) => setError(toMessage(e)));

  const revoke = (role: string, target: string) =>
    api
      .revokeTarget(role, target)
      .then(refresh)
      .catch((e: unknown) => setError(toMessage(e)));

  const remove = (role: string) =>
    api
      .deleteRole(role)
      .then(refresh)
      .catch((e: unknown) => setError(toMessage(e)));

  // Rol silmek yalnız satırı değil, o rolü taşıyan HERKESİN erişimini
  // kaldırır. Onay metni hangi hedeflerin gittiğini adıyla söylüyor:
  // "are you sure" bu işin ne kadarını geri alınamaz yaptığını gizler.
  const deleteConfirm = (r: Role) =>
    r.targets.length === 0
      ? `Delete the role "${r.name}"? It grants no targets, but every user and group mapping holding it loses it immediately.`
      : `Delete the role "${r.name}"? Everyone holding it immediately loses access to: ${r.targets.join(", ")}.`;

  const columns: Column<Role>[] = [
    { key: "name", header: "Name", value: (r) => r.name },
    {
      key: "targets",
      header: "Targets",
      className: "wrap",
      // Arama hedef adlarını da kapsıyor: "hangi rol db-01'e eriyor"
      // sorusunun cevabı tek kutuya yazılabilsin.
      value: (r) => r.targets.join(" "),
      render: (r) =>
        r.targets.length === 0 ? (
          <span className="muted">no targets</span>
        ) : (
          <span className="chips">
            {r.targets.map((t) => (
              <span key={t} className="chip">
                <code>{t}</code>
                <ActionButton
                  onClick={() => revoke(r.name, t)}
                  confirm={`Revoke "${t}" from the role "${r.name}"? Everyone holding this role loses access to that host.`}
                  label={`revoke ${t} from role ${r.name}`}
                >
                  revoke
                </ActionButton>
              </span>
            ))}
          </span>
        ),
    },
    {
      key: "grant",
      header: "Grant target",
      render: (r) => {
        // Verilmiş hedefi tekrar sunmak anlamsız: sunucu onu sessizce
        // yutuyor (ON CONFLICT DO NOTHING), yani hiçbir şey
        // değiştirmeyen tıklama başarı gibi görünüyordu.
        const free = targets.items.filter((t) => !r.targets.includes(t.name));
        const choice = picked[r.name] ?? "";
        return (
          <div className="cell-form">
            <select
              aria-label={`target to grant to role ${r.name}`}
              value={choice}
              onChange={(e) =>
                setPicked((p) => ({ ...p, [r.name]: e.target.value }))
              }
              disabled={free.length === 0}
            >
              <option value="">
                {targets.items.length === 0
                  ? "no targets registered"
                  : free.length === 0
                    ? "all targets granted"
                    : "choose a target…"}
              </option>
              {free.map((t) => (
                <option key={t.name} value={t.name}>
                  {t.name}
                </option>
              ))}
            </select>
            <ActionButton
              onClick={() => grant(r.name, choice)}
              label={
                choice
                  ? `grant ${choice} to role ${r.name}`
                  : `grant a target to role ${r.name}`
              }
              disabled={!choice}
            >
              Grant
            </ActionButton>
          </div>
        );
      },
    },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (r) => (
        <ActionButton
          variant="danger"
          onClick={() => remove(r.name)}
          confirm={deleteConfirm(r)}
          label={`delete role ${r.name}`}
        >
          Delete
        </ActionButton>
      ),
    },
  ];

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Roles</h2>
          <p className="page-sub">
            Access is granted only through a role: a role holds targets, and a
            user holds roles.
          </p>
        </div>
        <button className="btn-primary" onClick={() => setAdding(true)}>
          New role
        </button>
      </div>
      <ErrorLine msg={error} />

      {/* Hedef listesi düşerse seçim kutusu boş kalır; sebebini
          söylemezsek operatör panelin bozuk olduğunu sanar. */}
      <WarnLine
        msg={
          targets.error &&
          `Targets could not be loaded (${targets.error}) — you can still delete roles, but nothing can be granted until that list comes back.`
        }
      />
      {!targets.loading && !targets.error && targets.items.length === 0 && (
        <WarnLine msg="No targets are registered yet, so every role here grants nothing." />
      )}

      <ListState
        loading={loading}
        denied={denied}
        failed={failed}
        empty={items.length === 0}
        emptyText="No roles yet — access is granted only through a role, so nobody can reach a target until one exists."
      />

      {items.length > 0 && (
        <DataTable
          rows={items}
          columns={columns}
          rowKey={(r) => r.name}
          initialSort={{ key: "name", dir: "asc" }}
          noun="role"
          searchLabel="search roles by name or granted target"
          searchPlaceholder="Search roles…"
        />
      )}

      <Modal
        open={adding}
        onClose={() => setAdding(false)}
        title="New role"
        description="A role starts empty and grants nothing until you give it a target in the table."
      >
        <div className="field-row">
          <label>
            Name
            {/* trim: baştaki/sondaki boşluk gözle görünmüyor ama eşleme
                tarafında adlar birebir karşılaştırılıyor — "ops " rolü
                "ops" mapping'ine hiç bağlanmazdı. */}
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <ActionButton
            variant="primary"
            onClick={() => create().then((ok) => ok && setAdding(false))}
            disabled={!name.trim()}
          >
            Create role
          </ActionButton>
        </div>
      </Modal>
    </section>
  );
}
