import { useState } from "react";
import { api, Role, Target, toMessage } from "../api";
import { ActionButton, ErrorLine, ListState, WarnLine, useList } from "./common";

export default function Roles() {
  const { items, error, denied, loading, refresh, setError } = useList<Role>(api.roles);
  // Hedefler ayrıca çekiliyor: adı elle yazdırmak, tek harf yanlışında
  // "target not found" veren bir grant demekti. Kutu yalnızca gerçekten
  // kayıtlı hedefleri sunuyor.
  const targets = useList<Target>(api.targets);

  const [name, setName] = useState("");
  // Seçim SATIR BAŞINA tutuluyor; tek ortak state, bir satırda seçilen
  // hedefi bütün satırlarda seçili gösterirdi.
  const [picked, setPicked] = useState<Record<string, string>>({});

  const create = () =>
    api
      .createRole({ name: name.trim() })
      .then(() => {
        setName("");
        return refresh();
      })
      .catch((e: unknown) => setError(toMessage(e)));

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

  return (
    <section>
      <div className="page-head">
        <h2>Roles</h2>
        <p className="page-sub">
          Access is granted only through a role: a role holds targets, and a
          user holds roles.
        </p>
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
        empty={items.length === 0}
        emptyText="No roles yet — access is granted only through a role, so nobody can reach a target until one exists."
      />

      {items.length > 0 && (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th className="wrap">Targets</th>
                  <th>Grant target</th>
                  <th className="actions">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((r) => {
                  // Verilmiş hedefi tekrar sunmak anlamsız: sunucu onu
                  // sessizce yutuyor (ON CONFLICT DO NOTHING), yani hiçbir
                  // şey değiştirmeyen tıklama başarı gibi görünüyordu.
                  const free = targets.items.filter((t) => !r.targets.includes(t.name));
                  const choice = picked[r.name] ?? "";

                  return (
                    <tr key={r.name}>
                      <td>{r.name}</td>
                      <td className="wrap">
                        {r.targets.length === 0 ? (
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
                        )}
                      </td>
                      <td>
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
                            label={choice ? `grant ${choice} to role ${r.name}` : `grant a target to role ${r.name}`}
                            disabled={!choice}
                          >
                            Grant
                          </ActionButton>
                        </div>
                      </td>
                      <td className="actions">
                        <ActionButton
                          variant="danger"
                          onClick={() => remove(r.name)}
                          confirm={deleteConfirm(r)}
                          label={`delete role ${r.name}`}
                        >
                          Delete
                        </ActionButton>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="panel">
        <h3>Add role</h3>
        <p className="note">
          A new role starts empty and grants nothing until you give it a target
          in the table above.
        </p>
        <div className="field-row">
          <label>
            Name
            {/* trim: baştaki/sondaki boşluk gözle görünmüyor ama eşleme
                tarafında adlar birebir karşılaştırılıyor — "ops " rolü
                "ops" mapping'ine hiç bağlanmazdı. */}
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <ActionButton variant="primary" onClick={create} disabled={!name.trim()}>
            Create role
          </ActionButton>
        </div>
      </div>
    </section>
  );
}
