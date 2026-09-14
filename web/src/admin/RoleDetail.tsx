import { useState } from "react";
import { api, Role, Target, toMessage } from "../api";
import { ActionButton, ErrorLine, OkLine } from "./common";
import DataTable, { Column } from "./DataTable";
import { BackIcon } from "../icons";
import PathRules from "./PathRules";
import RoleSudo from "./RoleSudo";

/**
 * RoleDetail — tek bir rolün sayfası: hedefleri, sudo kuralı, yol kuralları.
 *
 * ⚠️ NİYE AYRI SAYFA. Hepsi rol listesinin satırındaydı: hedefler rozet
 * rozet yan yana, yol kuralları bir modalda, sudo başka bir modalda. Yüz
 * hedefli bir rolde o satır tabloyu okunmaz yapıyor (kullanıcı söyledi) ve
 * "hangi rol nereye eriyor" sorusunu cevaplaması gereken tablo, tek bir
 * rolün içeriğini göstermeye çalışırken bozuluyor. Liste artık sayıyor,
 * sayfa gösteriyor — hedef listesindeki desenin aynısı.
 *
 * ⚠️ VERİ LİSTEDEN GELİYOR, AYRI BİR UÇTAN DEĞİL. Rolün hedefleri ve sudo
 * kuralı zaten /api/admin/roles cevabında var; sayfa için ikinci bir uç
 * açmak, aynı gerçeği iki yerden anlatmak olurdu. Değişiklikten sonra
 * onChanged listeyi tazeliyor ve sayfa tazelenen satırla yeniden çiziliyor.
 */
export default function RoleDetail({
  role,
  targets,
  onBack,
  onChanged,
}: {
  role: Role;
  targets: Target[];
  onBack: () => void;
  onChanged: () => Promise<unknown>;
}) {
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const [picked, setPicked] = useState("");

  const grant = async () => {
    if (!picked) return;
    setError("");
    setOk("");
    try {
      await api.grantTarget(role.name, picked);
      setPicked("");
      setOk(`${picked} granted to ${role.name}.`);
      await onChanged();
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  const revoke = async (target: string) => {
    setError("");
    setOk("");
    try {
      await api.revokeTarget(role.name, target);
      await onChanged();
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  const remove = async () => {
    setError("");
    try {
      await api.deleteRole(role.name);
      onBack();
      await onChanged();
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  // Verilmiş hedefi tekrar sunmak anlamsız: sunucu onu sessizce yutuyor
  // (ON CONFLICT DO NOTHING), yani hiçbir şeyi değiştirmeyen bir tıklama
  // başarı gibi görünüyordu.
  const free = targets.filter((t) => !role.targets.includes(t.name));

  const columns: Column<{ name: string }>[] = [
    { key: "name", header: "Target", value: (t) => t.name, className: "wrap" },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (t) => (
        <ActionButton
          variant="danger"
          onClick={() => revoke(t.name)}
          confirm={`Revoke "${t.name}" from the role "${role.name}"? Everyone holding this role loses access to that host.`}
          label={`revoke ${t.name} from role ${role.name}`}
        >
          Revoke
        </ActionButton>
      ),
    },
  ];

  /*
   * ⚠️ SİLME ONAYI HANGİ HEDEFLERİN GİTTİĞİNİ SAYIYOR. "Emin misin" bu
   * işin ne kadarını geri alınamaz yaptığını gizler; rolü taşıyan herkes
   * o hedeflere erişimini anında kaybediyor.
   */
  const deleteConfirm =
    role.targets.length === 0
      ? `Delete the role "${role.name}"? It grants no targets, but every user and group mapping holding it loses it immediately.`
      : `Delete the role "${role.name}"? Everyone holding it immediately loses access to ${role.targets.length} host(s): ${role.targets.join(", ")}.`;

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <button className="btn-quiet back-link" onClick={onBack}>
            <BackIcon />
            All roles
          </button>
          <h2>{role.name}</h2>
          <p className="page-sub">
            What this role reaches, what it may run there with sudo, and which
            paths it may touch over SFTP.
          </p>
        </div>
        <ActionButton
          variant="danger"
          onClick={remove}
          confirm={deleteConfirm}
          label={`delete role ${role.name}`}
        >
          Delete role
        </ActionButton>
      </div>

      <ErrorLine msg={error} />
      <OkLine msg={ok} />

      <div className="card">
        <div className="card-head">
          <h3>Targets</h3>
          <p className="muted small">
            The hosts everyone holding this role can open a session to.
          </p>
        </div>
        <div className="card-body">
          <div className="cell-form">
            <label>
              Grant a target
              <select
                aria-label={`target to grant to role ${role.name}`}
                value={picked}
                onChange={(e) => setPicked(e.target.value)}
                disabled={free.length === 0}
              >
                <option value="">
                  {targets.length === 0
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
            </label>
            <ActionButton variant="primary" onClick={grant} disabled={!picked}>
              Grant
            </ActionButton>
          </div>

          {role.targets.length === 0 ? (
            <p className="state">
              This role grants nothing yet, so holding it reaches no host.
            </p>
          ) : (
            <DataTable
              rows={role.targets.map((name) => ({ name }))}
              columns={columns}
              rowKey={(t) => t.name}
              initialSort={{ key: "name", dir: "asc" }}
              noun="target"
              searchLabel={`search the targets granted to ${role.name}`}
              searchPlaceholder="Search targets…"
            />
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h3>Sudo</h3>
          <p className="muted small">
            What everyone in this role may run with sudo on the machines it
            reaches. A temporary grant can still add more for one account.
          </p>
        </div>
        <div className="card-body">
          <RoleSudo role={role.name} rule={role.sudo} onChanged={onChanged} />
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h3>SFTP paths</h3>
          <p className="muted small">
            Which paths this role may reach over SFTP. A role with no rules is
            unrestricted, and rules restrict a role rather than a user.
          </p>
        </div>
        <div className="card-body">
          <PathRules role={role.name} />
        </div>
      </div>
    </section>
  );
}
