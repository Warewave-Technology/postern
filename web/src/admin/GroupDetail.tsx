import { useState } from "react";
import { api, Group, Target, toMessage } from "../api";
import { ActionButton, ErrorLine, OkLine } from "./common";
import DataTable, { Column } from "./DataTable";
import Modal from "./Modal";
import MultiSelect from "./MultiSelect";
import { BackIcon } from "../icons";
import PathRules from "./PathRules";
import GroupSudo from "./GroupSudo";

/**
 * GroupDetail — tek bir rolün sayfası: hedefleri, sudo kuralı, yol kuralları.
 *
 * ⚠️ NİYE AYRI SAYFA. Hepsi rol listesinin satırındaydı: hedefler rozet
 * rozet yan yana, yol kuralları bir modalda, sudo başka bir modalda. Yüz
 * hedefli bir rolde o satır tabloyu okunmaz yapıyor (kullanıcı söyledi) ve
 * "hangi rol nereye eriyor" sorusunu cevaplaması gereken tablo, tek bir
 * rolün içeriğini göstermeye çalışırken bozuluyor. Liste artık sayıyor,
 * sayfa gösteriyor — hedef listesindeki desenin aynısı.
 *
 * ⚠️ VERİ LİSTEDEN GELİYOR, AYRI BİR UÇTAN DEĞİL. Rolün hedefleri ve sudo
 * kuralı zaten /api/admin/groups cevabında var; sayfa için ikinci bir uç
 * açmak, aynı gerçeği iki yerden anlatmak olurdu. Değişiklikten sonra
 * onChanged listeyi tazeliyor ve sayfa tazelenen satırla yeniden çiziliyor.
 */
export default function GroupDetail({
  group,
  targets,
  onBack,
  onChanged,
}: {
  group: Group;
  targets: Target[];
  onBack: () => void;
  onChanged: () => Promise<unknown>;
}) {
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const [granting, setGranting] = useState(false);
  const [picked, setPicked] = useState<string[]>([]);

  /*
   * ⚠️ HEDEFLER BİRER BİRER VERİLİYOR AMA SEÇİM TOPLU. Uç hedef başına
   * tek grant alıyor; biri düşerse kalanı yine veriliyor ve kaçının
   * verildiği söyleniyor. Toplu bir isteği tek bir "başarısız"a indirmek,
   * yarısı verilmiş bir rolü hiç verilmemiş gibi gösterirdi.
   */
  const grant = async () => {
    if (picked.length === 0) return;
    setError("");
    setOk("");
    const failed: string[] = [];
    let done = 0;
    for (const t of picked) {
      try {
        await api.grantTarget(group.name, t);
        done++;
      } catch (e: unknown) {
        failed.push(`${t}: ${toMessage(e)}`);
      }
    }
    setPicked([]);
    await onChanged();
    if (done > 0) {
      setOk(`${done} target${done === 1 ? "" : "s"} granted to ${group.name}.`);
    }
    if (failed.length > 0) {
      setError(failed.join("; "));
      return;
    }
    setGranting(false);
  };

  const revoke = async (target: string) => {
    setError("");
    setOk("");
    try {
      await api.revokeTarget(group.name, target);
      await onChanged();
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  const remove = async () => {
    setError("");
    try {
      await api.deleteRole(group.name);
      onBack();
      await onChanged();
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  // Verilmiş hedefi tekrar sunmak anlamsız: sunucu onu sessizce yutuyor
  // (ON CONFLICT DO NOTHING), yani hiçbir şeyi değiştirmeyen bir tıklama
  // başarı gibi görünüyordu.
  const free = targets.filter((t) => !group.targets.includes(t.name));

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
          confirm={`Revoke "${t.name}" from the group "${group.name}"? Everyone holding this group loses access to that host.`}
          label={`revoke ${t.name} from group ${group.name}`}
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
    group.targets.length === 0
      ? `Delete the group "${group.name}"? It grants no targets, but every user and group mapping holding it loses it immediately.`
      : `Delete the group "${group.name}"? Everyone holding it immediately loses access to ${group.targets.length} host(s): ${group.targets.join(", ")}.`;

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <button className="btn-quiet back-link" onClick={onBack}>
            <BackIcon />
            All groups
          </button>
          <h2>{group.name}</h2>
          <p className="page-sub">
            What this group reaches, what it may run there with sudo, and which
            paths it may touch over SFTP.
          </p>
        </div>
        <ActionButton
          variant="danger"
          onClick={remove}
          confirm={deleteConfirm}
          label={`delete group ${group.name}`}
        >
          Delete group
        </ActionButton>
      </div>

      <ErrorLine msg={error} />
      <OkLine msg={ok} />

      <div className="card">
        <div className="card-head">
          <h3>Targets</h3>
          <p className="muted small">
            The hosts everyone holding this group can open a session to.
          </p>
        </div>
        <div className="card-body">
          <div className="card-toolbar">
            <ActionButton
              variant="primary"
              onClick={() => setGranting(true)}
              disabled={free.length === 0}
            >
              Grant targets
            </ActionButton>
            <span className="muted small">
              {targets.length === 0
                ? "No targets are registered yet."
                : free.length === 0
                  ? "Every registered target is already granted to this group."
                  : `${free.length} target${free.length === 1 ? "" : "s"} not granted yet.`}
            </span>
          </div>

          {group.targets.length === 0 ? (
            <p className="state">
              This group grants nothing yet, so holding it reaches no host.
            </p>
          ) : (
            <DataTable
              rows={group.targets.map((name) => ({ name }))}
              columns={columns}
              rowKey={(t) => t.name}
              initialSort={{ key: "name", dir: "asc" }}
              noun="target"
              searchLabel={`search the targets granted to ${group.name}`}
              searchPlaceholder="Search targets…"
            />
          )}
        </div>
      </div>

      <Modal
        open={granting}
        onClose={() => {
          setGranting(false);
          setPicked([]);
        }}
        title={`Grant targets to "${group.name}"`}
        description="Everyone holding this group can open a session to whatever you add here."
      >
        {/*
          ⚠️ KENDİ ÇOKLU SEÇİMİMİZ, TARAYICININ LİSTESİ DEĞİL. Yüz hedefli
          bir envanterde <select multiple> aranamıyor ve seçilenler
          görünmüyor; MultiSelect arama, etiket ve "hepsini seç" taşıyor
          (geçici erişim sihirbazında ölçüldü).

          ⚠️ VERİLMİŞ HEDEF LİSTEDE YOK: sunucu onu sessizce yutuyor
          (ON CONFLICT DO NOTHING), yani hiçbir şeyi değiştirmeyen bir
          tıklama başarı gibi görünürdü.
        */}
        <MultiSelect
          label="Targets"
          options={free.map((t) => ({
            value: t.name,
            label: t.name,
            hint: `${t.host}:${t.port}`,
          }))}
          value={picked}
          onChange={setPicked}
          placeholder="Search targets…"
          emptyText="Every registered target is already granted to this group."
        />
        <ErrorLine msg={error} />
        <div className="form-actions">
          <ActionButton variant="primary" onClick={grant} disabled={picked.length === 0}>
            Grant {picked.length > 0 ? `${picked.length} target${picked.length === 1 ? "" : "s"}` : "targets"}
          </ActionButton>
        </div>
      </Modal>

      <div className="card">
        <div className="card-head">
          <h3>Sudo</h3>
          <p className="muted small">
            What everyone in this group may run with sudo on the machines it
            reaches. A temporary grant can still add more for one account.
          </p>
        </div>
        <div className="card-body">
          <GroupSudo group={group.name} rule={group.sudo} onChanged={onChanged} />
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h3>SFTP paths</h3>
          <p className="muted small">
            Which paths this group may reach over SFTP. A group with no rules is
            unrestricted, and rules restrict a group rather than a user.
          </p>
        </div>
        <div className="card-body">
          <PathRules group={group.name} />
        </div>
      </div>
    </section>
  );
}
