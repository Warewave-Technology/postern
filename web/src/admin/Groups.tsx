import { useState } from "react";
import { api, Group, Target, toMessage } from "../api";
import { ErrorLine, ListState, WarnLine, useList } from "./common";
import DataTable, { Column } from "./DataTable";
import Modal from "./Modal";
import GroupDetail from "./GroupDetail";

/**
 * Groups — rollerin listesi.
 *
 * ⚠️ LİSTE SAYIYOR, SAYFA GÖSTERİYOR. Önceki hâlde her satır rolün bütün
 * hedeflerini rozet rozet çiziyor, ayrıca bir hedef seçme kutusu, bir
 * "Paths" ve bir "Sudo" düğmesi taşıyordu. Yüz hedefli bir rolde o satır
 * tabloyu okunmaz yapıyor (kullanıcı söyledi): "hangi rol nereye eriyor"
 * sorusuna bakan tablo, tek bir rolün içeriğini göstermeye çalışırken
 * bozuluyor. Ad artık detay sayfasına götürüyor — hedef listesindeki
 * desenin aynısı.
 *
 * ⚠️ SAYILAR ROLÜN NE VERDİĞİNİ SÖYLÜYOR. Yalnızca ad gösteren bir liste,
 * hangi rolün ağır olduğunu gizler: hedef sayısı ve sudo komutu sayısı,
 * birini bir group eklemeden önce bakılacak iki sayı.
 */
export default function Groups() {
  const { items, error, denied, loading, failed, refresh, setError } =
    useList<Group>(api.groups);
  // Hedefler ayrıca çekiliyor: detay sayfasındaki kutu yalnızca gerçekten
  // kayıtlı hedefleri sunsun, adı elle yazdırmak "target not found" veren
  // bir grant demekti.
  const targets = useList<Target>(api.targets);

  const [name, setName] = useState("");
  // Ekleme formu MODALDA: sayfanın işi listeyi göstermek, ekleme ara sıra
  // yapılan bir eylem ve listenin altında kalıcı durması hem listeyi aşağı
  // itiyor hem sayfanın ne için olduğunu bulanıklaştırıyordu.
  const [adding, setAdding] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  // ⚠️ BAŞARIYI DÖNDÜRÜYOR. Hata durumunda modal AÇIK kalmalı: kapanan bir
  // modal, arkadaki hata satırını görmeyen kullanıcıya işlemin tuttuğunu
  // düşündürür ve aynı adı bir daha yazdırır.
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

  const columns: Column<Group>[] = [
    {
      key: "name",
      header: "Name",
      value: (r) => r.name,
      render: (r) => (
        <button className="link-cell" onClick={() => setSelected(r.name)}>
          {r.name}
        </button>
      ),
    },
    {
      key: "targets",
      header: "Targets",
      // Arama hedef adlarını da kapsıyor: "hangi rol db-01'e eriyor"
      // sorusunun cevabı tek kutuya yazılabilsin — adlar satırda
      // görünmese de.
      value: (r) => `${r.targets.length} ${r.targets.join(" ")}`,
      render: (r) =>
        r.targets.length === 0 ? (
          <span className="muted">no targets</span>
        ) : (
          <>
            {r.targets.length} host{r.targets.length === 1 ? "" : "s"}
          </>
        ),
    },
    {
      /*
       * ⚠️ SUDO SÜTUNU SAYIYOR, YAZMIYOR. Rol artık erişimin yanında
       * yetki de veriyor ve bunu listede hiç göstermemek, birini group
       * eklerken ne verdiğini görmemek demek. Komutların kendisi
       * sayfada: iki yüz komutu bir hücreye sığdırmak da aynı tabloyu
       * bozardı.
       */
      key: "sudo",
      header: "Sudo",
      value: (r) => (r.sudo ? r.sudo.commands.map((c) => `${c.command} ${c.run_as}`).join(" ") : ""),
      render: (r) =>
        r.sudo ? (
          <span className="chips">
            <span className="chip">
              {r.sudo.commands.length} command
              {r.sudo.commands.length === 1 ? "" : "s"}
            </span>
            {r.sudo.acknowledged && (
              <span className="chip warn">acknowledged root escape</span>
            )}
          </span>
        ) : (
          <span className="muted">no rule</span>
        ),
    },
  ];

  if (selected) {
    const group = items.find((r) => r.name === selected);
    if (group) {
      return (
        <GroupDetail
          group={group}
          targets={targets.items}
          onBack={() => setSelected(null)}
          onChanged={refresh}
        />
      );
    }
    /*
     * Rol silinmiş ya da liste tazelenirken kaybolmuş olabilir. Burada
     * setSelected ÇAĞIRMIYORUZ: render sırasında durum değiştirmek
     * React'te yeniden render tetikler. Seçim duruyor, ekranda liste
     * çiziliyor; sayfaya dönmenin yolu yeni bir tıklama.
     */
  }

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Groups</h2>
          <p className="page-sub">
            Access is granted only through a group: a group holds targets, and a
            user holds groups. Open one to see what it reaches and what it may
            run there.
          </p>
        </div>
        <button className="btn-primary" onClick={() => setAdding(true)}>
          New group
        </button>
      </div>
      <ErrorLine msg={error} />

      {/* Hedef listesi düşerse detaydaki seçim kutusu boş kalır; sebebini
          söylemezsek operatör panelin bozuk olduğunu sanar. */}
      <WarnLine
        msg={
          targets.error &&
          `Targets could not be loaded (${targets.error}) — you can still open a group, but nothing can be granted until that list comes back.`
        }
      />
      {!targets.loading && !targets.error && targets.items.length === 0 && (
        <WarnLine msg="No targets are registered yet, so every group here grants nothing." />
      )}

      <ListState
        loading={loading}
        denied={denied}
        failed={failed}
        empty={items.length === 0}
        emptyText="No groups yet — access is granted only through a group, so nobody can reach a target until one exists."
      />

      {items.length > 0 && (
        <DataTable
          rows={items}
          columns={columns}
          rowKey={(r) => r.name}
          initialSort={{ key: "name", dir: "asc" }}
          noun="group"
          searchLabel="search groups by name, granted target or sudo command"
          searchPlaceholder="Search groups…"
        />
      )}

      <Modal
        open={adding}
        onClose={() => setAdding(false)}
        title="New group"
        description="A group starts empty and grants nothing until you open it and give it a target."
      >
        <div className="field-row">
          <label>
            Name
            {/* trim: baştaki/sondaki boşluk gözle görünmüyor ama eşleme
                tarafında adlar birebir karşılaştırılıyor — "ops " rolü
                "ops" mapping'ine hiç bağlanmazdı. */}
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <button
            className="btn-primary"
            onClick={() => create().then((ok) => ok && setAdding(false))}
            disabled={!name.trim()}
          >
            Create group
          </button>
        </div>
      </Modal>
    </section>
  );
}
