import { useRef, useState } from "react";
import { api, Mapping, Group, UnmappedGroup, toMessage } from "../api";
import { ActionButton, ErrorLine, ListState, OkLine, Timestamp, useList } from "./common";
import DataTable, { Column } from "./DataTable";
import Modal from "./Modal";

// IdP grubu → postern rolü eşlemesi.
//
// Eşlenmemiş gruplar bölümü bilerek AYNI sayfada: yöneticinin "IdP bana
// ne gönderiyor" sorusuyla "hangisini eşleyeyim" kararı yan yana
// durmalı. Warpgate'te bu bilgi hiçbir yerde olmadığı için insanlar
// claim'lerin geldiğini görüp neden rol oluşmadığını anlayamıyor.
export default function Mappings() {
  const { items, error, denied, loading, failed, refresh, setError } =
    useList<Mapping>(api.mappings);
  const unmapped = useList<UnmappedGroup>(api.unmappedGroups);
  const groups = useList<Group>(api.groups);

  const [directoryGroup, setDirectoryGroup] = useState("");
  const [group, setGroup] = useState("");
  // Ekleme formu MODALDA: sayfanın işi listeyi göstermek.
  const [adding, setAdding] = useState(false);
  // Hem ekleme hem kaldırma GECİKMELİ etki ediyor: satırın tablodan
  // gidip gelmesi işin bittiğini söylüyor ama ne zaman geçerli olacağını
  // söylemiyor. O cümle olmadan yönetici "kaldırdım, hâlâ girebiliyor"
  // diye ürünü bozuk sanıyor.
  const [notice, setNotice] = useState("");

  // Eşlenmemiş satırdaki düğme grubu yukarıdaki forma yazıyor; odağı da
  // taşımak gerekiyor, yoksa tıklayan kişi ekranın altında kalıyor ve
  // hiçbir şey olmamış gibi görünüyor.
  const groupRef = useRef<HTMLSelectElement>(null);

  const add = () => {
    const dg = directoryGroup.trim();
    setNotice("");
    return (
      api
        .addMapping(dg, group)
        .then(() => {
          // postern grubu seçili KALIYOR: aynı gruba birden çok dizin
          // grubu eşlemek olağan iş.
          setDirectoryGroup("");
          setNotice(
            `${dg} → ${group} mapped. Members get the group at their next sign-in.`,
          );
          refresh();
          unmapped.refresh();
          return true;
        })
        // ⚠️ BAŞARIYI DÖNDÜRÜYOR: hatada modal AÇIK kalmalı, yoksa
        // kapanan modal işlemin tuttuğunu düşündürür.
        .catch((e: unknown) => {
          setError(toMessage(e));
          return false;
        })
    );
  };

  const remove = (m: Mapping) => {
    setNotice("");
    return api
      .removeMapping(m.directory_group, m.group)
      .then(() => {
        setNotice(
          `${m.directory_group} → ${m.group} removed. Anyone who already holds ${m.group} keeps it until their next sign-in.`,
        );
        refresh();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const mapThisGroup = (name: string) => {
    setGroup(name);
    groupRef.current?.focus();
  };

  // Sunucu teşhis tablosundan satır SİLMİYOR: bir grubu eşledikten sonra
  // da "eşlenmemiş" listesinde duruyor ve yönetici eşlemenin tutmadığını
  // sanıyor. Karşılaştırma küçük harfle, çünkü sunucudaki eşleşme de harf
  // duyarsız (store.ciEq) — "Developers" eşliyken "developers" satırı
  // kalmamalı.
  const mapped = new Set(items.map((m) => m.group.toLowerCase()));
  const pending = unmapped.items.filter(
    (g) => !mapped.has(g.name.toLowerCase()),
  );

  const mappingCols: Column<Mapping>[] = [
    {
      key: "directory_group",
      /*
       * ⚠️ "Directory group", "IdP group" DEĞİL ve "Group" hiç değil.
       * Bu ekranda üç ayrı grup kavramı var; sütun adı hangisinden
       * bahsettiğini söylemezse eşleme okunmaz olur.
       */
      header: "Directory group",
      value: (m) => m.directory_group,
      render: (m) => <code>{m.directory_group}</code>,
    },
    {
      key: "group",
      header: "Group",
      value: (m) => m.group,
      render: (m) => <code>{m.group}</code>,
    },
    { key: "by", header: "Mapped by", value: (m) => m.created_by },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (m) => (
        <ActionButton
          variant="danger"
          confirm={`Remove the mapping ${m.group} → ${m.group}? Anyone who already holds ${m.group} keeps it until their next sign-in.`}
          label={`remove mapping ${m.group} to ${m.group}`}
          onClick={() => remove(m)}
        >
          Remove
        </ActionButton>
      ),
    },
  ];

  const pendingCols: Column<UnmappedGroup>[] = [
    {
      key: "name",
      header: "Group",
      value: (g) => g.name,
      render: (g) => <code>{g.name}</code>,
    },
    // Sıralama SAYISAL: "12" ile "9" metin olarak sıralandığında 12 önce
    // gelir ve "en çok görülen grup" yanlış çıkar.
    {
      key: "seen",
      header: "Times seen",
      className: "num",
      value: (g) => g.seen_count,
    },
    {
      key: "last",
      header: "Last seen",
      value: (g) => g.last_seen,
      // Ham ISO değil, panelin damgası: aynı an Sessions'ta "Sep 13,
      // 09:58:00", burada "2026-09-13T09:58:00Z" yazıyordu.
      render: (g) => <Timestamp value={g.last_seen} />,
    },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (g) => (
        <button
          onClick={() => mapThisGroup(g.name)}
          aria-label={`map group ${g.name}`}
        >
          Map this group
        </button>
      ),
    },
  ];

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Group mappings</h2>
          <p className="page-sub">
            A directory group becomes a postern group at sign-in. Removing a
            mapping revokes nothing on the spot: existing SSO assignments are
            refreshed on the user&apos;s next login.
          </p>
        </div>
        <button className="btn-primary" onClick={() => setAdding(true)}>
          New mapping
        </button>
      </div>
      <ErrorLine msg={error} />
      <OkLine msg={notice} />

      <ListState
        loading={loading}
        denied={denied}
        failed={failed}
        empty={items.length === 0}
        emptyText="No mappings — nobody can sign in through the IdP yet."
      />
      {items.length > 0 && (
        <DataTable
          rows={items}
          columns={mappingCols}
          rowKey={(m) => `${m.group}/${m.group}`}
          initialSort={{ key: "group", dir: "asc" }}
          noun="mapping"
          searchLabel="search mappings by group or group"
          searchPlaceholder="Search mappings…"
        />
      )}

      <Modal
        open={adding}
        onClose={() => setAdding(false)}
        title="New mapping"
        description="Members of the group get the group at their next sign-in — a mapping never changes anyone's access on the spot."
      >
        <div className="field-row">
          <label>
            Directory group
            <input
              value={group}
              onChange={(e) => setGroup(e.target.value)}
              placeholder="sysadmins"
            />
          </label>
          <label>
            Group
            <select
              ref={groupRef}
              value={group}
              onChange={(e) => setGroup(e.target.value)}
            >
              <option value="">select group…</option>
              {groups.items.map((r) => (
                <option key={r.name} value={r.name}>
                  {r.name}
                </option>
              ))}
            </select>
          </label>
          <ActionButton
            variant="primary"
            onClick={() => add().then((ok) => ok && setAdding(false))}
            disabled={!group.trim() || !group}
          >
            Map group
          </ActionButton>
        </div>
        <ErrorLine msg={groups.error} />
        {/*
        Boş bir rol açılırı sessizce "seçecek bir şey yok" gibi duruyor.
        Sebebi söylenmezse yönetici formu bozuk sanıyor — ve reddedilmiş
        bir istek ile gerçekten rol olmaması AYNI şey değil.
      */}
        {!groups.loading && groups.items.length === 0 && (
          <p className="note">
            {groups.denied
              ? "Groups could not be listed for your account, so this list is empty — that is not the same as there being no groups."
              : "No groups exist yet — create one on the Groups tab before a group can be mapped."}
          </p>
        )}
      </Modal>

      <div className="page-head">
        <h3>Groups seen but not mapped</h3>
        <p className="page-sub">
          These arrived in a login and matched no group, so whoever signed in got
          nothing from them. Mapping one grants access on that user&apos;s next
          sign-in.
        </p>
      </div>
      <ErrorLine msg={unmapped.error} />
      <ListState
        loading={unmapped.loading}
        denied={unmapped.denied}
        // ⚠️ unmapped.failed — BURADA sayfanın üstündeki listenin
        // bayrağı duruyordu. Eşlenmemiş grup sorgusu çökünce bu ekran
        // "Nothing unmapped so far" diyordu: yani "bakamadım" yerine
        // "bakacak bir şey yok". Tam olarak failed'ın kapatmak için
        // eklendiği arıza, onu ekleyen sayfada.
        failed={unmapped.failed}
        empty={pending.length === 0}
        emptyText="Nothing unmapped so far — every group seen in a login matched a group."
      />
      {pending.length > 0 && (
        <DataTable
          rows={pending}
          columns={pendingCols}
          rowKey={(g) => g.name}
          initialSort={{ key: "seen", dir: "desc" }}
          noun="group"
          searchLabel="search unmapped groups"
          searchPlaceholder="Search groups…"
        />
      )}
    </section>
  );
}
