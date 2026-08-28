import { useEffect, useRef, useState } from "react";
import { api, Role, User, toMessage } from "../api";
import { ActionButton, ErrorLine, ListState, OkLine, WarnLine, useList } from "./common";
import DataTable, { Column } from "./DataTable";
import Modal from "./Modal";

// Kullanıcılar.
//
// Rol atama ve anahtar yönetimi bilerek BU sayfada: rolü olmayan bir
// kullanıcı hiçbir hedefe ulaşamaz, anahtarı olmayan hiç bağlanamaz.
// Yalnızca kullanıcı oluşturabilen bir panel, yöneticiyi işi bitirmek
// için hosttaki CLI'a geri gönderiyordu — o hâlde panelin varlığı
// kullanıcıya yalnızca yarım bir yol gösteriyor demekti.
export default function Users() {
  const { items, error, denied, loading, refresh, setError } = useList<User>(api.users);
  // Roller ayrıca çekiliyor: adı elle yazdırmak, tek harf yanlışında
  // "role not found" veren bir atama demekti.
  const roles = useList<Role>(api.roles);

  const [name, setName] = useState("");
  const [osUser, setOsUser] = useState("");
  const [email, setEmail] = useState("");
  // Ekleme formu MODALDA: sayfanın işi listeyi göstermek.
  const [adding, setAdding] = useState(false);
  // Seçim SATIR BAŞINA tutuluyor; tek ortak state, bir satırda seçilen
  // rolü bütün satırlarda seçili gösterir ve yanlış kullanıcıya
  // yetki verdirirdi.
  const [picked, setPicked] = useState<Record<string, string>>({});

  // Anahtar paneli aynı anda tek kullanıcı için açık: iki panel açıkken
  // yapıştırılan anahtarın hangisine gittiği yalnızca tahmin edilirdi.
  const [keysFor, setKeysFor] = useState<string | null>(null);
  const [keyText, setKeyText] = useState("");
  const keyBox = useRef<HTMLTextAreaElement>(null);
  // Anahtar işlemleri tabloda yalnızca bir SAYIYI değiştiriyor: 3'ün 4
  // olması "eklendi" demek için fazla sessiz, üstelik aynı anahtarı
  // ikinci kez eklemek sayıyı hiç oynatmıyor.
  const [notice, setNotice] = useState("");

  const fail = (e: unknown) => {
    setNotice("");
    setError(toMessage(e));
  };

  // ⚠️ BAŞARIYI DÖNDÜRÜYOR. Hata durumunda modal AÇIK kalmalı: kapanan
  // bir modal, arkadaki hata satırını görmeyen kullanıcıya işlemin
  // tuttuğunu düşündürür ve aynı adı bir daha yazdırır.
  const create = () =>
    api
      .createUser({ name: name.trim(), os_user: osUser.trim(), email: email.trim() || undefined })
      .then(() => {
        setName("");
        setOsUser("");
        setEmail("");
        setNotice(`${name.trim()} created — give it a role and a key in the table, or it reaches nothing.`);
        return refresh().then(() => true);
      })
      .catch((e: unknown) => {
        fail(e);
        return false;
      });

  const assign = (user: string, role: string) =>
    api
      .assignRole(user, role)
      .then(() => {
        setPicked((p) => ({ ...p, [user]: "" }));
        setNotice("");
        return refresh();
      })
      .catch(fail);

  const revoke = (user: string, role: string) =>
    api
      .revokeRole(user, role)
      .then(() => {
        setNotice("");
        return refresh();
      })
      .catch(fail);

  const remove = (user: string) =>
    api
      .deleteUser(user)
      .then(() => {
        setNotice("");
        return refresh();
      })
      .catch(fail);

  const addKey = (user: string) =>
    api
      .addKey(user, keyText.trim())
      .then(() => {
        setKeyText("");
        setNotice(`Key added to ${user}.`);
        return refresh();
      })
      .catch(fail);

  const removeKey = (user: string) =>
    api
      .removeKey(user, keyText.trim())
      .then(() => {
        setKeyText("");
        setNotice(`Key removed from ${user}. ${user} can no longer connect with it.`);
        return refresh();
      })
      .catch(fail);

  const toggleKeys = (user: string) => {
    setKeysFor((cur) => (cur === user ? null : user));
    // Kutuyu ve bildirimi TEMİZLE: önceki kullanıcının anahtarı kutuda
    // kalırsa bir sonraki "remove" yanlış hesaptan anahtar siler.
    setKeyText("");
    setNotice("");
  };

  // Panel tablonun ALTINDA çiziliyor: telefonda "keys" düğmesine basan
  // kişi ekranda hiçbir şey değişmediğini görüp düğmenin bozuk olduğunu
  // sanıyordu. Odağı kutuya taşımak paneli görünür alana da getiriyor.
  useEffect(() => {
    if (keysFor) keyBox.current?.focus();
  }, [keysFor]);

  // Satır silinince panel de kapanmalı; adla arayınca bu kendiliğinden
  // olur, kopyasını ayrı state'te tutmak silinmiş kullanıcıya anahtar
  // eklemeye çalışan bir form bırakırdı.
  const keysUser = items.find((u) => u.name === keysFor) ?? null;

  const columns: Column<User>[] = [
    { key: "name", header: "Name", value: (u) => u.name },
    { key: "os_user", header: "OS user", value: (u) => u.os_user },
    {
      key: "admin",
      header: "Admin",
      // Sıralama adminleri BİR ARADA toplasın: "kimler admin" sorusu
      // tek tıkla cevaplanabilsin.
      value: (u) => (u.admin ? 1 : 0),
      render: (u) =>
        u.admin ? (
          <span className="badge badge-accent">admin</span>
        ) : (
          <span className="muted">—</span>
        ),
    },
    {
      key: "roles",
      header: "Roles",
      className: "wrap",
      value: (u) => u.roles.join(" "),
      render: (u) =>
        u.roles.length === 0 ? (
          <span className="muted">no roles</span>
        ) : (
          <span className="chips">
            {u.roles.map((r) => (
              <span key={r} className="chip">
                <code>{r}</code>
                <ActionButton
                  onClick={() => revoke(u.name, r)}
                  confirm={`Revoke "${r}" from ${u.name}? They immediately lose every target that role grants.`}
                  label={`revoke role ${r} from ${u.name}`}
                >
                  revoke
                </ActionButton>
              </span>
            ))}
          </span>
        ),
    },
    {
      key: "assign",
      header: "Assign role",
      render: (u) => {
        // Zaten atanmış rol kutuda GÖRÜNMÜYOR: sunucu isteği kabul
        // ediyor (upsert) ama tabloda hiçbir şey değişmiyor —
        // değişmeyen satıra bakan yönetici atamanın tutmadığını sanıp
        // aynı düğmeye tekrar basıyordu.
        const free = roles.items.filter((r) => !u.roles.includes(r.name));
        const choice = picked[u.name] ?? "";
        return (
          <div className="cell-form">
            <select
              aria-label={`role to assign to ${u.name}`}
              value={choice}
              onChange={(e) => setPicked((p) => ({ ...p, [u.name]: e.target.value }))}
              disabled={free.length === 0}
            >
              <option value="">
                {roles.items.length === 0
                  ? "no roles defined"
                  : free.length === 0
                    ? "all roles assigned"
                    : "choose a role…"}
              </option>
              {free.map((r) => (
                <option key={r.name} value={r.name}>
                  {r.name}
                </option>
              ))}
            </select>
            <ActionButton
              onClick={() => assign(u.name, choice)}
              label={choice ? `assign ${choice} to ${u.name}` : `assign a role to ${u.name}`}
              disabled={!choice}
            >
              Assign
            </ActionButton>
          </div>
        );
      },
    },
    {
      key: "keys",
      header: "Keys",
      className: "num",
      value: (u) => u.keys,
      render: (u) => (
        <div className="cell-form">
          {u.keys === 0 ? <span className="muted">none</span> : u.keys}
          <button
            onClick={() => toggleKeys(u.name)}
            aria-expanded={keysFor === u.name}
            aria-label={`manage SSH keys for ${u.name}`}
          >
            {keysFor === u.name ? "Close" : "Keys"}
          </button>
        </div>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (u) => (
        <ActionButton
          variant="danger"
          onClick={() => remove(u.name)}
          confirm={`Delete the user "${u.name}"? Their SSH keys and role assignments go with them. If ${u.name} has recorded sessions the server refuses this outright — revoking their keys and roles is how access is cut without losing the audit trail.`}
          label={`delete user ${u.name}`}
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
          <h2>Users</h2>
          <p className="page-sub">
            Accounts postern knows. The admin flag is read-only here on purpose:
            it is set from the bastion&apos;s own CLI, so the panel can never
            hand out administrators.
          </p>
        </div>
        <button className="btn-primary" onClick={() => setAdding(true)}>
          New user
        </button>
      </div>
      <ErrorLine msg={error} />
      <OkLine msg={notice} />

      {/* Rol listesi düşerse atama kutusu boş kalır; sebebini
          söylemezsek operatör hiç rol tanımlı olmadığını sanar. */}
      <WarnLine
        msg={
          roles.error &&
          `Roles could not be loaded (${roles.error}) — you can still remove roles, but nothing can be assigned until that list comes back.`
        }
      />
      {!roles.loading && !roles.error && roles.items.length === 0 && (
        <WarnLine msg="No roles exist yet — create one on the Roles tab, otherwise every user here reaches nothing." />
      )}

      <ListState
        loading={loading}
        denied={denied}
        empty={items.length === 0}
        emptyText="No users yet. A user created here still needs a role and an SSH key before anyone can connect as them."
      />

      {items.length > 0 && (
        <DataTable
          rows={items}
          columns={columns}
          rowKey={(u) => u.name}
          initialSort={{ key: "name", dir: "asc" }}
          noun="user"
          searchLabel="search users by name, OS user or role"
          searchPlaceholder="Search users, or a role like sysadmin…"
        />
      )}

      {keysUser && (
        <div className="panel">
          <div className="panel-header">
            <h3>SSH keys — {keysUser.name}</h3>
            <span className="spacer" />
            <button onClick={() => toggleKeys(keysUser.name)}>Close</button>
          </div>
          {/*
            Anahtarlar LİSTELENMİYOR, yalnızca sayılıyor (User.keys) —
            sunucu böyle bir uç sunmuyor. O yüzden kaldırma da satır
            başına bir düğme değil, tam anahtar metni istiyor: hangi
            anahtarın gittiğini göstermeden çizilen bir "sil" düğmesi,
            yöneticiye kör bir tıklama yaptırırdı.
          */}
          <p className="muted small">
            {keysUser.keys === 0
              ? "No keys on file — until one is added, this user cannot connect at all."
              : `${keysUser.keys} key${keysUser.keys === 1 ? "" : "s"} on file. postern never hands stored keys back, so removing one takes the key text itself — the trailing comment does not have to match.`}
          </p>
          <label>
            authorized_keys line
            <textarea
              ref={keyBox}
              rows={3}
              cols={64}
              value={keyText}
              onChange={(e) => setKeyText(e.target.value)}
              placeholder="ssh-ed25519 AAAAC3Nza… someone@laptop"
            />
          </label>
          <div className="field-row">
            <ActionButton
              onClick={() => addKey(keysUser.name)}
              label={`add this key to ${keysUser.name}`}
              disabled={!keyText.trim()}
            >
              Add key
            </ActionButton>
            <ActionButton
              onClick={() => removeKey(keysUser.name)}
              confirm={`Remove this key from "${keysUser.name}"? If it is their last key they can no longer connect.`}
              label={`remove this key from ${keysUser.name}`}
              disabled={!keyText.trim()}
            >
              Remove key
            </ActionButton>
          </div>
        </div>
      )}

      <Modal
        open={adding}
        onClose={() => setAdding(false)}
        title="New user"
        description="The OS user is the account postern opens on the target host; it is not the name people sign in with."
      >
        <div className="field-row">
          <label>
            Name
            {/* trim: baştaki/sondaki boşluk gözle görünmüyor ama SSH
                tarafında ad birebir eşleşiyor — "ops " kullanıcısına
                hiç kimse bağlanamazdı. */}
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label>
            OS user
            <input value={osUser} onChange={(e) => setOsUser(e.target.value)} />
          </label>
          <label>
            Email (optional)
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <ActionButton
            variant="primary"
            onClick={() => create().then((ok) => ok && setAdding(false))}
            disabled={!name.trim() || !osUser.trim()}
          >
            Create user
          </ActionButton>
        </div>
      </Modal>
    </section>
  );
}
