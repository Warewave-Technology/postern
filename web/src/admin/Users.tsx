import { useEffect, useRef, useState } from "react";
import { api, Role, User, toMessage } from "../api";
import { ActionButton, ErrorLine, ListState, OkLine, WarnLine, useList } from "./common";

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

  const create = () =>
    api
      .createUser({ name: name.trim(), os_user: osUser.trim(), email: email.trim() || undefined })
      .then(() => {
        setName("");
        setOsUser("");
        setEmail("");
        setNotice(`${name.trim()} created — give it a role and a key below, or it reaches nothing.`);
        return refresh();
      })
      .catch(fail);

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

  return (
    <section>
      <h2>Users</h2>
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
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>OS user</th>
                <th>Admin</th>
                <th className="wrap">Roles</th>
                <th>Assign role</th>
                <th>Keys</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((u) => {
                // Zaten atanmış rol kutuda GÖRÜNMÜYOR: sunucu isteği kabul
                // ediyor (upsert) ama tabloda hiçbir şey değişmiyor —
                // değişmeyen satıra bakan yönetici atamanın tutmadığını sanıp
                // aynı düğmeye tekrar basıyordu.
                const free = roles.items.filter((r) => !u.roles.includes(r.name));
                const choice = picked[u.name] ?? "";

                return (
                  <tr key={u.name}>
                    <td>{u.name}</td>
                    <td>{u.os_user}</td>
                    {/* Admin sütunu SALT OKUNUR: bayrak yalnızca hosttaki CLI'dan
                        değişir — panel kendine yetki dağıtamaz. */}
                    <td>{u.admin ? "yes" : "—"}</td>
                    <td className="wrap">
                      {u.roles.length === 0 ? (
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
                      )}
                    </td>
                    <td>
                      <div className="cell-form">
                        <select
                          aria-label={`role to assign to ${u.name}`}
                          value={choice}
                          onChange={(e) =>
                            setPicked((p) => ({ ...p, [u.name]: e.target.value }))
                          }
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
                          assign
                        </ActionButton>
                      </div>
                    </td>
                    <td>
                      <div className="cell-form">
                        {u.keys === 0 ? <span className="muted">none</span> : u.keys}
                        <button
                          onClick={() => toggleKeys(u.name)}
                          aria-expanded={keysFor === u.name}
                          aria-label={`manage SSH keys for ${u.name}`}
                        >
                          {keysFor === u.name ? "close" : "keys"}
                        </button>
                      </div>
                    </td>
                    <td>
                      <ActionButton
                        onClick={() => remove(u.name)}
                        confirm={`Delete the user "${u.name}"? Their SSH keys and role assignments go with them. If ${u.name} has recorded sessions the server refuses this outright — revoking their keys and roles is how access is cut without losing the audit trail.`}
                        label={`delete user ${u.name}`}
                      >
                        delete
                      </ActionButton>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <p className="muted small">
        The admin column is read-only here on purpose: the flag is set from the
        bastion's own CLI, so the panel can never hand out administrators.
      </p>

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

      <h3>Add user</h3>
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
        <ActionButton onClick={create} disabled={!name.trim() || !osUser.trim()}>
          Create
        </ActionButton>
      </div>
      <p className="muted small">
        The OS user is the account postern opens on the target host; it is not
        the name people sign in with.
      </p>
    </section>
  );
}
