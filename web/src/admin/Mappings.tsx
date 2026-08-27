import { useRef, useState } from "react";
import { api, Mapping, Role, UnmappedGroup, toMessage } from "../api";
import { ActionButton, ErrorLine, ListState, OkLine, useList } from "./common";

// IdP grubu → postern rolü eşlemesi.
//
// Eşlenmemiş gruplar bölümü bilerek AYNI sayfada: yöneticinin "IdP bana
// ne gönderiyor" sorusuyla "hangisini eşleyeyim" kararı yan yana
// durmalı. Warpgate'te bu bilgi hiçbir yerde olmadığı için insanlar
// claim'lerin geldiğini görüp neden rol oluşmadığını anlayamıyor.
export default function Mappings() {
  const { items, error, denied, loading, refresh, setError } = useList<Mapping>(api.mappings);
  const unmapped = useList<UnmappedGroup>(api.unmappedGroups);
  const roles = useList<Role>(api.roles);

  const [group, setGroup] = useState("");
  const [role, setRole] = useState("");
  // Hem ekleme hem kaldırma GECİKMELİ etki ediyor: satırın tablodan
  // gidip gelmesi işin bittiğini söylüyor ama ne zaman geçerli olacağını
  // söylemiyor. O cümle olmadan yönetici "kaldırdım, hâlâ girebiliyor"
  // diye ürünü bozuk sanıyor.
  const [notice, setNotice] = useState("");

  // Eşlenmemiş satırdaki düğme grubu yukarıdaki forma yazıyor; odağı da
  // taşımak gerekiyor, yoksa tıklayan kişi ekranın altında kalıyor ve
  // hiçbir şey olmamış gibi görünüyor.
  const roleRef = useRef<HTMLSelectElement>(null);

  const add = () => {
    const g = group.trim();
    setNotice("");
    return api
      .addMapping(g, role)
      .then(() => {
        // Rol seçili KALIYOR: aynı role birden çok grup eşlemek olağan iş.
        setGroup("");
        setNotice(`${g} → ${role} mapped. Members get the role at their next sign-in.`);
        refresh();
        unmapped.refresh();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const remove = (m: Mapping) => {
    setNotice("");
    return api
      .removeMapping(m.group, m.role)
      .then(() => {
        setNotice(
          `${m.group} → ${m.role} removed. Anyone who already holds ${m.role} keeps it until their next sign-in.`,
        );
        refresh();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const mapThisGroup = (name: string) => {
    setGroup(name);
    roleRef.current?.focus();
  };

  // Sunucu teşhis tablosundan satır SİLMİYOR: bir grubu eşledikten sonra
  // da "eşlenmemiş" listesinde duruyor ve yönetici eşlemenin tutmadığını
  // sanıyor. Karşılaştırma küçük harfle, çünkü sunucudaki eşleşme de harf
  // duyarsız (store.ciEq) — "Developers" eşliyken "developers" satırı
  // kalmamalı.
  const mapped = new Set(items.map((m) => m.group.toLowerCase()));
  const pending = unmapped.items.filter((g) => !mapped.has(g.name.toLowerCase()));

  return (
    <section>
      <h2>Group mappings</h2>
      <ErrorLine msg={error} />
      <OkLine msg={notice} />
      <p className="muted small">
        A mapping is applied at sign-in. Removing one revokes nothing on the
        spot: existing SSO assignments are refreshed on the user's next login.
      </p>

      <ListState
        loading={loading}
        denied={denied}
        empty={items.length === 0}
        emptyText="No mappings — nobody can sign in through the IdP yet."
      />
      {items.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>IdP group</th>
                <th>Role</th>
                <th>Mapped by</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((m) => (
                <tr key={`${m.group}/${m.role}`}>
                  <td>{m.group}</td>
                  <td>{m.role}</td>
                  <td>{m.created_by}</td>
                  <td>
                    <ActionButton
                      confirm={`Remove the mapping ${m.group} → ${m.role}? Anyone who already holds ${m.role} keeps it until their next sign-in.`}
                      label={`remove mapping ${m.group} to ${m.role}`}
                      onClick={() => remove(m)}
                    >
                      remove
                    </ActionButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h3>Add mapping</h3>
      <div className="field-row">
        <label>
          IdP group
          <input
            value={group}
            onChange={(e) => setGroup(e.target.value)}
            placeholder="sysadmins"
          />
        </label>
        <label>
          Role
          <select ref={roleRef} value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="">select role…</option>
            {roles.items.map((r) => (
              <option key={r.name} value={r.name}>{r.name}</option>
            ))}
          </select>
        </label>
        <ActionButton onClick={add} disabled={!group.trim() || !role}>
          Map
        </ActionButton>
      </div>
      <ErrorLine msg={roles.error} />
      {/*
        Boş bir rol açılırı sessizce "seçecek bir şey yok" gibi duruyor.
        Sebebi söylenmezse yönetici formu bozuk sanıyor — ve reddedilmiş
        bir istek ile gerçekten rol olmaması AYNI şey değil.
      */}
      {!roles.loading && roles.items.length === 0 && (
        <p className="muted small">
          {roles.denied
            ? "Roles could not be listed for your account, so this list is empty — that is not the same as there being no roles."
            : "No roles exist yet — create one on the Roles tab before a group can be mapped."}
        </p>
      )}

      <h3>Groups seen but not mapped</h3>
      <p className="muted small">
        These arrived in a login and matched no role, so whoever signed in got
        nothing from them. Mapping one grants access on that user's next
        sign-in.
      </p>
      <ErrorLine msg={unmapped.error} />
      <ListState
        loading={unmapped.loading}
        denied={unmapped.denied}
        empty={pending.length === 0}
        emptyText="Nothing unmapped so far — every group seen in a login matched a role."
      />
      {pending.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Group</th>
                <th>Times seen</th>
                <th>Last seen</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {pending.map((g) => (
                <tr key={g.name}>
                  <td>{g.name}</td>
                  <td>{g.seen_count}</td>
                  <td>{g.last_seen}</td>
                  <td>
                    <button
                      onClick={() => mapThisGroup(g.name)}
                      aria-label={`map group ${g.name}`}
                    >
                      map this group
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
