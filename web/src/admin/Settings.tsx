import { useState } from "react";
import { api, LDAPTestResult, Setting, toMessage } from "../api";
import { ActionButton, ErrorLine, ListState, OkLine, WarnLine, useList } from "./common";

// LDAP alanları. Sıra yapılandırma sırasıyla aynı: önce bağlantı, sonra
// kullanıcı arama, sonra grup okuma.
const FIELDS: { key: string; label: string; hint: string; secret?: boolean }[] = [
  { key: "ldap.url", label: "URL", hint: "ldaps://ldap.example:636 — plain ldap:// only on loopback" },
  { key: "ldap.bind_dn", label: "Bind DN", hint: "postern's own service account, not a user" },
  { key: "ldap.bind_password", label: "Bind password", hint: "stored encrypted, never shown again", secret: true },
  { key: "ldap.user_base", label: "User base", hint: "ou=people,dc=example,dc=com" },
  { key: "ldap.user_filter", label: "User filter", hint: "(uid=%s) — %s is the IdP username" },
  { key: "ldap.group_attribute", label: "Group attribute", hint: "memberOf — leave empty to search groups instead" },
  // İpucu "grup niteliği boşken kullanılır" diyordu; artık DOĞRU DEĞİL.
  // group_base her iki yolda da zorunlu (bkz. ldap.New): memberOf yolu
  // eskiden dizinin herhangi bir yerindeki grubu kabul ediyordu ve
  // "bir yere grup açabilmek" = "o rolün hedeflerine girebilmek"ti.
  // Eski ipucu memberOf kullanan operatörü alanı boş bırakmaya
  // yönlendirir, bağlantı reddedilir ve sebebi panelde görünmezdi.
  { key: "ldap.group_base", label: "Group base", hint: "required — limits which part of the directory may name a role" },
  { key: "ldap.group_filter", label: "Group filter", hint: "(&(objectClass=groupOfNames)(member=%s))" },
  { key: "ldap.group_name_from", label: "Group name from", hint: "cn (default) or dn" },
];

// Sunucunun "kaydettim ama kaynağı kuramadım" cevabının öneki
// (bkz. reloadGroupSource).
//
// ⚠️ Bu cevap YEŞİL çiziliyordu: yarım kalmış bir LDAP yapılandırması
// admine başarı diye onaylanıyor, o da grupların artık LDAP'tan geldiğini
// sanıyordu. Yetkilendirme durumu hakkında söylenen en pahalı yalan.
const INCOMPLETE = "incomplete:";

// Sunucunun sırlar için döndürdüğü maske (store.secretMask ile aynı).
const MASK = "********";

export default function Settings() {
  const { items, error, denied, loading, refresh, setError } = useList<Setting>(api.settings);
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [status, setStatus] = useState("");
  const [warning, setWarning] = useState("");
  const [testUser, setTestUser] = useState("");
  const [test, setTest] = useState<LDAPTestResult | null>(null);

  const stored = (key: string) => items.find((s) => s.key === key);

  // Girdi değişince önceki cevaplar ARTIK O EKRANI ANLATMIYOR: eskiden
  // temizlenmiyordu, admin alanı düzenledikten sonra da bir önceki
  // "ok" satırı duruyordu — yani ekrandaki yapılandırma için değil, bir
  // öncekisi için verilmiş onayı okuyordu.
  const clearNotices = () => {
    setStatus("");
    setWarning("");
    setTest(null);
  };

  const write = (key: string, value: string) =>
    api
      .setSetting(key, value)
      .then((r) => {
        setEdits((e) => {
          const next = { ...e };
          delete next[key];
          return next;
        });
        // "incomplete: ..." yazmanın başarılı olduğunu ama grup
        // kaynağının DEĞİŞMEDİĞİNİ söyler; sunucu eskisini korur.
        const stuck = r.source.startsWith(INCOMPLETE);
        setStatus(stuck ? "" : `saved — group source: ${r.source}`);
        setWarning(stuck ? `saved, but the group source did not switch — ${r.source}` : "");
        // Yazılan ayar, testin dayandığı yapılandırmayı değiştirdi.
        setTest(null);
        // Yenileme uçuşun parçası: liste tazelenmeden düğme açılırsa
        // ikinci tıklama eski "Stored" sütununa bakarak yapılır.
        return refresh();
      })
      .catch((e: unknown) => {
        setStatus("");
        setWarning("");
        // toMessage: Error olmayan bir reddediş boş mesaj bırakıyor,
        // ErrorLine boş mesajda hiçbir şey çizmiyordu — BAŞARISIZ bir
        // yazma başarılı olmuş gibi görünüyordu.
        setError(toMessage(e));
      });

  const runTest = () => {
    clearNotices();
    return api
      .testLDAP(testUser || undefined)
      .then(setTest)
      .catch((e: unknown) => setError(toMessage(e)));
  };

  return (
    <section>
      <h2>LDAP settings</h2>
      <p className="muted small">
        Identity always comes from the identity provider. LDAP is only used to
        read group membership — postern never sees a user's password.
      </p>
      <ErrorLine msg={error} />
      <OkLine msg={status} />
      <WarnLine msg={warning} />

      <ListState
        loading={loading}
        denied={denied}
        // Liste HATA ile döndüyse boş: "hiçbir şey yazılmamış" demek
        // yanlış olur — bilmiyoruz, okuyamadık. Hata satırı yeter.
        empty={items.length === 0 && error === ""}
        emptyText="Nothing stored yet — group membership comes from the IdP claim until ldap.url is set."
      />

      {/* Yetki reddedildiyse form da çizilmiyor: yazamayacağı alanları
          doldurtmak, admine olmayan bir yetki vaat etmektir. */}
      {!loading && !denied && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Setting</th>
                <th>Stored</th>
                <th>New value</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {FIELDS.map((f) => {
                const cur = stored(f.key);
                const pending = edits[f.key] ?? "";
                const hasValue = cur !== undefined && cur.value !== "";
                return (
                  <tr key={f.key}>
                    <td className="wrap">
                      {f.label}
                      <div className="muted small">{f.hint}</div>
                    </td>
                    <td>
                      {hasValue ? (
                        // Sır sunucuda maskeleniyor ve düz metni buraya
                        // hiç gelmiyor; f.secret ikinci kilit: maskeleme
                        // bir gün gerilerse bind parolası DOM'a düşmesin.
                        <code>{f.secret || cur.secret ? MASK : cur.value}</code>
                      ) : (
                        // "hiç yazılmadı" ile "boşaltıldı" AYNI ŞEY DEĞİL:
                        // boş group_attribute, grup aramaya geçildiğini
                        // söyleyen geçerli bir yapılandırma.
                        <span className="muted">{cur ? "empty" : "not set"}</span>
                      )}
                    </td>
                    <td>
                      <input
                        type={f.secret ? "password" : "text"}
                        size={28}
                        value={pending}
                        // Placeholder ad değildir: yazmaya başlayınca
                        // kaybolur ve ekran okuyucuya adsız bir kutu kalır.
                        aria-label={`new value for ${f.label}`}
                        onChange={(e) => {
                          clearNotices();
                          setEdits({ ...edits, [f.key]: e.target.value });
                        }}
                      />
                    </td>
                    <td>
                      <ActionButton
                        onClick={() => write(f.key, pending)}
                        disabled={pending === ""}
                        label={`save ${f.key}`}
                      >
                        save
                      </ActionButton>{" "}
                      {/*
                        Boşaltma AYRI bir düğme.

                        ⚠️ Tek "save" düğmesi vardı ve boş değerde kapalıydı:
                        sayfanın kendi ipucunun anlattığı "group attribute'ü
                        boşalt, grup aramaya geç" moduna arayüzden
                        ULAŞILAMIYORDU. Yıkıcı olduğu için onay ister.
                      */}
                      {hasValue && (
                        <ActionButton
                          onClick={() => write(f.key, "")}
                          confirm={`Clear ${f.key}? The stored value is removed and postern behaves as if it was never set.`}
                          label={`clear ${f.key}`}
                        >
                          clear
                        </ActionButton>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div className="panel">
        <h3>Test connection</h3>
        <p className="muted small">
          A wrong base DN or bind password should surface here, not on someone's
          first login. The test reads what is STORED, not what is typed above.
        </p>
        <div className="field-row">
          <label>
            Username to look up (optional)
            <input
              size={28}
              value={testUser}
              onChange={(e) => {
                clearNotices();
                setTestUser(e.target.value);
              }}
            />
          </label>
          <ActionButton onClick={runTest} label="test the stored LDAP settings">
            Test
          </ActionButton>
        </div>

        {test &&
          (test.ok ? (
            <OkLine msg="connection and bind succeeded" />
          ) : (
            // Boş bir hata metni hiçbir şey çizmez, o da BAŞARISIZ testi
            // başarılı gibi gösterirdi.
            <ErrorLine msg={test.error || "the bind failed and the server did not say why"} />
          ))}

        {test?.groups && (
          <ul>
            <li>groups: {test.groups.join(", ") || "—"}</li>
            <li>mapped to roles: {test.roles?.join(", ") || "—"}</li>
            <li>unmapped: {test.unmapped?.join(", ") || "—"}</li>
          </ul>
        )}
      </div>
    </section>
  );
}
