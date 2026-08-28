import { useState } from "react";
import { api, LDAPTestResult, Setting, toMessage } from "../api";
import { ActionButton, ErrorLine, ListState, OkLine, WarnLine, useList } from "./common";

/**
 * LDAP yapılandırması — sihirbaz.
 *
 * NEDEN SİHİRBAZ: alanlar dokuz taneydi ve hepsi tek tabloda, her biri
 * kendi "save" düğmesiyle duruyordu. Bir dizin bağlantısını ilk kez
 * kuran kişi için bu bir form değil bir liste: hangi alanın hangisiyle
 * birlikte anlam kazandığı (bağlan → kullanıcıyı bul → grubunu oku)
 * ekranda hiçbir yerde yazmıyordu, ve yarısı doldurulmuş bir
 * yapılandırma "kaydedildi" diye onaylanıyordu.
 *
 * Adımlar ATLANABİLİR: tek bir alanı düzeltmek için baştan yürümek
 * gerekmiyor — kurulum bir kez, düzeltme defalarca yapılır.
 */

type StepId = "connection" | "users" | "groups" | "review";

type Field = { key: string; label: string; hint: string; secret?: boolean; required?: boolean };

const STEPS: { id: StepId; title: string; blurb: string; fields: Field[] }[] = [
  {
    id: "connection",
    title: "Connection",
    blurb:
      "How postern reaches the directory, and as whom. This is postern's own service account — never a person's.",
    fields: [
      {
        key: "ldap.url",
        label: "URL",
        hint: "ldaps://ldap.example:636 — plain ldap:// is refused unless it is loopback",
        required: true,
      },
      { key: "ldap.bind_dn", label: "Bind DN", hint: "cn=postern,ou=services,dc=example,dc=com", required: true },
      {
        key: "ldap.bind_password",
        label: "Bind password",
        hint: "stored encrypted and never shown again",
        secret: true,
        required: true,
      },
    ],
  },
  {
    id: "users",
    title: "Users",
    blurb: "Where to look a person up once the identity provider has said who they are.",
    fields: [
      { key: "ldap.user_base", label: "User base", hint: "ou=people,dc=example,dc=com", required: true },
      {
        key: "ldap.user_filter",
        label: "User filter",
        hint: "(uid=%s) — %s is replaced with the IdP username",
        required: true,
      },
    ],
  },
  {
    id: "groups",
    title: "Groups",
    blurb:
      "How to read someone's group membership. Either read it off the user entry (memberOf) or search the group tree — but the search base is required either way.",
    fields: [
      {
        key: "ldap.group_attribute",
        label: "Group attribute",
        hint: "memberOf — leave empty to search the group tree instead",
      },
      // ⚠️ Bu alan HER İKİ YOLDA DA zorunlu (bkz. ldap.New). memberOf
      // yolu eskiden dizinin herhangi bir yerindeki grubu kabul
      // ediyordu: "bir yere grup açabilmek" = "o rolün hedeflerine
      // girebilmek"ti. Kapsamı zorunlu kılmak bunu kapatıyor.
      {
        key: "ldap.group_base",
        label: "Group base",
        hint: "required — limits which part of the directory may name a postern role",
        required: true,
      },
      {
        key: "ldap.group_filter",
        label: "Group filter",
        hint: "(&(objectClass=groupOfNames)(member=%s)) — used when the attribute is empty",
      },
      { key: "ldap.group_name_from", label: "Group name from", hint: "cn (default) or dn" },
    ],
  },
  { id: "review", title: "Review", blurb: "What is stored, and whether it actually works.", fields: [] },
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
  const [step, setStep] = useState<StepId>("connection");
  const [status, setStatus] = useState("");
  const [warning, setWarning] = useState("");
  const [testUser, setTestUser] = useState("");
  const [test, setTest] = useState<LDAPTestResult | null>(null);

  const stored = (key: string) => items.find((s) => s.key === key);
  const hasValue = (key: string) => {
    const cur = stored(key);
    return cur !== undefined && cur.value !== "";
  };

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
    api.setSetting(key, value).then((r) => {
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
      setTest(null);
      return r;
    });

  /**
   * saveStep, adımdaki DEĞİŞTİRİLMİŞ alanları sırayla yazar.
   *
   * ⚠️ SIRALI, paralel değil: her yazma sunucuda grup kaynağını yeniden
   * kurmayı deniyor ve aynı anda giden istekler hangisinin son sözü
   * söylediğini belirsiz bırakırdı. Biri düşerse orada durup söylüyoruz —
   * kalanları yazmaya devam etmek, yarısı uygulanmış bir yapılandırmayı
   * "kaydedildi" diye onaylamak olurdu.
   */
  const saveStep = async (fields: Field[], next?: StepId) => {
    clearNotices();
    for (const f of fields) {
      const v = edits[f.key];
      if (v === undefined || v === "") continue;
      try {
        await write(f.key, v);
      } catch (e: unknown) {
        setError(toMessage(e));
        return;
      }
    }
    await refresh();
    if (next) setStep(next);
  };

  const clearField = (key: string) =>
    write(key, "")
      .then(() => refresh())
      .catch((e: unknown) => setError(toMessage(e)));

  const runTest = () => {
    clearNotices();
    return api
      .testLDAP(testUser || undefined)
      .then(setTest)
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const idx = STEPS.findIndex((s) => s.id === step);
  const current = STEPS[idx];
  const prev = idx > 0 ? STEPS[idx - 1] : null;
  const next = idx < STEPS.length - 1 ? STEPS[idx + 1] : null;

  // Bir adım "tamam" sayılıyorsa zorunlu alanlarının HEPSİ dolu.
  const stepDone = (s: (typeof STEPS)[number]) =>
    s.fields.length > 0 && s.fields.filter((f) => f.required).every((f) => hasValue(f.key));

  const nothingStored = items.length === 0 && error === "";

  return (
    <section>
      <div className="page-head">
        <h2>LDAP</h2>
        <p className="page-sub">
          Identity always comes from the identity provider. LDAP is only used to
          read group membership — postern never sees a user&apos;s password.
          Values are stored in the database, and secrets are never shown again.
        </p>
      </div>

      <ErrorLine msg={error} />
      <OkLine msg={status} />
      <WarnLine msg={warning} />

      {/* Yükleniyor ve yetki reddi GERÇEKTEN farklı hâller; "kayıt yok"
          ise bu ekranda bir boş liste değil, doldurulmayı bekleyen bir
          form — o yüzden empty her zaman false. */}
      <ListState loading={loading} denied={denied} empty={false} emptyText="" />

      {!loading && !denied && (
        <>
          {nothingStored && (
            <p className="note">
              Nothing stored yet — group membership comes from the IdP claim
              until <code>ldap.url</code> is set.
            </p>
          )}

          <div className="steps">
            {STEPS.map((s, i) => (
              <button
                key={s.id}
                className={`step${stepDone(s) ? " step-done" : ""}`}
                aria-current={s.id === step ? "step" : undefined}
                onClick={() => {
                  clearNotices();
                  setStep(s.id);
                }}
              >
                <span className="step-n" aria-hidden="true">
                  {stepDone(s) ? "✓" : i + 1}
                </span>
                {s.title}
              </button>
            ))}
          </div>

          <div className="panel">
            <h3>{current.title}</h3>
            <p className="note">{current.blurb}</p>

            {current.id === "review" ? (
              <>
                <dl className="kv">
                  {STEPS.flatMap((s) => s.fields).map((f) => {
                    const cur = stored(f.key);
                    const shown =
                      cur === undefined
                        ? "not set"
                        : cur.value === ""
                          ? "empty"
                          : f.secret || cur.secret
                            ? MASK
                            : cur.value;
                    return (
                      <div key={f.key} style={{ display: "contents" }}>
                        <dt>{f.label}</dt>
                        <dd>{shown}</dd>
                      </div>
                    );
                  })}
                </dl>

                <div className="field-row" style={{ marginTop: "1rem" }}>
                  <label>
                    Username to look up (optional)
                    <input
                      value={testUser}
                      onChange={(e) => {
                        clearNotices();
                        setTestUser(e.target.value);
                      }}
                    />
                  </label>
                  <ActionButton
                    variant="primary"
                    onClick={runTest}
                    label="test the stored LDAP settings"
                  >
                    Run test
                  </ActionButton>
                </div>
                <p className="note">
                  The test reads what is <b>stored</b>, not what is typed above.
                  A wrong base DN or bind password should surface here, not on
                  someone&apos;s first login.
                </p>

                {test &&
                  (test.ok ? (
                    <OkLine msg="connection and bind succeeded" />
                  ) : (
                    // Boş bir hata metni hiçbir şey çizmez, o da BAŞARISIZ
                    // testi başarılı gibi gösterirdi.
                    <ErrorLine
                      msg={test.error || "the bind failed and the server did not say why"}
                    />
                  ))}

                {test?.groups && (
                  <dl className="kv">
                    <dt>groups</dt>
                    <dd>{test.groups.join(", ") || "—"}</dd>
                    <dt>mapped to roles</dt>
                    <dd>{test.roles?.join(", ") || "—"}</dd>
                    <dt>unmapped</dt>
                    <dd>{test.unmapped?.join(", ") || "—"}</dd>
                  </dl>
                )}
              </>
            ) : (
              <>
                {current.fields.map((f) => {
                  const cur = stored(f.key);
                  const filled = hasValue(f.key);
                  return (
                    <div className="field-row" key={f.key}>
                      <label style={{ flexBasis: "100%" }}>
                        {/* Tek satır: label flex-column olduğu için ad ile
                            "required" ayrı çocuklar olarak alt alta
                            düşüyordu. */}
                        <span>
                          {f.label}
                          {f.required && <span className="muted"> · required</span>}
                        </span>
                        <input
                          type={f.secret ? "password" : "text"}
                          value={edits[f.key] ?? ""}
                          // Placeholder ad değildir: yazmaya başlayınca
                          // kaybolur ve ekran okuyucuya adsız bir kutu kalır.
                          aria-label={`new value for ${f.label}`}
                          // ⚠️ İPUCU BURADA DEĞİL. Yer tutucuya da ipucu
                          // koyunca aynı cümle hem kutunun içinde hem
                          // altında iki kez yazıyordu. Yer tutucu SAKLI
                          // OLANI gösteriyor — kutunun neyin üstüne
                          // yazacağını söylüyor.
                          placeholder={
                            filled ? (f.secret || cur?.secret ? MASK : cur?.value) : ""
                          }
                          onChange={(e) => {
                            clearNotices();
                            setEdits({ ...edits, [f.key]: e.target.value });
                          }}
                        />
                      </label>
                      <div className="setting-hint" style={{ flexBasis: "100%" }}>
                        {f.hint}
                        {" · "}
                        {/* "hiç yazılmadı" ile "boşaltıldı" AYNI ŞEY DEĞİL:
                            boş group_attribute, grup aramaya geçildiğini
                            söyleyen geçerli bir yapılandırma. */}
                        {cur === undefined ? (
                          <span className="muted">not set</span>
                        ) : cur.value === "" ? (
                          <span className="muted">stored as empty</span>
                        ) : (
                          <>
                            <span className="muted">stored</span>{" "}
                            {/*
                              Boşaltma AYRI bir düğme.

                              ⚠️ Tek "save" düğmesi vardı ve boş değerde
                              kapalıydı: "group attribute'ü boşalt, grup
                              aramaya geç" moduna arayüzden ULAŞILAMIYORDU.
                            */}
                            <ActionButton
                              variant="danger"
                              onClick={() => clearField(f.key)}
                              confirm={`Clear ${f.key}? The stored value is removed and postern behaves as if it was never set.`}
                              label={`clear ${f.key}`}
                            >
                              Clear
                            </ActionButton>
                          </>
                        )}
                      </div>
                    </div>
                  );
                })}
              </>
            )}

            <div className="wizard-nav">
              {prev && (
                <button
                  onClick={() => {
                    clearNotices();
                    setStep(prev.id);
                  }}
                >
                  Back
                </button>
              )}
              <span className="spacer" />
              {current.fields.length > 0 && (
                <ActionButton
                  variant="primary"
                  onClick={() => saveStep(current.fields, next?.id)}
                  label={`save this step${next ? " and continue" : ""}`}
                >
                  {next ? "Save and continue" : "Save"}
                </ActionButton>
              )}
              {current.fields.length === 0 && next && (
                <button onClick={() => setStep(next.id)}>Continue</button>
              )}
            </div>
          </div>
        </>
      )}
    </section>
  );
}
