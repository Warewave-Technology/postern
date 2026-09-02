import { useMemo, useState } from "react";
import { LDAPCandidate, LDAPTestResult, Setting, api, toMessage } from "../api";
import {
  ActionButton,
  ErrorLine,
  ListState,
  OkLine,
  WarnLine,
  useList,
} from "./common";
import ArchiveCredential from "./ArchiveCredential";
import AdminGroup from "./AdminGroup";
import SyncPanel from "./SyncPanel";

/**
 * LDAP yapılandırması.
 *
 * ÜÇ HÂL, ve hangisinin gösterileceğini yapılandırmanın kendisi söylüyor:
 *
 *   1. Kurulmamış  → SİHİRBAZ. Dokuz alan tek tabloda dururken, hangisinin
 *      hangisiyle anlam kazandığı (bağlan → kullanıcıyı bul → grubunu oku)
 *      ekranda hiçbir yerde yazmıyordu.
 *   2. Kurulmuş    → BEYAN. Sihirbazı kurulduktan sonra da göstermek,
 *      bitmiş bir işi bitmemiş gibi sunmak; operatör her girişinde "bir
 *      şey mi eksik" diye bakıyordu.
 *   3. Düzenleme   → tek form, ve SINANMADAN KAYDEDİLEMEZ.
 *
 * ⚠️ (3)'ün kuralı yalnızca bir nezaket değil: bu ayarlar yetkilendirmenin
 * kaynağı. Bozuk bir değeri kaydetmek, herkesin girişini — düzeltecek
 * kişininki dahil — o anda kesiyor. Sıra bu yüzden tersine çevrildi:
 * önce kanıtla, sonra yaz.
 */

type Field = {
  key: string;
  label: string;
  hint: string;
  secret?: boolean;
  required?: boolean;
};

const FIELDS: Field[] = [
  {
    key: "ldap.url",
    label: "URL",
    hint: "ldaps://ldap.example:636 — plain ldap:// is refused unless it is loopback",
    required: true,
  },
  {
    key: "ldap.bind_dn",
    label: "Bind DN",
    hint: "postern's own service account, never a person's",
    required: true,
  },
  {
    key: "ldap.bind_password",
    label: "Bind password",
    hint: "stored encrypted and never shown again",
    secret: true,
    required: true,
  },
  {
    key: "ldap.user_base",
    label: "User base",
    hint: "ou=people,dc=example,dc=com",
    required: true,
  },
  {
    key: "ldap.user_filter",
    label: "User filter",
    hint: "(uid=%s) — %s is replaced with the IdP username",
    required: true,
  },
  {
    key: "ldap.group_attribute",
    label: "Group attribute",
    hint: "memberOf — leave empty to search the group tree instead",
  },
  // ⚠️ Bu alan HER İKİ YOLDA DA zorunlu (bkz. ldap.New). memberOf yolu
  // eskiden dizinin herhangi bir yerindeki grubu kabul ediyordu: "bir
  // yere grup açabilmek" = "o rolün hedeflerine girebilmek"ti.
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
  {
    key: "ldap.group_name_from",
    label: "Group name from",
    hint: "cn (default) or dn",
  },
];

type StepId = "connection" | "users" | "groups" | "review";

const STEPS: { id: StepId; title: string; blurb: string; keys: string[] }[] = [
  {
    id: "connection",
    title: "Connection",
    blurb:
      "How postern reaches the directory, and as whom. This is postern's own service account — never a person's.",
    keys: ["ldap.url", "ldap.bind_dn", "ldap.bind_password"],
  },
  {
    id: "users",
    title: "Users",
    blurb:
      "Where to look a person up once the identity provider has said who they are.",
    keys: ["ldap.user_base", "ldap.user_filter"],
  },
  {
    id: "groups",
    title: "Groups",
    blurb:
      "How to read someone's group membership. Either read it off the user entry (memberOf) or search the group tree — but the search base is required either way.",
    keys: [
      "ldap.group_attribute",
      "ldap.group_base",
      "ldap.group_filter",
      "ldap.group_name_from",
    ],
  },
  {
    id: "review",
    title: "Review",
    blurb: "What is stored, and whether it actually works.",
    keys: [],
  },
];

// Sunucunun "kaydettim ama kaynağı kuramadım" cevabının öneki.
const INCOMPLETE = "incomplete:";

// Sunucunun sırlar için döndürdüğü maske (store.secretMask ile aynı).
const MASK = "********";

const byKey = (k: string) => FIELDS.find((f) => f.key === k)!;

/*
 * ⚠️ BU DOĞRULAMA BİR ERKEN UYARI, KURAL DEĞİL.
 *
 * Asıl kural sunucuda (ldap.New / ldap.checkScheme) ve orada kalmalı:
 * panel süslü bir istemci, yetkilendirme kararı veren taraf değil.
 * Buradaki kopya yalnızca yazarken söylemek için var.
 */
function looksLoopback(rawURL: string): boolean {
  try {
    const host = new URL(
      rawURL.replace(/^ldaps?:\/\//i, "http://"),
    ).hostname.replace(/^\[|\]$/g, "");
    if (host === "localhost" || host === "::1") return true;
    return /^127\./.test(host);
  } catch {
    return false;
  }
}

function fieldProblem(key: string, value: string): string {
  if (value === "") return "";
  switch (key) {
    case "ldap.url": {
      const scheme = value.split("://")[0].toLowerCase();
      if (scheme === "ldaps") return "";
      if (scheme === "ldap") {
        return looksLoopback(value)
          ? ""
          : "plain ldap:// is only accepted for loopback — the service account password would cross the network in the clear";
      }
      return `unsupported scheme “${scheme}” — use ldaps://`;
    }
    case "ldap.user_filter":
      return value.includes("%s")
        ? ""
        : "must contain %s — that is where the IdP username is substituted";
    case "ldap.group_filter":
      return value.includes("%s")
        ? ""
        : "must contain %s — that is where the user's DN is substituted";
    case "ldap.group_name_from":
      return value === "cn" || value === "dn" ? "" : "must be either cn or dn";
    default:
      return "";
  }
}

/** Hatanın ad çözümlemesi kaynaklı olup olmadığı (Go'nun net paketi). */
function looksLikeDNS(err?: string): boolean {
  if (!err) return false;
  const e = err.toLowerCase();
  return (
    e.includes("no such host") ||
    e.includes("server misbehaving") ||
    e.includes("lookup ")
  );
}

export default function Settings({ meName }: { meName?: string }) {
  const { items, error, denied, loading, failed, refresh, setError } =
    useList<Setting>(api.settings);

  const [mode, setMode] = useState<"auto" | "edit">("auto");
  const [step, setStep] = useState<StepId>("connection");
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [status, setStatus] = useState("");
  const [warning, setWarning] = useState("");
  const [testUser, setTestUser] = useState("");
  const [test, setTest] = useState<LDAPTestResult | null>(null);
  const [conn, setConn] = useState<{ ok: boolean; error?: string } | null>(
    null,
  );

  // Sınama sonucu, SINANAN DEĞERLERE bağlı. Form değişince geçersiz
  // olmalı — yoksa "test geçti" damgası başka bir yapılandırmaya ait olur.
  const [verified, setVerified] = useState<{
    sig: string;
    result: LDAPTestResult;
  } | null>(null);

  const stored = (key: string) => items.find((s) => s.key === key);
  const hasValue = (key: string) => {
    const cur = stored(key);
    return cur !== undefined && cur.value !== "";
  };

  const clearNotices = () => {
    setStatus("");
    setWarning("");
    setTest(null);
    setConn(null);
  };

  const write = (key: string, value: string) =>
    api.setSetting(key, value).then((r) => {
      setEdits((e) => {
        const next = { ...e };
        delete next[key];
        return next;
      });
      const stuck = r.source.startsWith(INCOMPLETE);
      setStatus(stuck ? "" : `saved — group source: ${r.source}`);
      setWarning(
        stuck ? `saved, but the group source did not switch — ${r.source}` : "",
      );
      setTest(null);
      return r;
    });

  /**
   * saveKeys, değiştirilmiş alanları SIRAYLA yazar.
   *
   * ⚠️ Sıralı, paralel değil: her yazma sunucuda grup kaynağını yeniden
   * kurmayı deniyor ve aynı anda giden istekler hangisinin son sözü
   * söylediğini belirsiz bırakırdı.
   */
  const saveKeys = async (keys: string[]): Promise<boolean> => {
    for (const key of keys) {
      const v = edits[key];
      if (v === undefined || v === "") continue;
      try {
        await write(key, v);
      } catch (e: unknown) {
        setError(toMessage(e));
        return false;
      }
    }
    await refresh();
    return true;
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

  const checkConnection = () => {
    clearNotices();
    return api
      .checkLDAPConnection()
      .then(setConn)
      .catch((e: unknown) => setError(toMessage(e)));
  };

  // --- kurulu mu? ---
  const problems: string[] = [];
  if (!loading && !denied) {
    for (const f of FIELDS) {
      const cur = stored(f.key);
      if (f.required && (cur === undefined || cur.value === "")) {
        problems.push(`${f.label} is required and nothing is stored`);
        continue;
      }
      // Sırlar maskeli geliyor: değerini doğrulayamayız, yalnızca
      // varlığını. Maskeyi doğrulamak uydurma bir hata üretirdi.
      if (cur && !cur.secret && !f.secret) {
        const bad = fieldProblem(f.key, cur.value);
        if (bad) problems.push(`${f.label}: ${bad}`);
      }
    }
    const attr = stored("ldap.group_attribute");
    const filt = stored("ldap.group_filter");
    const hasAttr = attr !== undefined && attr.value !== "";
    const hasFilter = filt !== undefined && filt.value !== "";
    if (!hasAttr && !hasFilter && items.length > 0) {
      problems.push(
        "Group attribute and Group filter are both empty — set one: memberOf on the user entry, or a filter to search the group tree",
      );
    }
  }
  const configured =
    !loading && !denied && items.length > 0 && problems.length === 0;

  // --- düzenleme formu ---
  const editValue = (key: string) => {
    if (edits[key] !== undefined) return edits[key];
    if (byKey(key).secret) return ""; // sır geri gelmiyor
    return stored(key)?.value ?? "";
  };

  const candidate: LDAPCandidate = useMemo(
    () => ({
      url: editValue("ldap.url"),
      bind_dn: editValue("ldap.bind_dn"),
      bind_password: editValue("ldap.bind_password"),
      user_base: editValue("ldap.user_base"),
      user_filter: editValue("ldap.user_filter"),
      group_attribute: editValue("ldap.group_attribute"),
      group_base: editValue("ldap.group_base"),
      group_filter: editValue("ldap.group_filter"),
      group_name_from: editValue("ldap.group_name_from"),
      user: testUser || undefined,
    }),
    // editValue items ve edits'e bağlı; ikisi de listede.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [items, edits, testUser],
  );

  // ⚠️ İMZAYA kullanıcı adı GİRMİYOR: "kimi arayalım" sorusu
  // yapılandırmanın parçası değil, sınamanın parametresi. Girseydi
  // kutuya yazılan her harf geçerli bir sınamayı iptal ederdi.
  const signature = JSON.stringify({ ...candidate, user: undefined });
  const verifiedNow = verified?.sig === signature && verified.result.ok;

  const verify = () => {
    setError("");
    return api
      .verifyLDAP(candidate)
      .then((r) => setVerified({ sig: signature, result: r }))
      .catch((e: unknown) => {
        setVerified(null);
        setError(toMessage(e));
      });
  };

  const saveEdit = async () => {
    const changed = FIELDS.map((f) => f.key).filter(
      (k) => edits[k] !== undefined && edits[k] !== "",
    );
    if (await saveKeys(changed)) {
      setMode("auto");
      setVerified(null);
    }
  };

  const idx = STEPS.findIndex((s) => s.id === step);
  const current = STEPS[idx];
  const prev = idx > 0 ? STEPS[idx - 1] : null;
  const next = idx < STEPS.length - 1 ? STEPS[idx + 1] : null;
  const stepFields = current.keys.map(byKey);

  const stepDone = (s: (typeof STEPS)[number]) =>
    s.keys.length > 0 &&
    s.keys
      .map(byKey)
      .filter((f) => f.required)
      .every((f) => hasValue(f.key));

  const stepHasProblem = stepFields.some(
    (f) => fieldProblem(f.key, edits[f.key] ?? "") !== "",
  );

  // Tek bir alanın çizimi — sihirbaz ve düzenleme formu paylaşıyor.
  const renderField = (
    f: Field,
    value: string,
    onChange: (v: string) => void,
  ) => {
    const cur = stored(f.key);
    const filled = hasValue(f.key);
    const problem = fieldProblem(f.key, value);
    return (
      <div className="wfield" key={f.key}>
        <label className="wfield-label" htmlFor={`f-${f.key}`}>
          {f.label}
          {f.required && <span className="wfield-req">required</span>}
        </label>
        <input
          id={`f-${f.key}`}
          type={f.secret ? "password" : "text"}
          value={value}
          aria-invalid={problem ? true : undefined}
          aria-describedby={`h-${f.key}`}
          // Yer tutucu SAKLI OLANI gösteriyor: kutunun neyin üstüne
          // yazacağını söylüyor. İpucu aşağıda, ikisi aynı cümle değil.
          placeholder={
            filled ? (f.secret || cur?.secret ? MASK : cur?.value) : ""
          }
          onChange={(e) => {
            clearNotices();
            onChange(e.target.value);
          }}
        />
        <p className="wfield-hint" id={`h-${f.key}`}>
          {f.hint}
        </p>
        {problem && (
          <p className="wfield-problem" role="alert">
            {problem}
          </p>
        )}
        <div className="wfield-state">
          {cur === undefined ? (
            <span className="muted">nothing stored</span>
          ) : cur.value === "" ? (
            <span className="muted">stored as empty</span>
          ) : (
            <>
              <span className="badge badge-ok">stored</span>
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
  };

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>LDAP</h2>
          {/*
            ⚠️ BU METİN ESKİDEN YANLIŞTI ve yanlışlığı pahalıydı:
            "postern kullanıcının parolasını hiç görmez" diyordu. LDAP
            artık bir grup kaynağı değil, birinci sınıf kimlik
            sağlayıcı — panel kapısında kurumsal parola gerçekten
            görülüyor. Kurulum yapan kişinin bu ayrımı ekrandan okuması
            gerekiyor.
          */}
          <p className="page-sub">
            Where postern finds people, and what it is allowed to ask about
            them. When the directory is the active sign-in source it also checks
            passwords at the panel door — never for SSH, which is key-only.
            Values live in the database, and secrets are never shown again.
          </p>
        </div>
        {configured && mode === "auto" && (
          <button
            className="btn-primary"
            onClick={() => {
              clearNotices();
              setVerified(null);
              setMode("edit");
            }}
          >
            Edit directory
          </button>
        )}
      </div>

      <ErrorLine msg={error} />
      <OkLine msg={status} />
      <WarnLine msg={warning} />

      <ListState
        loading={loading}
        denied={denied}
        failed={failed}
        empty={false}
        emptyText=""
      />

      {!loading && !denied && (
        <>
          {/* ---------- 2. BEYAN ---------- */}
          {configured && mode === "auto" && (
            <>
              <div className="card">
                <div className="card-head">
                  <h3>
                    Directory configured{" "}
                    <span className="badge badge-ok">group source: ldap</span>
                  </h3>
                  <p>
                    Group membership is read from this directory at every
                    sign-in, and — when the directory is the active sign-in
                    source — passwords are checked against it too. Changes go
                    through <b>Edit directory</b>, which will not save anything
                    that has not been tested.
                  </p>
                </div>
                <div className="card-body">
                  <dl className="kv">
                    {FIELDS.map((f) => {
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

                  <div className="wizard-check">
                    <label style={{ flex: "0 0 auto" }}>
                      Look up a user (optional)
                      <input
                        value={testUser}
                        onChange={(e) => {
                          clearNotices();
                          setTestUser(e.target.value);
                        }}
                      />
                    </label>
                    <ActionButton
                      onClick={runTest}
                      label="test the stored LDAP settings"
                    >
                      Run test
                    </ActionButton>
                    <span className="note">
                      Reads what is <b>stored</b>. The name is resolved on the
                      bastion, not in your browser.
                    </span>
                  </div>

                  {test &&
                    (test.ok ? (
                      <OkLine msg="connection and bind succeeded" />
                    ) : (
                      <ErrorLine
                        msg={
                          test.error ||
                          "the bind failed and the server did not say why"
                        }
                      />
                    ))}

                  {/*
                    ⚠️ SORULAN SORUNUN CEVABI HER ZAMAN GÖSTERİLİR.
                    Eskiden blok `test.groups` doluysa çiziliyordu; bir
                    kullanıcı adı yazıp da dizinde bulunamayınca ekranda
                    yalnızca yeşil "connection and bind succeeded"
                    kalıyordu. Bağ kurulmuştu, doğruydu — ama operatörün
                    sorduğu soru o değildi. Boş cevap, cevapsızlık
                    değildir.
                  */}
                  {test?.presence === "absent" && (
                    <p className="msg msg-warn" role="status">
                      The directory answered, and it has no user matching{" "}
                      <b>{testUser}</b>. postern looks the name up with the
                      stored user filter, so a directory whose accounts are
                      named differently from the identity provider will grant no
                      groups at all — and no roles with them.
                    </p>
                  )}

                  {test?.presence === "unknown" && (
                    <p className="msg msg-warn" role="status">
                      The directory could not answer for <b>{testUser}</b>. This
                      is not the same as having no groups: nothing can be
                      concluded from it, and sync refuses to act on it.
                    </p>
                  )}

                  {!!test?.out_of_scope?.length && (
                    <p className="msg msg-warn" role="status">
                      <b>
                        {test.out_of_scope.length} group(s) are not counted
                        because they sit outside the group scope.
                      </b>{" "}
                      postern reads the group name from the first component of
                      the DN, and LDAP only guarantees that name is unique under
                      one parent — so a group of the same name in any sub-OU
                      would resolve to the same role. Only direct children of
                      the group base count. Not counted:{" "}
                      <code>{test.out_of_scope.join(", ")}</code>
                    </p>
                  )}

                  {test?.presence === "present" && (
                    <dl className="kv">
                      <dt>groups</dt>
                      <dd>{test.groups?.join(", ") || "none"}</dd>
                      <dt>mapped to roles</dt>
                      <dd>{test.roles?.join(", ") || "none"}</dd>
                      <dt>unmapped</dt>
                      <dd>{test.unmapped?.join(", ") || "none"}</dd>
                      {/*
                        ⚠️ Kararlı kimlik, HENÜZ hiçbir yetki kararına
                        bağlı değil — ama bağlanmadan önce operatörün
                        kendi dizininde gerçekten geldiğini görmesi
                        gerekiyor. Sonradan "boş çıkıyormuş" diye
                        öğrenmek, bağlamanın açıldığı gün herkesin
                        kapıda kalması demek.
                      */}
                      <dt>stable identity</dt>
                      <dd>
                        {test.identity ? (
                          <code>{test.identity}</code>
                        ) : test.identity_error ? (
                          <span className="msg msg-warn">
                            the directory returned one but postern could not
                            read it — {test.identity_error}
                          </span>
                        ) : (
                          <span className="muted">
                            none — this directory (or this service account) does
                            not expose objectGUID or entryUUID
                          </span>
                        )}
                      </dd>
                    </dl>
                  )}
                </div>
              </div>

              {/* ⚠️ Dizin kurulduktan SONRA gelen soru: bu dizinde
                  kim yönetici? Ayrı bir kart, çünkü diğer alanlardan
                  farklı bir şey yapıyor — yetki dağıtıyor. */}
              <AdminGroup meName={meName} />

              <SyncPanel ldapReady />
            </>
          )}

          {/* ---------- 3. DÜZENLEME ---------- */}
          {mode === "edit" && (
            <div className="panel">
              <h3>Edit directory</h3>
              <p className="note">
                Nothing is written until a test against these exact values
                succeeds. These settings decide who gets in, and saving a broken
                one cuts off everyone — including whoever has to fix it.
              </p>

              <div className="wizard-form">
                {FIELDS.map((f) =>
                  renderField(f, editValue(f.key), (v) => {
                    setEdits({ ...edits, [f.key]: v });
                    // Değer değişti: önceki sınama artık bu
                    // yapılandırmaya ait değil.
                    setVerified(null);
                  }),
                )}

                <div className="wizard-check">
                  <label style={{ flex: "0 0 auto" }}>
                    Look up a user (optional)
                    <input
                      value={testUser}
                      onChange={(e) => setTestUser(e.target.value)}
                    />
                  </label>
                  <ActionButton onClick={verify} label="test these values">
                    Test these values
                  </ActionButton>
                  <span className="note">
                    Tests what is typed here, without saving it. The name is
                    resolved on the bastion, not in your browser.
                  </span>
                </div>

                {verified &&
                  (verified.result.ok ? (
                    <OkLine msg="these values work — you can save them now" />
                  ) : (
                    <>
                      <ErrorLine
                        msg={
                          verified.result.error ||
                          "the directory refused and did not say why"
                        }
                      />
                      {looksLikeDNS(verified.result.error) && (
                        <p className="note">
                          postern could not resolve that name. It looks it up
                          from the bastion, not from your browser — a name that
                          works on your machine may not exist there.
                        </p>
                      )}
                    </>
                  ))}

                {verified?.result.groups && (
                  <dl className="kv">
                    <dt>groups</dt>
                    <dd>{verified.result.groups.join(", ") || "—"}</dd>
                    <dt>mapped to roles</dt>
                    <dd>{verified.result.roles?.join(", ") || "—"}</dd>
                    <dt>unmapped</dt>
                    <dd>{verified.result.unmapped?.join(", ") || "—"}</dd>
                  </dl>
                )}
              </div>

              <div className="wizard-nav">
                <button
                  onClick={() => {
                    setEdits({});
                    setVerified(null);
                    clearNotices();
                    setMode("auto");
                  }}
                >
                  Cancel
                </button>
                <span className="spacer" />
                <ActionButton
                  variant="primary"
                  onClick={saveEdit}
                  // ⚠️ SINANMADAN KAYDEDİLEMEZ — ve sınama BU değerlere
                  // ait olmalı. İmza değiştiyse damga başka bir
                  // yapılandırmaya aitti.
                  disabled={!verifiedNow}
                  label="save the tested configuration"
                >
                  {verifiedNow
                    ? "Save tested configuration"
                    : "Test before saving"}
                </ActionButton>
              </div>
            </div>
          )}

          {/* ---------- 1. SİHİRBAZ ---------- */}
          {!configured && mode === "auto" && (
            <>
              {items.length === 0 && (
                <p className="note">
                  Nothing stored yet. Until <code>ldap.url</code> is set,
                  postern cannot ask this directory anything — group membership
                  falls back to whatever the identity provider puts in the
                  token.
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
                    {problems.length > 0 ? (
                      <div className="msg msg-warn" role="status">
                        <b>Not ready yet</b>
                        <ul className="problem-list">
                          {problems.map((p) => (
                            <li key={p}>{p}</li>
                          ))}
                        </ul>
                      </div>
                    ) : (
                      <OkLine msg="every field the server requires is stored" />
                    )}

                    <dl className="kv">
                      {FIELDS.map((f) => {
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
                  </>
                ) : (
                  <div className="wizard-form">
                    {stepFields.map((f) =>
                      renderField(f, edits[f.key] ?? "", (v) =>
                        setEdits({ ...edits, [f.key]: v }),
                      ),
                    )}

                    {current.id === "connection" && (
                      <div className="wizard-check">
                        <ActionButton
                          onClick={checkConnection}
                          disabled={!hasValue("ldap.url")}
                          label="test the stored connection and service account"
                        >
                          Test connection
                        </ActionButton>
                        <span className="note">
                          Dials the directory and binds as the service account.
                          Reads what is <b>stored</b>, so save first. The name
                          is resolved <b>on the bastion</b>, not in your
                          browser.
                        </span>
                      </div>
                    )}

                    {conn &&
                      (conn.ok ? (
                        <OkLine msg="reached the directory and bound as the service account" />
                      ) : (
                        <>
                          <ErrorLine
                            msg={
                              conn.error ||
                              "the bind failed and the server did not say why"
                            }
                          />
                          {looksLikeDNS(conn.error) && (
                            <p className="note">
                              postern could not resolve that name. It looks it
                              up from the bastion, not from your browser — a
                              name that works on your machine may not exist
                              there.
                            </p>
                          )}
                        </>
                      ))}
                  </div>
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
                  {stepFields.length > 0 && (
                    <ActionButton
                      variant="primary"
                      onClick={() =>
                        saveKeys(current.keys).then((ok) => {
                          if (ok && next) setStep(next.id);
                        })
                      }
                      disabled={stepHasProblem}
                      label={`save this step${next ? " and continue" : ""}`}
                    >
                      {next ? "Save and continue" : "Save"}
                    </ActionButton>
                  )}
                  {stepFields.length === 0 && next && (
                    <button onClick={() => setStep(next.id)}>Continue</button>
                  )}
                </div>
              </div>

              {/* Sihirbaz sürerken de görünüyor: senkronizasyonun var
                  olduğunu LDAP kurulduktan SONRA öğrenmek, "kurdum,
                  bitti" sanan operatörü geç uyarmak olurdu. */}
              <SyncPanel ldapReady={configured} />
            </>
          )}
        </>
      )}

      {/*
        ⚠️ KİMLİK KAYNAĞINDAN BAĞIMSIZ GÖSTERİLİYOR.
        Arşiv, LDAP/OIDC sihirbazının bir adımı değil: yerel kimlikle
        çalışan bir kurulumun da kayıtları dışarı yazması gerekiyor.
        Sihirbazın içine koymak, o kurulumlarda ekranı hiç
        göstermemek olurdu.
      */}
      <ArchiveCredential />
    </section>
  );
}
