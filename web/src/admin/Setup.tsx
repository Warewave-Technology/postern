import { useEffect, useState } from "react";
import { AuthSourceStatus, OIDCSettings, Setting, api, toMessage } from "../api";
import { ActionButton, ErrorLine, OkLine } from "./common";
import AdminGroup from "./AdminGroup";
import Mappings from "./Mappings";
import Settings from "./Settings";

/**
 * İlk kurulum sihirbazı.
 *
 * ⚠️ VAR OLMA SEBEBİ, SIRALAMA. Bu adımlar ayrı ayrı da yapılabilir ve
 * ekranları zaten var; ama YANLIŞ SIRADA yapıldıklarında kurulumu yapan
 * kişi kendini dışarıda bırakıyor:
 *
 *   kaynağı çevir → yerel kapı kapanır → kendi hesabı yönetici olduğu
 *   için ad eşleşmesiyle devralınamaz → geri giremez
 *
 * Sihirbazın asıl işi bu sırayı zorlamak: önce dizini kur, sonra
 * yönetici grubunu seç, sonra eşlemeleri yap, SONRA kendi kimliğini
 * bağla, EN SON kaynağı çevir.
 */

type StepID = "source" | "configure" | "admins" | "mapping" | "activate";

const STEPS: { id: StepID; title: string }[] = [
  { id: "source", title: "Sign-in source" },
  { id: "configure", title: "Configure it" },
  { id: "admins", title: "Administrators" },
  { id: "mapping", title: "Groups and roles" },
  { id: "activate", title: "Link yourself, then switch" },
];

const SOURCE_LABEL: Record<string, string> = {
  local: "postern's own credentials",
  oidc: "Identity provider (OIDC)",
  ldap: "Directory (LDAP)",
};

export default function Setup({
  meName,
  dirBound = false,
}: {
  meName?: string;
  /** Hesap zaten bir dizin kimliğine bağlıysa bağlama adımı geçilmiş
   *  sayılır: bağlama ucu haklı olarak çatışma dönerdi ve operatör
   *  ilerleyemeyeceği bir duvara dayanırdı. */
  dirBound?: boolean;
}) {
  const [status, setStatus] = useState<AuthSourceStatus | null>(null);
  const [settings, setSettings] = useState<Setting[]>([]);
  const [choice, setChoice] = useState<string>("");
  const [step, setStep] = useState<StepID>("source");
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  // Kendi dizin kimliğini bağlama.
  const [dirUser, setDirUser] = useState("");
  const [dirPass, setDirPass] = useState("");
  const [linked, setLinked] = useState("");
  const alreadyLinked = dirBound || linked !== "";

  const [autoCreate, setAutoCreate] = useState(false);

  // OIDC ayarları artık veritabanında ve panelden yazılıyor.
  const [oidcState, setOidcState] = useState<OIDCSettings | null>(null);
  const [oidcResult, setOidcResult] = useState("");
  const [oidc, setOidc] = useState({ issuer: "", clientID: "", secret: "" });

  // "All is set" ekranı ve ana sayfaya dönüş.
  const [finished, setFinished] = useState(false);

  const load = () =>
    Promise.all([api.authSource(), api.settings(), api.oidcSettings()])
      .then(([st, se, oi]) => {
        setStatus(st);
        setSettings(se);
        setOidcState(oi);
        setOidc((cur) =>
          cur.issuer === "" && cur.clientID === ""
            ? { issuer: oi.issuer_url, clientID: oi.client_id, secret: "" }
            : cur,
        );
        if (choice === "") setChoice(st.source);
        const ac = se.find((x) => x.key === "auth.auto_create");
        setAutoCreate(ac?.value === "true");
      })
      .catch((e: unknown) => setError(toMessage(e)));

  useEffect(() => {
    void load();
    // yalnızca ilk çizimde
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const idx = STEPS.findIndex((s) => s.id === step);
  const eligible = status?.options.find((o) => o.source === choice);
  const adminGroup = settings.find((s) => s.key === "ldap.admin_group")?.value ?? "";

  const setAuto = (on: boolean) =>
    api
      .setSetting("auth.auto_create", on ? "true" : "false")
      .then(() => {
        setAutoCreate(on);
        return load();
      })
      .catch((e: unknown) => setError(toMessage(e)));

  const saveOIDC = () => {
    setError("");
    setOidcResult("");
    return api
      .setOIDCSettings(
        oidc.issuer.trim(),
        oidc.clientID.trim(),
        // ⚠️ Boş bırakılmışsa GÖNDERİLMİYOR: boş dize "temizle" demek
        // değil, "değiştirme" demek.
        oidc.secret === "" ? undefined : oidc.secret,
      )
      .then((r) => {
        if (!r.live) setOidcResult(r.error);
        setOidc({ ...oidc, secret: "" });
        return load();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const link = () =>
    api
      .bindOwnDirectory(dirUser.trim(), dirPass)
      .then((r) => {
        setLinked(r.identity);
        setDirPass("");
        setError("");
      })
      .catch((e: unknown) => setError(toMessage(e)));

  const activate = () =>
    api
      .setAuthSource(choice)
      .then((r) => {
        setDone(r.note);
        return api.completeSetup();
      })
      .then(() => {
        setFinished(true);
        /*
         * ⚠️ TAM SAYFA YENİLEME, yönlendirme değil.
         *
         * /api/me artık setup_required=false diyecek ve uygulamanın
         * kabuğu ona göre çizilecek. React durumunu elle "kurulum
         * bitti"ye çevirmek, sunucunun söylediğiyle ekranın gösterdiği
         * arasında ikinci bir doğruluk kaynağı yaratırdı.
         */
        setTimeout(() => window.location.assign("/"), 3000);
      })
      .catch((e: unknown) => setError(toMessage(e)));

  /*
   * ⚠️ BİTİŞ EKRANI HER ŞEYİN YERİNE GEÇİYOR.
   *
   * Sihirbaz bittiğinde arkasındaki adımlar hâlâ dururken bir başarı
   * satırı göstermek, operatöre "bitti mi, devam mı" diye sordurur.
   * Ekran tek bir şey söylüyor ve üç saniye sonra uygulamaya geçiyor.
   */
  if (finished) {
    return (
      <section className="setup-done" role="status" aria-live="polite">
        <svg
          viewBox="0 0 64 64"
          className="setup-check"
          aria-hidden="true"
          width="72"
          height="72"
        >
          <circle cx="32" cy="32" r="28" />
          <path d="M20 33.5 28.5 42 45 24" />
        </svg>
        <h2>All is set</h2>
        <p>
          postern is configured and ready. Taking you to the app…
        </p>
      </section>
    );
  }

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Set up sign-in</h2>
          <p className="page-sub">
            These steps exist in their own screens too. They are here in this
            order because doing them in another one locks you out: switching the
            source closes the door you came in through, and an administrator
            account cannot be claimed later just by matching its name.
          </p>
        </div>
      </div>

      <ErrorLine msg={error} />
      <OkLine msg={done} />

      <div className="steps">
        {STEPS.map((s, i) => (
          <button
            key={s.id}
            className={`step${i < idx ? " step-done" : ""}`}
            aria-current={s.id === step ? "step" : undefined}
            onClick={() => setStep(s.id)}
          >
            <span className="step-n" aria-hidden="true">
              {i < idx ? "✓" : i + 1}
            </span>
            {s.title}
          </button>
        ))}
      </div>

      {step === "source" && status && (
        <div className="panel">
          <h3>Which source opens the panel?</h3>
          <p className="note">
            Only one at a time. Choosing one closes the others — SSH is not
            affected: server access is proved with a key.
          </p>
          {status.options.map((o) => (
            <label className="source-row" key={o.source}>
              <div>
                <input
                  type="radio"
                  name="src"
                  checked={choice === o.source}
                  onChange={() => setChoice(o.source)}
                />{" "}
                <b>{SOURCE_LABEL[o.source] ?? o.source}</b>
                {!o.eligible && (
                  <p className="msg msg-warn" role="status">
                    {o.why}
                  </p>
                )}
              </div>
            </label>
          ))}
          <div className="wizard-nav">
            <span className="spacer" />
            <button className="btn-primary" onClick={() => setStep("configure")}>
              Continue
            </button>
          </div>
        </div>
      )}

      {step === "configure" && (
        <>
          {choice === "ldap" && <Settings meName={meName} />}
          {choice === "oidc" && (
            <div className="panel">
              <h3>Identity provider</h3>
              <div className="wizard-form">
                <div className="wfield">
                  <label className="wfield-label" htmlFor="oidc-issuer">
                    Issuer address
                  </label>
                  <input
                    id="oidc-issuer"
                    value={oidc.issuer}
                    placeholder="https://idp.example/realms/company"
                    onChange={(e) => setOidc({ ...oidc, issuer: e.target.value })}
                  />
                  <p className="wfield-hint">
                    postern reads{" "}
                    <code>&lt;issuer&gt;/.well-known/openid-configuration</code>{" "}
                    from here. Plain http:// is only accepted for loopback.
                  </p>
                </div>
                <div className="wfield">
                  <label className="wfield-label" htmlFor="oidc-client">
                    Client id
                  </label>
                  <input
                    id="oidc-client"
                    value={oidc.clientID}
                    onChange={(e) => setOidc({ ...oidc, clientID: e.target.value })}
                  />
                </div>
                <div className="wfield">
                  <label className="wfield-label" htmlFor="oidc-secret">
                    Client secret
                  </label>
                  <input
                    id="oidc-secret"
                    type="password"
                    value={oidc.secret}
                    placeholder={oidcState?.client_secret_set ? "••••••••" : ""}
                    onChange={(e) => setOidc({ ...oidc, secret: e.target.value })}
                  />
                  {/*
                    ⚠️ Sır geri OKUNMUYOR ve boş bırakmak "değiştirme"
                    demek. Boşu "temizle" saymak, sırsız public client
                    kurulumunu kazayla silmenin yolu olurdu.
                  */}
                  <p className="wfield-hint">
                    Stored encrypted and never shown again. Leave empty to keep
                    the current one. A public client using PKCE has none.
                  </p>
                </div>
                <div className="wizard-check">
                  <ActionButton
                    onClick={saveOIDC}
                    disabled={!oidc.issuer.trim() || !oidc.clientID.trim()}
                    label="save and contact the identity provider"
                  >
                    Save and test
                  </ActionButton>
                  <span className="note">
                    Saved first, then contacted. If it cannot be reached the
                    settings are still kept — otherwise you could never fix an
                    provider that is down.
                  </span>
                </div>
                {oidcState &&
                  (oidcState.live ? (
                    <OkLine msg="reached the identity provider and read its configuration" />
                  ) : oidcState.configured ? (
                    <ErrorLine
                      msg={
                        oidcResult ||
                        "saved, but postern could not reach the provider yet"
                      }
                    />
                  ) : null)}
              </div>
              {/*
                ⚠️ GRUP CLAIM'İ. postern grupları token'dan okuyor; IdP
                onu göndermiyorsa herkes gruplu görünmez ve hiçbir rol
                eşleşmez. Bu, kurulumda en sık kaçırılan adım.
              */}
              <div className="msg msg-warn" role="status">
                <b>Your identity provider has to send group names.</b> postern
                reads them from the token — if the claim is missing, everyone
                arrives with no groups, matches no mapping and reaches nothing.
                <ul className="problem-list">
                  <li>
                    Keycloak: add a <b>Group Membership</b> mapper to the
                    postern client, name the claim <code>groups</code>, and turn
                    off &ldquo;Full group path&rdquo; unless your mappings use
                    full paths.
                  </li>
                  <li>
                    Entra ID / Azure AD: add the <b>groups</b> claim to the
                    token. It emits object ids by default — either map those ids
                    or switch the claim to group names.
                  </li>
                  <li>
                    Okta: add a <b>groups</b> claim to the ID token with a
                    filter that matches the groups you intend to map.
                  </li>
                </ul>
                Whatever the claim is called, set{" "}
                <code>oidc.groups_claim</code> to match it.
              </div>
              <p className="note">
                Anyone whose source answers but names no group lands in the{" "}
                <code>unknown</code> group, so you can map that and not leave
                them stranded while you sort the claim out.
              </p>
            </div>
          )}
          {choice === "local" && (
            <div className="panel">
              <h3>postern&apos;s own credentials</h3>
              <p className="note">
                Nothing to configure. Accounts are created on the bastion host
                with <code>postern user add</code>, and administrators with{" "}
                <code>postern admin issue</code>. Only those accounts can be
                administrators — there is no group to inherit it from.
              </p>
            </div>
          )}
          <div className="wizard-nav">
            <button onClick={() => setStep("source")}>Back</button>
            <span className="spacer" />
            <button className="btn-primary" onClick={() => setStep("admins")}>
              Continue
            </button>
          </div>
        </>
      )}

      {step === "admins" && (
        <>
          {choice === "local" ? (
            <div className="panel">
              <h3>Administrators</h3>
              <p className="note">
                With local sign-in, administrator comes only from the bastion
                host: <code>postern admin issue &lt;name&gt;</code>. Nobody can
                grant it from this panel, and there is no group to inherit it
                from.
              </p>
            </div>
          ) : (
            <>
              {/*
                ⚠️ Dizin/IdP kaynağında yönetici grubu ZORUNLU — kaynağı
                çevirme ucu da onsuz geçmiyor. Sebebi: o modda yöneticilik
                yalnızca gruptan geliyor; grup yoksa kimse yönetemez.
              */}
              {adminGroup === "" && (
                <p className="msg msg-warn" role="alert">
                  <b>An administrator group is required.</b> In this mode
                  administrator comes only from a group, so without one nobody
                  could administer postern — and switching will be refused.
                </p>
              )}
              <AdminGroup meName={meName} />
            </>
          )}
          <div className="wizard-nav">
            <button onClick={() => setStep("configure")}>Back</button>
            <span className="spacer" />
            <button className="btn-primary" onClick={() => setStep("mapping")}>
              Continue
            </button>
          </div>
        </>
      )}

      {step === "mapping" && (
        <>
          <div className="panel">
            <h3>Do accounts open on their own?</h3>
            {/*
              ⚠️ Bu anahtar eşlemenin YERİNE geçmiyor. Kapalıyken de
              eşleme şart: onayladığınız kişinin rolleri oradan geliyor.
            */}
            <label className="source-row">
              <div>
                <input
                  type="radio"
                  name="auto"
                  checked={!autoCreate}
                  onChange={() => setAuto(false)}
                />{" "}
                <b>No — put them in a queue</b>
                <p className="note">
                  Someone the source authenticates but postern does not know is
                  told their account is waiting, and appears under{" "}
                  <b>Pending</b>.
                </p>
              </div>
            </label>
            <label className="source-row">
              <div>
                <input
                  type="radio"
                  name="auto"
                  checked={autoCreate}
                  onChange={() => setAuto(true)}
                />{" "}
                <b>Yes — create the account</b>
                <p className="note">
                  Still only when at least one of their groups is mapped below.
                  An account that reaches nothing is not access.
                </p>
              </div>
            </label>
          </div>

          {/*
            ⚠️ Eşleme, yukarıdaki anahtardan BAĞIMSIZ olarak gerekli:
            kuyruktan onayladığınız kişinin rolleri de buradan geliyor.
          */}
          <p className="note">
            Mapping is needed either way. It is what turns a group in your
            source into access here — including for people you approve by hand.
          </p>
          <Mappings />

          <div className="wizard-nav">
            <button onClick={() => setStep("admins")}>Back</button>
            <span className="spacer" />
            <button className="btn-primary" onClick={() => setStep("activate")}>
              Continue
            </button>
          </div>
        </>
      )}

      {step === "activate" && (
        <div className="panel">
          <h3>Link yourself, then switch</h3>

          {choice === "ldap" && (
            <>
              {/*
                ⚠️ SİHİRBAZIN ASIL ADIMI. Kaynağı çevirmek yerel kapıyı
                kapatıyor; kendi dizin kimliğinizi önceden bağlamazsanız
                geri giremezsiniz — hesabınız yönetici olduğu için ad
                eşleşmesiyle de devralınamaz.
              */}
              <p className="note">
                Switching closes the door you came in through. Prove your
                directory account <b>now</b>, while you are still signed in:
                postern links it to <b>{meName}</b> and you keep your way back.
              </p>
              {alreadyLinked ? (
                <OkLine
                  msg={
                    linked
                      ? `linked to directory identity ${linked} — you can switch safely`
                      : "your account is already linked to a directory identity — you can switch safely"
                  }
                />
              ) : (
                <div className="wizard-form">
                  <div className="wfield">
                    <label className="wfield-label" htmlFor="dir-user">
                      Your directory username
                    </label>
                    <input
                      id="dir-user"
                      value={dirUser}
                      onChange={(e) => setDirUser(e.target.value)}
                    />
                  </div>
                  <div className="wfield">
                    <label className="wfield-label" htmlFor="dir-pass">
                      Your directory password
                    </label>
                    <input
                      id="dir-pass"
                      type="password"
                      autoComplete="current-password"
                      value={dirPass}
                      onChange={(e) => setDirPass(e.target.value)}
                    />
                    <p className="wfield-hint">
                      Checked against the directory and never stored. This links
                      your account to the identity the directory publishes, so a
                      later rename there does not lock you out.
                    </p>
                  </div>
                  <ActionButton
                    onClick={link}
                    disabled={!dirUser.trim() || !dirPass}
                    label="link my directory account"
                  >
                    Link my account
                  </ActionButton>
                </div>
              )}
            </>
          )}

          {choice === "oidc" && (
            <p className="msg msg-warn" role="status">
              <b>There is no way to prove an OIDC identity before switching</b>{" "}
              — that door is closed until the switch happens. So postern leaves
              a single-use permission on your account instead: the first sign-in
              through the identity provider as <b>{meName}</b> claims it. Do it
              immediately after switching, and check <b>Admin log</b> to see
              which identity took it.
            </p>
          )}

          {eligible && !eligible.eligible && (
            <p className="msg msg-warn" role="alert">
              {eligible.why}
            </p>
          )}

          <div className="wizard-nav">
            <button onClick={() => setStep("mapping")}>Back</button>
            <span className="spacer" />
            <ActionButton
              variant="primary"
              disabled={
                !eligible?.eligible || (choice === "ldap" && !alreadyLinked)
              }
              label="switch the panel to this source"
              confirm={
                `Switch panel sign-in to ${SOURCE_LABEL[choice] ?? choice}?\n\n` +
                `Every other sign-in method closes.\n\n` +
                `To undo this from the bastion host:\n` +
                `  postern settings set --key auth.source --value local`
              }
              onClick={activate}
            >
              {choice === "ldap" && !alreadyLinked
                ? "Link your account first"
                : "Switch now"}
            </ActionButton>
          </div>
        </div>
      )}
    </section>
  );
}
