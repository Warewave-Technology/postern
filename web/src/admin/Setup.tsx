import { useEffect, useState } from "react";
import { AuthSourceStatus, Setting, api, toMessage } from "../api";
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

export default function Setup({ meName }: { meName?: string }) {
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

  const [autoCreate, setAutoCreate] = useState(false);

  const load = () =>
    Promise.all([api.authSource(), api.settings()])
      .then(([st, se]) => {
        setStatus(st);
        setSettings(se);
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
        return load();
      })
      .catch((e: unknown) => setError(toMessage(e)));

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
              <p className="note">
                The issuer, client id and secret come from the config file
                (<code>oidc.*</code>) and a restart, not from this panel: they
                decide who postern trusts, and a panel that can change them can
                change who it trusts.
              </p>
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
              {linked ? (
                <OkLine
                  msg={`linked to directory identity ${linked} — you can switch safely`}
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
                !eligible?.eligible || (choice === "ldap" && linked === "")
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
              {choice === "ldap" && linked === ""
                ? "Link your account first"
                : "Switch now"}
            </ActionButton>
          </div>
        </div>
      )}
    </section>
  );
}
