import { useCallback, useEffect, useRef, useState } from "react";
import {
  IssuedCredential,
  Role,
  UserDetail as Detail,
  api,
  toMessage,
} from "../api";
import { ActionButton, ErrorLine, OkLine, useList } from "./common";
import { BackIcon } from "../icons";

/**
 * Tek bir kullanıcının sayfası.
 *
 * ⚠️ NEDEN VAR: liste dokuz sütuna çıkmıştı ve her satırda üç ayrı
 * eylem taşıyordu — rol atama kutusu, aktifleştirme, anahtar paneli,
 * sıfırlama, silme. Bir liste "kimler var ve durumları ne" sorusunu
 * cevaplamalı; tek bir kişi üzerinde yapılacak işler o kişinin
 * sayfasına ait. Aynı karar hedeflerde zaten verilmişti
 * (TargetDetail); burası onun eşi ve bilerek aynı iskelet.
 */
export default function UserDetail({
  name,
  publicKeyLogin,
  localSource,
  onBack,
}: {
  name: string;
  publicKeyLogin: boolean;
  localSource: boolean;
  onBack: () => void;
}) {
  const [u, setU] = useState<Detail | null>(null);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const [loading, setLoading] = useState(true);

  const roles = useList<Role>(api.roles);
  const [pick, setPick] = useState("");
  const [keyText, setKeyText] = useState("");
  const [issued, setIssued] = useState<IssuedCredential | null>(null);
  const [editing, setEditing] = useState(false);
  const [osUser, setOsUser] = useState("");
  const [email, setEmail] = useState("");
  const issuedRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!issued) return;
    // Kaydırma bir İYİLEŞTİRME: olmayan bir ortamda (jsdom, eski
    // tarayıcı) render'ı düşürmemeli. Odak asıl iş ve o her yerde var.
    issuedRef.current?.scrollIntoView?.({ block: "start", behavior: "smooth" });
    issuedRef.current?.focus();
  }, [issued]);

  const load = useCallback(() => {
    setLoading(true);
    return api
      .userDetail(name)
      .then((v) => {
        setU(v);
        setOsUser(v.os_user);
        setEmail(v.email);
        setError("");
      })
      .catch((e: unknown) => setError(toMessage(e)))
      .finally(() => setLoading(false));
  }, [name]);

  useEffect(() => {
    load();
  }, [load]);

  /*
   * run, bir yönetim eylemini çalıştırır ve sonucu ekrana yazar.
   *
   * ⚠️ BAŞARI GERİ ÇAĞRISI VAR ve gerekli: run'ın kendisi hata
   * durumunda da BAŞARIYLA çözülüyor (catch hatayı yutup ekrana
   * yazıyor). Dolayısıyla `run(...).then(() => setKeyText(""))` yazmak,
   * SUNUCU REDDETTİĞİNDE de kutuyu temizlerdi — yani yapıştırılan
   * anahtar, "bu anahtar geçersiz" hatasıyla birlikte yok olurdu ve
   * kullanıcı düzeltecek metni kaybederdi.
   */
  const run = (p: Promise<unknown>, msg: string, onOk?: () => void) => {
    setOk("");
    setError("");
    return p
      .then(() => {
        setOk(msg);
        onOk?.();
        return load();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const state = u?.state ?? "active";
  const unassigned = roles.items.filter(
    (r) => !(u?.roles ?? []).some((have) => have.name === r.name),
  );

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <button className="btn-quiet back-link" onClick={onBack}>
            <BackIcon />
            All users
          </button>
          <h2>{name}</h2>
          <p className="page-sub">
            Everything postern knows about this account — what it reaches, how
            it proves who it is, and what it has been doing.
          </p>
        </div>
        <ActionButton
          variant="danger"
          onClick={() =>
            api
              .deleteUser(name)
              // Silinen hesabın sayfasında kalmak anlamsız: listeye dön.
              .then(onBack)
              .catch((e: unknown) => setError(toMessage(e)))
          }
          confirm={`Delete the user "${name}"? Their SSH keys and role assignments go with them. If ${name} has recorded sessions the server refuses this outright — revoking their keys and roles is how access is cut without losing the audit trail.`}
          label={`delete user ${name}`}
        >
          Delete user
        </ActionButton>
      </div>

      <ErrorLine msg={error} />
      <OkLine msg={ok} />

      {/*
        ⚠️ VERİLEN DEĞER KUTUSU, BİLDİRİM SATIRI DEĞİL.
        Değer bir daha gösterilemiyor; kaybolan bir satırda duramaz.
      */}
      {issued && (
        /*
          ⚠️ KUTU GÖRÜNÜR ALANA KAYDIRILIYOR ve odak ona geçiyor.

          Sayfa uzun ve düğme aşağıda: kutu sayfanın BAŞINA çiziliyor,
          yani düğmeye basan kişi ekranında hiçbir şey değişmediğini
          görüyordu. Bir daha üretilemeyen bir değer için "belki
          yukarıdadır" yeterli değil.
        */
        <div className="issued-card" ref={issuedRef} tabIndex={-1}>
          <h3>
            New sign-in value for <b>{issued.username}</b>
          </h3>
          <p>
            {issued.replaced
              ? "Anything they held before no longer works, and their open panel sessions were dropped."
              : "This account had no credential before; it can sign in to the panel with this."}
          </p>
          <pre className="issued-secret">{issued.secret}</pre>
          <p className="msg warn">
            This is the only time it is shown. postern stores a verifier, not
            the value — it cannot be looked up or printed again. They must
            choose their own password before the panel opens for them.
          </p>
          <button className="btn btn-primary" onClick={() => setIssued(null)}>
            I have copied it
          </button>
        </div>
      )}

      {loading && !u && <p className="state">Loading…</p>}

      {u && (
        <div className="detail-grid">
          <div className="detail-main">
            <div className="card">
              <div className="card-head">
                <h3>Account</h3>
                <p>Who this is, and how postern found out.</p>
              </div>
              <div className="card-body">
                <dl className="kv">
                  <dt>OS user</dt>
                  <dd>
                    <code>{u.os_user}</code>
                  </dd>
                  <dt>Email</dt>
                  <dd>{u.email || "—"}</dd>
                  <dt>&nbsp;</dt>
                  <dd>
                    {/*
                      ⚠️ İKİSİ DE DÜZELTİLEBİLİR OLMAK ZORUNDA.

                      Uç (PATCH) ve denetim satırı ilk günden vardı,
                      panelde çağıran yoktu: yanlış yazılmış bir OS
                      kullanıcısını ya da e-postayı düzeltmek için
                      host'a girmek gerekiyordu. İkisi de kimlik
                      EŞLEŞTİRME anahtarı — e-posta OIDC eşleşmesinde,
                      os_user hedefteki hesapta — yani yazım hatası
                      sessiz bir erişim sorunu demek.
                    */}
                    <ActionButton
                      onClick={() => setEditing(!editing)}
                      label={editing ? "Cancel editing" : "Edit these details"}
                    >
                      {editing ? "Cancel" : "Edit"}
                    </ActionButton>
                  </dd>
                  <dt>Administrator</dt>
                  <dd>
                    {u.admin ? (
                      <>
                        <span className="badge badge-accent">admin</span>{" "}
                        {/*
                          ⚠️ KAYNAK YAZILI. Grup üzerinden gelen yetki ile
                          acil durum için elle açılmış hesap ekranda ayırt
                          edilemezse, operatör kaldıramayacağı bir yetkiyi
                          kaldırabileceğini sanır.
                        */}
                        <span className="muted small">
                          {u.admin_via === "group"
                            ? "from the directory group — remove them from it to take it away"
                            : u.admin_via === "cli"
                              ? "granted on the host; only the host can take it away"
                              : "source unknown (granted before postern recorded it)"}
                        </span>
                      </>
                    ) : (
                      <span className="muted">no</span>
                    )}
                  </dd>
                  <dt>Identity</dt>
                  <dd>
                    {u.dir_bound
                      ? "bound to a directory entry"
                      : u.sso_only
                        ? "signs in through the identity provider only"
                        : "local to this bastion"}
                  </dd>
                </dl>
                {editing && (
                  <div className="wizard-form" style={{ marginTop: "0.9rem" }}>
                    <div className="wfield">
                      <label className="wfield-label" htmlFor="u-osuser">
                        OS user
                      </label>
                      <input
                        id="u-osuser"
                        value={osUser}
                        onChange={(e) => setOsUser(e.target.value)}
                      />
                      <p className="wfield-hint">
                        The account postern opens on the target host. Not the
                        name they sign in with.
                      </p>
                    </div>
                    <div className="wfield">
                      <label className="wfield-label" htmlFor="u-email">
                        Email
                      </label>
                      <input
                        id="u-email"
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                      />
                      <p className="wfield-hint">
                        Used to match an identity provider account when it sends
                        no username. Empty clears it.
                      </p>
                    </div>
                    <div className="wizard-check">
                      <ActionButton
                        variant="primary"
                        disabled={osUser.trim() === ""}
                        onClick={() =>
                          run(
                            api.patchUser(name, {
                              os_user: osUser.trim(),
                              email: email.trim(),
                            }),
                            "details saved",
                            () => setEditing(false),
                          )
                        }
                        label="Save these details"
                      >
                        Save
                      </ActionButton>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="card">
              <div className="card-head">
                <h3>Access</h3>
                <p>
                  Whether this account can sign in at all. A source that stops
                  confirming somebody deactivates them on its own.
                </p>
              </div>
              <div className="card-body">
                <dl className="kv">
                  <dt>State</dt>
                  <dd>
                    {state === "active" ? (
                      "active"
                    ) : (
                      <span className="badge badge-warn">{state}</span>
                    )}
                  </dd>
                  <dt>Last confirmed</dt>
                  <dd>
                    {u.last_confirmed
                      ? new Date(u.last_confirmed).toLocaleString()
                      : "never"}
                  </dd>
                </dl>
                <div className="field-row" style={{ marginTop: "0.9rem" }}>
                  {/*
                    ⚠️ REACTIVATE, 'deleted' HÂLİNDE DE ÇİZİLİYOR.
                    Koşul bir ara `state !== "deleted"` yazılmıştı ve
                    sonucu şuydu: yaşam döngüsü işinin kendiliğinden
                    sildiği bir hesabın sayfasında GERİ DÖNÜŞSÜZ olan
                    tek düğme kalıyordu. Store bunun tersini açıkça
                    söylüyor (accountstate.go): "'deleted'ten 'active'e
                    dönüş SERBEST: yanlışlıkla silinmiş bir hesabın geri
                    gelememesi, tek tıkla kalıcı bir kayıp demekti."
                  */}
                  {state !== "active" ? (
                    <ActionButton
                      onClick={() =>
                        run(api.setUserState(name, "active"), "reactivated")
                      }
                      /*
                       * ⚠️ SİLİNMİŞ HESABI GERİ AÇMAK BİR MUAFİYET
                       * DEĞİL. Hesabı silen şey kaynağın onu artık
                       * doğrulamaması; kaynak hâlâ doğrulamıyorsa yaşam
                       * döngüsü işi onu yeniden kapatır. CLI aynı şeyi
                       * söylüyor (cmd/postern/user.go) ve panelin
                       * sessiz kalması, yöneticiye sorunu çözdüğünü
                       * sandırırdı.
                       */
                      confirm={
                        state === "deleted"
                          ? `Reactivate ${name}?\n\n` +
                            `They can sign in again. If the source still does not confirm ` +
                            `them, the lifecycle job will deactivate them once more — fix ` +
                            `it at the source, or this is only a reprieve.`
                          : undefined
                      }
                      label={`reactivate ${name}`}
                    >
                      Reactivate
                    </ActionButton>
                  ) : (
                    <ActionButton
                      variant="danger"
                      onClick={() =>
                        run(api.setUserState(name, "inactive"), "deactivated")
                      }
                      /*
                       * ⚠️ ONAY METNİ, ROLLERİN VE ANAHTARLARIN
                       * KORUNDUĞUNU SÖYLEMEK ZORUNDA. Aksi hâlde
                       * yönetici bunu geri dönüşü olmayan bir işlem
                       * sanır ve olay anında yapmaktan çekinir — oysa
                       * pasifleştirme tam da o an için var.
                       */
                      confirm={
                        `Deactivate ${name}?\n\n` +
                        `They cannot sign in or open an SSH session. Their roles and keys ` +
                        `are kept, and signing in through the source reactivates them.`
                      }
                      label={`deactivate ${name}`}
                    >
                      Deactivate
                    </ActionButton>
                  )}
                  {/*
                    ⚠️ ADI SERBEST BIRAKMAK YALNIZCA SİLİNMİŞ HESAPLARDA.
                    Satır KALIYOR: denetim kaydı kullanıcı adını metin
                    olarak saklıyor ve satır yok olursa geçmişteki o adın
                    kime ait olduğu cevapsız kalırdı.
                  */}
                  {state === "deleted" && (
                    <ActionButton
                      variant="danger"
                      onClick={() =>
                        api
                          .purgeUser(name)
                          // Adı serbest bırakılan hesabın sayfasında
                          // kalmak anlamsız: o ad artık bu kişiye ait
                          // değil.
                          .then(onBack)
                          .catch((e: unknown) => setError(toMessage(e)))
                      }
                      confirm={
                        `Free the name "${name}"?\n\n` +
                        `Their keys and roles are released so someone new can use ` +
                        `the name.\n\nThe account row is kept: audit entries naming ` +
                        `"${name}" stay readable, and the log records when the name ` +
                        `was released.`
                      }
                      label={`free the name ${name}`}
                    >
                      Free the name
                    </ActionButton>
                  )}
                </div>
              </div>
            </div>

            {/*
              ⚠️ GİRİŞ BİLGİSİ KARTI YALNIZCA YEREL KAPI AÇIKKEN.
              Dizin ya da kimlik sağlayıcı öndeyken postern hiçbir değer
              doğrulamıyor: burada bir şey göstermek, uygulanmayan bir
              mekanizmayı varmış gibi sunmak olurdu.
            */}
            {localSource && (
              <div className="card">
                <div className="card-head">
                  <h3>Sign-in</h3>
                  <p>How this account proves who it is to the panel.</p>
                </div>
                <div className="card-body">
                  {u.credential ? (
                    <dl className="kv">
                      <dt>Kind</dt>
                      <dd>
                        {u.credential.kind === "password"
                          ? "a password they chose"
                          : u.credential.kind === "issued"
                            ? "issued value — not changed yet"
                            : "machine-generated secret (break-glass)"}
                      </dd>
                      <dt>Issued</dt>
                      <dd>
                        {new Date(u.credential.created_at).toLocaleDateString()}{" "}
                        by <code>{u.credential.created_by}</code>
                      </dd>
                      <dt>Last used</dt>
                      <dd>
                        {u.credential.last_used_at
                          ? new Date(u.credential.last_used_at).toLocaleString()
                          : "never"}
                      </dd>
                    </dl>
                  ) : (
                    <p className="muted">
                      postern holds no credential for this account.
                    </p>
                  )}

                  {u.credential?.must_change && (
                    <p className="msg msg-warn" role="status">
                      They have not changed it yet, so whoever issued it still
                      knows the value. Until they do, the panel stays closed to
                      them.
                    </p>
                  )}

                  {/*
                    ⚠️ YÖNETİCİ SATIRINDA YOK. Yöneticinin kimlik bilgisi
                    bir acil durum kapısı ve yalnızca host'tan çıkabiliyor;
                    panelden değiştirilebilseydi, paneli ele geçiren kişi
                    mevcut bir yöneticinin yerine geçerdi. Düğmeyi gizlemek
                    bir kolaylık — asıl garanti sunucuda ve göç 026'daki
                    kısıtta.
                  */}
                  {u.admin ? (
                    <p className="note">
                      This is an administrator: its credential is a break-glass
                      secret and is issued only on the host, with{" "}
                      <code>postern admin issue --name {name}</code>.
                    </p>
                  ) : (
                    <div className="field-row" style={{ marginTop: "0.9rem" }}>
                      <ActionButton
                        onClick={() =>
                          api
                            .resetCredential(name)
                            .then((r) => {
                              setIssued(r);
                              setOk("");
                              return load();
                            })
                            .catch((e: unknown) => setError(toMessage(e)))
                        }
                        confirm={`Reset the sign-in value for "${name}"? The new one is shown once, ${name} must change it at their next sign-in, anything they hold now stops working, and their open panel sessions are dropped.`}
                        label={`reset the sign-in value for ${name}`}
                      >
                        Reset sign-in
                      </ActionButton>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="detail-side">
            <div className="card">
              <div className="card-head">
                <h3>Roles</h3>
                <p>
                  Access comes only from roles. Without one this account reaches
                  nothing, whatever else is set.
                </p>
              </div>
              <div className="card-body">
                {u.roles.length === 0 ? (
                  <p className="msg msg-warn" role="status">
                    No role, so this account reaches no target at all.
                  </p>
                ) : (
                  <ul className="role-list">
                    {u.roles.map((r) => (
                      <li key={r.name}>
                        <div>
                          <code>{r.name}</code>
                          <span className="muted small">
                            {r.targets.length === 0
                              ? " reaches nothing"
                              : ` → ${r.targets.join(", ")}`}
                          </span>
                        </div>
                        {/*
                          ⚠️ ONAY ŞART. Bir rolü geri almak, o kişinin
                          eriştiği HER hedefi anında kapatıyor —
                          listedeki hâlinde onay vardı ve buraya
                          taşınırken düşmüştü. Aynı dosyadaki Delete ve
                          Deactivate onay istiyor; bu, ikisinden daha
                          az geri dönüşlü değil.
                        */}
                        <ActionButton
                          variant="danger"
                          onClick={() =>
                            run(
                              api.revokeRole(name, r.name),
                              `${r.name} revoked`,
                            )
                          }
                          confirm={
                            r.targets.length === 0
                              ? `Revoke "${r.name}" from ${name}?`
                              : `Revoke "${r.name}" from ${name}? They immediately lose ${r.targets.join(", ")}.`
                          }
                          label={`revoke ${r.name} from ${name}`}
                        >
                          Revoke
                        </ActionButton>
                      </li>
                    ))}
                  </ul>
                )}

                <div className="field-row" style={{ marginTop: "0.9rem" }}>
                  {/*
                    Zaten atanmış rol kutuda GÖRÜNMÜYOR: sunucu isteği
                    reddederdi ve kullanıcı yapamayacağı bir şeyi
                    seçebiliyor olurdu.
                  */}
                  {/*
                    ⚠️ "ÇEKİLEMEDİ" İLE "HİÇ YOK" AYRI ŞEYLER.
                    Rol listesi düşerse kutu boş kalıyor ve operatör hiç
                    rol tanımlı olmadığını sanıp Roles ekranına gidip
                    orada duran rolleri görüyordu. denied ayrıca
                    kontrol ediliyor: useList 403'ü boş error ile
                    denied'a çeviriyor.
                  */}
                  <label>
                    Add a role
                    <select
                      value={pick}
                      onChange={(e) => setPick(e.target.value)}
                      disabled={unassigned.length === 0}
                    >
                      <option value="">
                        {roles.error || roles.denied
                          ? "roles could not be loaded"
                          : roles.loading
                            ? "loading…"
                            : roles.items.length === 0
                              ? "no roles defined"
                              : unassigned.length === 0
                                ? "already has every role"
                                : "choose a role…"}
                      </option>
                      {unassigned.map((r) => (
                        <option key={r.name} value={r.name}>
                          {r.name}
                        </option>
                      ))}
                    </select>
                  </label>
                  <ActionButton
                    variant="primary"
                    disabled={!pick}
                    onClick={() =>
                      run(api.assignRole(name, pick), `${pick} assigned`, () =>
                        setPick(""),
                      )
                    }
                    label={`assign the chosen role to ${name}`}
                  >
                    Assign
                  </ActionButton>
                </div>
              </div>
            </div>

            {/*
              ⚠️ Anahtar kartı, anahtar girişi KAPALIYKEN hiç çizilmiyor.
              Devre dışı bir kart göstermek daha kötü olurdu: kullanıcı
              özelliğin bozuk mu yoksa kapalı mı olduğunu ayırt edemez.
            */}
            {publicKeyLogin && (
              <div className="card">
                <div className="card-head">
                  <h3>SSH keys</h3>
                  <p>
                    What lets this account open a session. What it can reach is
                    decided by the roles, not by the key.
                  </p>
                </div>
                <div className="card-body">
                  {u.keys.length === 0 ? (
                    <p className="muted">
                      No key on file — this account cannot connect over SSH.
                    </p>
                  ) : (
                    <ul className="key-list-admin">
                      {u.keys.map((k) => (
                        <li key={k.fingerprint}>
                          <div>
                            <code className="fp">{k.fingerprint}</code>
                            <span className="muted small">
                              {k.comment ? ` ${k.comment} · ` : " "}
                              added {new Date(k.added_at).toLocaleDateString()}
                            </span>
                          </div>
                          <ActionButton
                            onClick={() =>
                              run(
                                api.removeKeyByFingerprint(name, k.fingerprint),
                                "key removed",
                              )
                            }
                            confirm={`Remove this key from "${name}"? If it is their last key they can no longer connect.`}
                            label={`remove key ${k.fingerprint} from ${name}`}
                          >
                            Remove
                          </ActionButton>
                        </li>
                      ))}
                    </ul>
                  )}

                  <label style={{ marginTop: "0.9rem", display: "block" }}>
                    Add a public key
                    <textarea
                      rows={3}
                      value={keyText}
                      onChange={(e) => setKeyText(e.target.value)}
                      placeholder="ssh-ed25519 AAAA… yourlaptop"
                    />
                  </label>
                  <ActionButton
                    variant="primary"
                    disabled={!keyText.trim()}
                    onClick={() =>
                      run(api.addKey(name, keyText.trim()), "key added", () =>
                        setKeyText(""),
                      )
                    }
                    label={`add this key to ${name}`}
                  >
                    Add key
                  </ActionButton>
                </div>
              </div>
            )}
          </div>

          <div className="card detail-wide">
            <div className="card-head">
              <h3>Recent sessions</h3>
              <p>The last connections this account opened.</p>
            </div>
            {u.sessions.length === 0 ? (
              <p className="no-match">
                This account has never opened a session.
              </p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>
                        <span className="th-pad">Target</span>
                      </th>
                      <th>Started</th>
                      <th>Ended</th>
                    </tr>
                  </thead>
                  <tbody>
                    {u.sessions.map((se) => (
                      <tr key={se.id}>
                        <td>
                          <span className="th-pad">
                            <code>{se.target}</code>
                          </span>
                        </td>
                        <td>{new Date(se.started).toLocaleString()}</td>
                        <td>
                          {se.ended ? (
                            new Date(se.ended).toLocaleString()
                          ) : (
                            <span className="badge badge-accent">open</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
