import { useEffect, useState } from "react";
import { AdminGroupPreview, AdminGroupStatus, api, toMessage } from "../api";
import { ActionButton, ErrorLine, OkLine } from "./common";

/**
 * Yönetici grubu.
 *
 * ⚠️ ONAY EKRANI, ve onayı gerçek yapan şey sunucuda: kaydetme ucu
 * panelin GÖSTERDİĞİ listeyi geri istiyor ve kendi hesabıyla
 * karşılaştırıyor. Yani "önizlemeye bakmadan kaydet" diye bir yol yok —
 * bu ekran atlanabilir olsaydı onay bir dekordan ibaret kalırdı.
 *
 * Ekranın söylemek zorunda olduğu üç şey var ve üçü de rahatsız edici:
 *
 *   1. Bu yetki yalnızca rol dağıtmıyor: DENETİM GÜNLÜĞÜNÜ ve OTURUM
 *      KAYITLARINI da açıyor. Yani geçmişe erişim.
 *   2. Liste bir FOTOĞRAF. Yetkiyi veren grup; yarın gruba eklenen de
 *      yönetici olur ve bunu postern'e sormaya gerek kalmaz.
 *   3. Kaydeden kişi kendi yetkisini kaybediyor olabilir.
 */
export default function AdminGroup({ meName }: { meName?: string }) {
  const [status, setStatus] = useState<AdminGroupStatus | null>(null);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  const [mode, setMode] = useState<"view" | "edit">("view");
  const [group, setGroup] = useState("");
  // Önizleme, YAZILAN ada bağlı: ad değişince damga düşmeli, yoksa
  // başka bir grubun listesini onaylamış olursunuz.
  const [preview, setPreview] = useState<{
    group: string;
    result: AdminGroupPreview;
  } | null>(null);

  const load = () =>
    api
      .adminGroup()
      .then(setStatus)
      .catch((e: unknown) => setError(toMessage(e)));

  useEffect(() => {
    void load();
    // yalnızca ilk çizimde
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const groupHolders = (status?.holders ?? []).filter((h) => h.via === "group");
  const shown = preview?.group === group.trim() ? preview.result : null;

  const runPreview = () => {
    setError("");
    setDone("");
    const g = group.trim();
    if (!g) return Promise.resolve();
    return api
      .previewAdminGroup(g)
      .then((r) => setPreview({ group: g, result: r }))
      .catch((e: unknown) => {
        setPreview(null);
        setError(toMessage(e));
      });
  };

  const save = (g: string, confirm: string[]) => {
    setError("");
    return api
      .setAdminGroup(g, confirm)
      .then((r) => {
        setDone(
          g === ""
            ? `administrator is no longer granted by any group — ${r.revoked.length} lost it`
            : `saved — ${r.granted.length} gained administrator, ${r.revoked.length} lost it`,
        );
        setPreview(null);
        setGroup("");
        setMode("view");
        return load();
      })
      .catch((e: unknown) => {
        setError(toMessage(e));
        // 409: onaylanan küme artık geçerli değil. TAZE listeyi
        // göstermeden tekrar sormak, aynı hatayı tekrar ettirmek olurdu.
        if (g !== "") return runPreview();
        return load();
      });
  };

  // Kaydeden kişi kendi yetkisini kaybediyor mu? Sessiz kalmak, panele
  // bir daha giremeyeceğini kaydettikten SONRA öğrenmesi demek.
  const losesSelf = (nextAdmins: string[]) => {
    if (!meName) return false;
    const mine = status?.holders.find(
      (h) => h.username.toLowerCase() === meName.toLowerCase(),
    );
    if (!mine || mine.via !== "group") return false;
    return !nextAdmins.some((n) => n.toLowerCase() === meName.toLowerCase());
  };

  return (
    <div className="card">
      <div className="card-head">
        <h3>Administrator group</h3>
        <p>
          Membership of one directory group carries the administrator flag.
          postern grants it when the directory says so and takes it back when it
          stops saying so — <b>nobody can hand it out from this panel</b>. An
          account created on the bastion host with{" "}
          <code>postern admin issue</code> is never touched by any of this.
        </p>
      </div>

      <div className="card-body">
        <ErrorLine msg={error} />
        <OkLine msg={done} />

        {status && (
          <>
            <dl className="kv">
              <dt>group</dt>
              <dd>
                {status.group ? (
                  <code>{status.group}</code>
                ) : (
                  <span className="muted">
                    not set — administrator comes only from the bastion host
                  </span>
                )}
              </dd>
              <dt>administrators</dt>
              <dd>
                {status.holders.length === 0 ? (
                  <span className="muted">none</span>
                ) : (
                  <ul className="problem-list">
                    {status.holders.map((h) => (
                      <li key={h.username}>
                        {h.username}{" "}
                        <span
                          className={
                            h.via === "cli" ? "badge badge-ok" : "badge"
                          }
                        >
                          {h.via === "cli"
                            ? "bastion host"
                            : h.via === "group"
                              ? `via ${status.group || "a group"}`
                              : "source unknown"}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </dd>
            </dl>

            {/*
              ⚠️ Sayılamayan kurulumu SAKLAMIYORUZ. Gruplar OIDC
              claim'inden geliyorsa üye listesi diye bir şey yok:
              claim yalnızca "bu kişi bu gruptaymış" der. Onay ekranı o
              kurulumda kimseyi sayamaz ve sayabiliyormuş gibi yapmak,
              güvenilecek en kötü şey olurdu.
            */}
            {!status.enumerable &&
              (status.enumerable_error ? (
                // Kurulmuş ama BOZUK. Bunu "claim modundasın" diye
                // göstermek, olmayan bir mimariyi anlatıp gerçek arızayı
                // gizlerdi.
                <p className="msg msg-warn" role="alert">
                  <b>The directory cannot be asked who is in a group.</b> LDAP
                  is configured but postern could not build a working
                  connection from it: <code>{status.enumerable_error}</code>.
                  Fix that above and this screen starts working — the same
                  fault also affects sign-in.
                </p>
              ) : (
                <p className="msg msg-warn" role="status">
                  <b>Who is in the group cannot be listed here.</b> Group
                  membership is coming from the identity provider&apos;s claim,
                  and a claim only answers &ldquo;is this person in that
                  group&rdquo; — one person at a time, at sign-in. There is no
                  member list to show you before saving, so in this mode the
                  administrator group is set from the bastion host.
                </p>
              ))}

            {status.enumerable && mode === "view" && (
              <div className="wizard-nav">
                <button
                  className="btn-primary"
                  onClick={() => {
                    setError("");
                    setDone("");
                    setGroup(status.group);
                    setPreview(null);
                    setMode("edit");
                  }}
                >
                  {status.group ? "Change group" : "Choose a group"}
                </button>
                {status.group !== "" && (
                  <>
                    <span className="spacer" />
                    <ActionButton
                      variant="danger"
                      label="stop granting administrator through a group"
                      confirm={
                        `Stop using ${status.group}? ` +
                        `${groupHolders.length} account(s) lose administrator immediately: ` +
                        `${groupHolders.map((h) => h.username).join(", ") || "none"}.`
                      }
                      onClick={() =>
                        save(
                          "",
                          groupHolders.map((h) => h.username),
                        )
                      }
                    >
                      Stop using a group
                    </ActionButton>
                  </>
                )}
              </div>
            )}

            {status.enumerable && mode === "edit" && (
              <div className="wizard-form">
                <div className="wfield">
                  <label className="wfield-label" htmlFor="admin-group">
                    Group name
                  </label>
                  <input
                    id="admin-group"
                    value={group}
                    aria-describedby="admin-group-hint"
                    onChange={(e) => {
                      setGroup(e.target.value);
                      setDone("");
                    }}
                  />
                  <p className="wfield-hint" id="admin-group-hint">
                    The same name the directory uses — matched the way sign-in
                    matches it, so scope and nesting rules apply here too.
                  </p>
                </div>

                <div className="wizard-check">
                  <ActionButton
                    onClick={runPreview}
                    disabled={group.trim() === ""}
                    label="see who this group would make an administrator"
                  >
                    See who this gives it to
                  </ActionButton>
                  <span className="note">
                    Asks the directory who is in that group, then resolves each
                    of them the way sign-in does. Nothing is saved yet.
                  </span>
                </div>

                {shown && !shown.ok && (
                  <ErrorLine
                    msg={
                      shown.error ||
                      "the directory refused and did not say why"
                    }
                  />
                )}

                {shown?.ok && (
                  <>
                    {shown.admins.length === 0 ? (
                      <p className="msg msg-warn" role="status">
                        <b>Nobody resolves in that group.</b>{" "}
                        {shown.note ??
                          "Saving it is allowed, but it would grant administrator to no one — check the spelling and the group base."}
                      </p>
                    ) : (
                      <div className="msg msg-warn" role="status">
                        <b>
                          You are giving administrator to{" "}
                          {shown.admins.length} account(s):
                        </b>
                        <ul className="problem-list">
                          {shown.admins.map((n) => (
                            <li key={n}>
                              {n}{" "}
                              {shown.no_account.includes(n) && (
                                <span className="badge">
                                  no postern account yet — gets it at first
                                  sign-in
                                </span>
                              )}
                            </li>
                          ))}
                        </ul>
                        <p>
                          They can read the <b>audit log</b> and{" "}
                          <b>session recordings</b> — every command anyone has
                          run through postern. This is access to the past, not
                          just to the future.
                        </p>
                        <p>
                          {/* Fotoğraf değil, GRUP onaylanıyor. */}
                          This list is what the group holds <i>right now</i>.
                          The grant follows the group: whoever is added to{" "}
                          <code>{shown.group}</code> later becomes an
                          administrator too, without anyone asking postern.
                        </p>
                      </div>
                    )}

                    {groupHolders.some(
                      (h) =>
                        !shown.admins.some(
                          (n) => n.toLowerCase() === h.username.toLowerCase(),
                        ),
                    ) && (
                      <p className="msg msg-warn" role="status">
                        <b>Losing it:</b>{" "}
                        {groupHolders
                          .filter(
                            (h) =>
                              !shown.admins.some(
                                (n) =>
                                  n.toLowerCase() === h.username.toLowerCase(),
                              ),
                          )
                          .map((h) => h.username)
                          .join(", ")}{" "}
                        — they hold it through the current group and are not in
                        this one.
                      </p>
                    )}

                    {losesSelf(shown.admins) && (
                      <p className="msg msg-warn" role="alert">
                        <b>This removes your own administrator access.</b> You
                        hold it through the current group and you are not in{" "}
                        <code>{shown.group}</code>. Saving will end your access
                        to this page.
                      </p>
                    )}

                    {!!shown.skipped.length && (
                      <p className="note">
                        In the group but not counted:{" "}
                        <code>{shown.skipped.join(", ")}</code> — they did not
                        resolve the way sign-in resolves them (out of scope,
                        disabled, or named differently in the directory).
                      </p>
                    )}

                    {shown.truncated && (
                      <p className="msg msg-warn" role="status">
                        <b>The member list was cut short.</b> postern stops
                        reading a group after a fixed number of members, so
                        this list may be incomplete — and a group this large is
                        an odd choice for administrator anyway.
                      </p>
                    )}
                  </>
                )}

                <div className="wizard-nav">
                  <button
                    onClick={() => {
                      setPreview(null);
                      setGroup("");
                      setError("");
                      setMode("view");
                    }}
                  >
                    Cancel
                  </button>
                  <span className="spacer" />
                  <ActionButton
                    variant="primary"
                    // ⚠️ Önizleme GÖRÜLMEDEN kaydedilemez — ve görülen
                    // liste bu ada ait olmalı. Asıl koruma sunucuda:
                    // gördüğün listeyi geri istiyor.
                    disabled={!shown?.ok}
                    label="confirm and save the administrator group"
                    confirm={
                      shown
                        ? `Give administrator to: ${shown.admins.join(", ") || "nobody"}?` +
                          `\n\nThey can read the audit log and every session recording.` +
                          `\nAnyone added to ${shown.group} later gets it too.`
                        : undefined
                    }
                    onClick={() => save(shown!.group, shown!.admins)}
                  >
                    {shown?.ok
                      ? `Confirm and save`
                      : "See the list before saving"}
                  </ActionButton>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
