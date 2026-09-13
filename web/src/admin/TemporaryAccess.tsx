import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Grant,
  GrantRequest,
  GrantResult,
  GrantStep,
  Target,
  TargetGroups,
  User,
  api,
  toMessage,
} from "../api";
import { ActionButton, ErrorLine, ListState, Timestamp, useList } from "./common";
import DataTable, { Column } from "./DataTable";
import Modal from "./Modal";

/**
 * TemporaryAccess — geçici erişim sekmesi: bütün hedeflerdeki haklar ve
 * yeni hak açan sihirbaz.
 *
 * ⚠️ KENDİ SEKMESİ, HEDEF SAYFASININ ALTINDAKİ KART DEĞİL. Kart hedef
 * başınaydı: "kimin nerede açık hesabı var" sorusu N hedefi gezdiriyor,
 * tablosu hedef sayfasının dar sütununa sığmıyordu (kullanıcı ekrana
 * bakıp söyledi). Burada kişi, hedef(ler) ve grup(lar) tek pencerede
 * seçiliyor; hak hedef başına açılıyor ve her hedefin sonucu ayrı
 * yazılıyor — üç makinenin ikisinde açılıp birinde açılamayan bir hak,
 * tek bir "başarısız" değil.
 *
 * ⚠️ GRUPLAR HEDEFTEN OKUNUP SEÇİLEBİLİYOR ve 1000'in altındakiler
 * seçilemiyor: docker, wheel, shadow gibi sistem grupları sudo kuralı
 * yazmadan root'a giden yollar. Bayrağı ve sınırı sunucu veriyor
 * (protected, min_gid); asıl ret plan aşamasında — burası yalnızca reddi
 * "Grant"e basmadan önce göstermek için.
 *
 * ⚠️ LİSTE KAYDIN KENDİSİ. Sunucu "durum" diye tek bir alan vermiyor;
 * revoked_at, revoke_error, applied_at ve expires_at'tan burada
 * türetiliyor (grantState). Geri alması başarısız olan bir hak yeşil değil
 * kırmızı: süresi dolmuş bir hesap makinede duruyor demek.
 */

const DURATIONS = [
  ["30m", "30 minutes"],
  ["1h", "1 hour"],
  ["4h", "4 hours"],
  ["8h", "8 hours"],
  ["24h", "24 hours"],
  ["168h", "7 days"],
] as const;

export default function TemporaryAccess() {
  const [grants, setGrants] = useState<Grant[]>([]);
  const [now, setNow] = useState("");
  const [listError, setListError] = useState("");
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);

  const [adding, setAdding] = useState(false);
  // Her açılışta sıfırdan sihirbaz: bir önceki turun seçimleri ve
  // sonuçları yeni bir hakka taşınmasın.
  const [round, setRound] = useState(0);

  const [error, setError] = useState("");
  const [result, setResult] = useState<GrantResult | null>(null);

  const load = useCallback(
    () =>
      api
        .allGrants()
        .then((v) => {
          setGrants(v.grants);
          setNow(v.now);
          setListError("");
          setFailed(false);
        })
        .catch((e: unknown) => {
          setListError(toMessage(e));
          setFailed(true);
        })
        .finally(() => setLoading(false)),
    [],
  );

  useEffect(() => {
    load();
  }, [load]);

  const revoke = (id: string) => {
    setError("");
    setResult(null);
    return api
      .revokeGrant(id)
      .then((r) => {
        setResult(r);
        return load();
      })
      .catch((e: unknown) => {
        setError(toMessage(e));
        // Başarısız geri alma da kayıtta (revoke_error): liste tazelenmezse
        // operatör kırmızı satırı görmez.
        return load();
      });
  };

  const columns: Column<Grant>[] = [
    {
      key: "person",
      header: "Person",
      value: (g) => `${g.username} ${g.os_user}`,
      render: (g) => (
        <>
          {g.username}
          <br />
          <code className="small">{g.os_user}</code>
        </>
      ),
    },
    { key: "target", header: "Host", className: "wrap", value: (g) => g.target },
    {
      key: "groups",
      header: "Groups",
      className: "wrap",
      value: (g) => g.groups.join(" "),
      render: (g) => (g.groups.length ? g.groups.join(", ") : "—"),
    },
    {
      key: "until",
      header: "Until",
      value: (g) => g.revoked_at ?? g.expires_at,
      render: (g) => <Timestamp value={g.revoked_at ?? g.expires_at} />,
    },
    {
      key: "state",
      header: "State",
      // grant-state, .state DEĞİL: .state boş-durum kutusunun (kesikli
      // çerçeve, ortalı) sınıfı ve tabloya sızıp sütunu çerçeveliyordu.
      className: "grant-state",
      value: (g) => grantState(g, now).text,
      render: (g) => {
        const st = grantState(g, now);
        return <span className={st.cls || undefined}>{st.text}</span>;
      },
    },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (g) =>
        !g.revoked_at && (
          <ActionButton
            variant="danger"
            onClick={() => revoke(g.id)}
            confirm={`End ${g.username}'s access to ${g.target} now? Their open sessions there are closed and the account ${g.os_user}, its home and its processes are removed.`}
            label={`revoke ${g.username}'s temporary access to ${g.target}`}
          >
            Revoke
          </ActionButton>
        ),
    },
  ];

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Temporary access</h2>
          <p className="page-sub">
            Accounts postern opens on hosts for a fixed time, through its
            management account, and removes when the time is up — sessions
            closed, processes killed, account and home deleted, sudo rule
            taken away. Both directions are written to the admin log first.
          </p>
        </div>
        <ActionButton
          variant="primary"
          onClick={() => {
            setRound((r) => r + 1);
            setAdding(true);
          }}
        >
          New temporary access
        </ActionButton>
      </div>

      <ErrorLine msg={error} />
      {result && <Outcome summary={result.summary} steps={result.steps} closed={result.sessions_closed} />}
      <ErrorLine msg={listError} />

      <ListState
        loading={loading}
        denied={false}
        failed={failed}
        empty={grants.length === 0}
        emptyText="No temporary access has been granted on any host."
      />

      {grants.length > 0 && (
        <DataTable
          rows={grants}
          columns={columns}
          rowKey={(g) => g.id}
          initialSort={{ key: "until", dir: "desc" }}
          searchLabel="Search grants by person, host or group"
          searchPlaceholder="Search grants…"
          noun="grant"
        />
      )}

      <Modal
        open={adding}
        onClose={() => setAdding(false)}
        title="New temporary access"
        description="Pick the person, the hosts and the groups. postern signs in to each host as its management account, creates the account there, and deletes it — with its home, its processes and its sudo rule — when the time is up."
      >
        {adding && <NewGrant key={round} onChanged={load} onClose={() => setAdding(false)} />}
      </Modal>
    </section>
  );
}

/*
 * grantState, kaydın alanlarından tek bir cümle ve bir vurgu sınıfı türetir.
 * Sıra önemli: geri alınmış hak "başarısız" değil; başarısız geri alma
 * "vadesi doldu"dan önce gelir çünkü daha acil.
 */
export function grantState(
  g: Grant,
  now: string,
): { text: string; cls: string } {
  if (g.revoked_at) return { text: "revoked", cls: "" };
  if (g.revoke_error)
    return {
      text: `revocation failing (attempt ${g.revoke_attempts}): ${g.revoke_error}`,
      cls: "bad",
    };
  if (!g.applied_at)
    return { text: "not fully applied — will be cleaned up", cls: "warn" };
  if (now && new Date(g.expires_at).getTime() <= new Date(now).getTime())
    return { text: "expired — being revoked", cls: "warn" };
  return { text: "active", cls: "" };
}

/** Bir koşunun özeti ve adımları — hak verme ve geri alma aynı biçimde. */
function Outcome({
  summary,
  steps,
  closed,
  error,
}: {
  summary: string;
  steps: GrantStep[];
  closed?: number;
  error?: string;
}) {
  const ok = !error && steps.every((s) => s.outcome === "done");
  return (
    <>
      <p className={ok ? "msg msg-ok" : "msg msg-warn"} role="status">
        {error ?? summary}
        {closed !== undefined && closed > 0 && <> — {closed} open session(s) closed</>}
      </p>
      {steps.length > 0 && (
        <details className="run-log" open={!ok}>
          <summary>What ran on the host</summary>
          <ul className="run-list">
            {steps.map((s, i) => (
              <li key={i}>
                <code>{s.kind}</code>
                <span className={s.outcome === "done" ? "" : "bad"}>{s.outcome}</span>
                <span className="run-reason">{s.error || s.why}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </>
  );
}

/* Bir hedefteki grubun seçicideki hâli: hangi seçili hedeflerde var. */
type Catalogued = { name: string; gid: number; protected: boolean; hosts: string[] };

/* Bir hedefte hak açmanın sonucu — sihirbaz hedef başına bir tane yazıyor. */
type HostOutcome = {
  target: string;
  summary: string;
  steps: GrantStep[];
  error?: string;
};

function splitGroups(text: string): string[] {
  return text
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function NewGrant({ onChanged, onClose }: { onChanged: () => Promise<unknown>; onClose: () => void }) {
  const users = useList<User>(api.users);
  const targets = useList<Target>(api.targets);

  const [username, setUsername] = useState("");
  const [hosts, setHosts] = useState<string[]>([]);
  const [groupText, setGroupText] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [inventory, setInventory] = useState<Record<string, TargetGroups | { error: string }>>({});
  const [duration, setDuration] = useState<string>("4h");
  const [commands, setCommands] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [outcomes, setOutcomes] = useState<HostOutcome[]>([]);
  const [done, setDone] = useState(false);

  // Yazılan ve seçilen gruplar tek küme: aynı ad iki kez gitmesin.
  const groups = useMemo(
    () => Array.from(new Set([...splitGroups(groupText), ...picked])),
    [groupText, picked],
  );

  const toggle = (list: string[], set: (v: string[]) => void, name: string) =>
    set(list.includes(name) ? list.filter((h) => h !== name) : [...list, name]);

  /*
   * Envanter hedef hedef okunuyor ve BİRLEŞTİRİLİYOR: bir grup üç seçili
   * hedefin ikisinde varsa satırında "only on …" yazıyor. Seçilmesi yine
   * serbest — olmayan hedefte postern grubu açar — ama operatör bunu
   * bilerek seçmeli. Bir hedefte korunan grup her hedefte korunan sayılır.
   */
  const loadGroups = async () => {
    const next: Record<string, TargetGroups | { error: string }> = {};
    for (const h of hosts) {
      try {
        next[h] = await api.targetGroups(h);
      } catch (e: unknown) {
        next[h] = { error: toMessage(e) };
      }
    }
    setInventory(next);
  };

  const catalogue = useMemo<Catalogued[]>(() => {
    const m = new Map<string, Catalogued>();
    for (const [host, v] of Object.entries(inventory)) {
      if ("error" in v) continue;
      for (const g of v.groups) {
        const cur = m.get(g.name) ?? { name: g.name, gid: g.gid, protected: false, hosts: [] };
        cur.hosts.push(host);
        cur.protected = cur.protected || g.protected;
        m.set(g.name, cur);
      }
    }
    return Array.from(m.values()).sort((a, b) => a.name.localeCompare(b.name));
  }, [inventory]);
  const minGID = Object.values(inventory).find((v): v is TargetGroups => !("error" in v))?.min_gid;
  const inventoryErrors = Object.entries(inventory).filter(
    (e): e is [string, { error: string }] => "error" in e[1],
  );

  const request = (): GrantRequest => {
    const g: GrantRequest = { username, groups, duration };
    const lines = commands
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    if (lines.length > 0) {
      g.sudo = {
        commands: lines.map((l) => {
          const [path, ...args] = l.split(/\s+/);
          return { path, args };
        }),
        acknowledged,
      };
    }
    return g;
  };

  /*
   * ⚠️ HEDEF HEDEF, SIRAYLA — ve biri düşünce durmuyor. Her hedefin
   * cevabı ayrı satır: "db-01'de açıldı, web-02 ulaşılamadı" tek bir
   * hata satırına indirgenmemeli, çünkü açılan hesap açık ve süpürücü
   * onu vadesinde toplayacak. Liste her hedeften sonra tazeleniyor.
   */
  const grant = async () => {
    const out: HostOutcome[] = [];
    for (const h of hosts) {
      try {
        const r = await api.createGrant(h, request());
        out.push({ target: h, summary: r.summary, steps: r.steps });
      } catch (e: unknown) {
        out.push({ target: h, summary: "", steps: [], error: toMessage(e) });
      }
      setOutcomes([...out]);
    }
    setDone(true);
    await onChanged();
  };

  const durationLabel = DURATIONS.find(([v]) => v === duration)?.[1] ?? duration;

  return (
    <>
      {outcomes.length > 0 && (
        <ul className="host-outcomes">
          {outcomes.map((o) => (
            <li key={o.target}>
              <h4>{o.target}</h4>
              <Outcome summary={o.summary} steps={o.steps} error={o.error} />
            </li>
          ))}
        </ul>
      )}

      {!done && (
        <>
          <div className="field-row">
            <label>
              Person
              <select value={username} onChange={(e) => setUsername(e.target.value)}>
                <option value="">choose…</option>
                {(users.items ?? []).map((u) => (
                  <option key={u.name} value={u.name}>
                    {u.name} (account {u.os_user})
                  </option>
                ))}
              </select>
            </label>
            <label>
              For
              <select value={duration} onChange={(e) => setDuration(e.target.value)}>
                {DURATIONS.map(([v, label]) => (
                  <option key={v} value={v}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {/*
            ⚠️ BAŞLIK <label> DEĞİL <span>: onay kutuları kendi label'larını
            taşıyor ve label içinde label geçersiz — dış label ilk kutuya
            bağlanır, "Hosts" yazısına tıklamak ilk hedefi işaretlerdi.
          */}
          <div className="field-row">
            <div className="pick-field">
              <span className="wfield-label">Hosts</span>
              <ErrorLine msg={targets.error} />
              {targets.items.length === 0 && !targets.loading ? (
                <span className="muted small">No target is registered yet.</span>
              ) : (
                <div className="pick-list" role="group" aria-label="Hosts">
                  {targets.items.map((t) => (
                    <label key={t.name} className="check">
                      <input
                        type="checkbox"
                        checked={hosts.includes(t.name)}
                        onChange={() => toggle(hosts, setHosts, t.name)}
                      />
                      <code>{t.name}</code>
                      <span className="muted small">
                        {t.host}:{t.port}
                      </span>
                    </label>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="field-row">
            <label>
              Groups (typed, comma-separated)
              <input
                value={groupText}
                onChange={(e) => setGroupText(e.target.value)}
                placeholder="dba, developer"
              />
            </label>
            <ActionButton onClick={loadGroups} disabled={hosts.length === 0}>
              Load groups from the selected hosts
            </ActionButton>
          </div>
          {inventoryErrors.map(([host, v]) => (
            <ErrorLine key={host} msg={`${host}: ${v.error}`} />
          ))}
          {catalogue.length > 0 && (
            <div className="field-row">
              <div className="pick-field">
                <span className="wfield-label">Groups on the selected hosts</span>
                {minGID !== undefined && (
                  <span className="muted small">
                    Groups numbered below {minGID} are system groups and cannot be
                    granted temporarily.
                  </span>
                )}
                <div className="pick-list" role="group" aria-label="Groups on the selected hosts">
                  {catalogue.map((g) => (
                    <label key={g.name} className={"check" + (g.protected ? " off" : "")}>
                      <input
                        type="checkbox"
                        disabled={g.protected}
                        checked={picked.includes(g.name)}
                        onChange={() => toggle(picked, setPicked, g.name)}
                      />
                      <code>{g.name}</code>
                      <span className="muted small">
                        gid {g.gid}
                        {g.protected ? " · protected" : ""}
                        {!g.protected && g.hosts.length < hosts.length
                          ? ` · only on ${g.hosts.join(", ")}`
                          : ""}
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          )}
          <p className="muted small">
            Will join: {groups.length ? groups.join(", ") : "no group besides postern-jit"}.
          </p>

          <div className="field-row">
            <label>
              Commands the account may run with sudo (optional, one per line)
              <textarea
                value={commands}
                onChange={(e) => setCommands(e.target.value)}
                rows={3}
                placeholder={"/usr/bin/systemctl restart nginx\n/usr/bin/journalctl -u nginx"}
              />
            </label>
          </div>
          {commands.trim() !== "" && (
            <label className="check">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={(e) => setAcknowledged(e.target.checked)}
              />
              I have read the escape-risk warning if postern raises one, and accept it
            </label>
          )}

          <div className="card-actions">
            <ActionButton
              variant="primary"
              onClick={grant}
              disabled={!username || hosts.length === 0}
              confirm={`Open an account for ${username || "this person"} on ${hosts.length} host(s) — ${hosts.join(", ")} — for ${durationLabel}? postern signs in as its management account to create it on each host, and will delete the account, its home directory and its processes when the time is up.`}
              label="grant temporary access"
            >
              Grant access
            </ActionButton>
          </div>
        </>
      )}

      {done && (
        <div className="card-actions">
          <button type="button" className="btn-quiet" onClick={onClose}>
            Done
          </button>
        </div>
      )}
    </>
  );
}
