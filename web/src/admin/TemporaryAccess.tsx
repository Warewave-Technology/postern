import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Grant,
  GrantRequest,
  GrantResult,
  GrantStep,
  Role,
  Target,
  TargetGroups,
  User,
  api,
  toMessage,
} from "../api";
import { ActionButton, ErrorLine, ListState, Timestamp, useList } from "./common";
import DataTable, { Column } from "./DataTable";
import Modal from "./Modal";
import MultiSelect from "./MultiSelect";

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
 * ⚠️ HEDEFLER VE GRUPLAR <select multiple>, ONAY KUTUSU LİSTESİ DEĞİL.
 * İlk hâl onay kutularıydı; yüz hedefli bir envanterde okunmuyordu
 * (kullanıcı söyledi). Seçim kutusu tarayıcının kendi kaydırma ve
 * klavye davranışını getiriyor; hedef listesinin üstünde bir süzgeç var.
 *
 * ⚠️ GRUP ADAYLARI İKİ ÖBEK: postern'in ROLLERİ (her zaman — rol adı
 * hedefte aynı adlı grup, yoksa postern açıyor) ve seçili hedeflerin
 * ORTAK grupları (yüklenince). Birden çok hedefte yalnızca hepsinde
 * olan gruplar listeleniyor ve bu yazıyor; sistem grupları (gid < 1000:
 * docker, wheel, shadow…) hiç listelenmiyor — üyelikleri sudo kuralı
 * yazmadan root'a giden yol. Asıl ret sunucuda, plan aşamasında.
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

  // Toplu geri alma: seçili hakların kimlikleri ve her birinin sonucu.
  const [selected, setSelected] = useState<string[]>([]);
  const [bulk, setBulk] = useState<HostOutcome[]>([]);

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

  /*
   * ⚠️ SEÇİLENLERİ SIRAYLA GERİ AL — biri düşünce durma. Yüz hostta açık
   * bir hakkı tek tek kapatmak yapılmıyor (kullanıcı söyledi); ama yüz
   * geri almayı tek bir "başarılı/başarısız"a indirgemek de olmaz:
   * ulaşılamayan hedefin hakkı açık kalıyor ve süpürücü yeniden deneyecek,
   * operatör hangisi olduğunu görmeli. Her hak kendi satırında; liste her
   * hakkın ardından değil sonda tazeleniyor, seçim sonda temizleniyor.
   */
  const revokeSelected = async () => {
    setError("");
    setResult(null);
    const out: HostOutcome[] = [];
    for (const id of selected) {
      const g = grants.find((x) => x.id === id);
      const target = g ? `${g.username} on ${g.target}` : id;
      try {
        const r = await api.revokeGrant(id);
        out.push({
          target,
          summary:
            r.summary + (r.sessions_closed ? ` — ${r.sessions_closed} open session(s) closed` : ""),
          steps: r.steps,
        });
      } catch (e: unknown) {
        out.push({ target, summary: "", steps: [], error: toMessage(e) });
      }
      setBulk([...out]);
    }
    setSelected([]);
    await load();
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
      {bulk.length > 0 && (
        <>
          <ul className="host-outcomes">
            {bulk.map((o, i) => (
              <li key={i}>
                <h4>{o.target}</h4>
                <Outcome summary={o.summary} steps={o.steps} error={o.error} />
              </li>
            ))}
          </ul>
          <p>
            <button type="button" className="btn-quiet" onClick={() => setBulk([])}>
              Dismiss these results
            </button>
          </p>
        </>
      )}
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
          /*
            Seçim: yalnızca açık haklar. Başlık kutusu aramanın gösterdiğini
            seçiyor — "ayse" yazıp tümünü seç, sonra "Revoke selected".
          */
          selection={{
            selected,
            onChange: setSelected,
            canSelect: (g) => !g.revoked_at,
            label: (g) => `select ${g.username} on ${g.target}`,
          }}
          toolbarExtra={
            selected.length > 0 && (
              <>
                <span className="count">{selected.length} selected</span>
                <ActionButton
                  variant="danger"
                  onClick={revokeSelected}
                  confirm={`End ${selected.length} temporary access grant(s) now? On every host involved, the person's open sessions are closed and the account, its home and its processes are removed.`}
                  label="revoke the selected grants"
                >
                  Revoke selected
                </ActionButton>
                <button type="button" className="btn-quiet" onClick={() => setSelected([])}>
                  Clear selection
                </button>
              </>
            )
          }
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

/* Bir hedefte hak açmanın sonucu — sihirbaz hedef başına bir tane yazıyor. */
type HostOutcome = {
  target: string;
  summary: string;
  steps: GrantStep[];
  error?: string;
};

/*
 * commonGroups, yüklenen envanterlerin KESİŞİMİ — sistem grupları
 * düşülmüş hâlde. Birden çok hedefte yalnızca hepsinde olan gruplar
 * aday: bir hedefte olmayan grubu seçtirmek, o hedefte postern'in yeni
 * bir grup açması demek ve bunun gizlice olmaması gerekiyor. hidden,
 * listelenmeyen sistem gruplarının ayrık sayısı — nota yazılıyor.
 */
export function commonGroups(inventories: TargetGroups[]): {
  names: string[];
  hidden: number;
  hosts: string[];
} {
  if (inventories.length === 0) return { names: [], hidden: 0, hosts: [] };
  const hidden = new Set<string>();
  let names: string[] | null = null;
  for (const inv of inventories) {
    const offered = new Set<string>();
    for (const g of inv.groups) {
      if (g.protected) hidden.add(g.name);
      else offered.add(g.name);
    }
    names = names === null ? Array.from(offered) : names.filter((n) => offered.has(n));
  }
  return {
    names: (names ?? []).sort((a, b) => a.localeCompare(b)),
    hidden: hidden.size,
    hosts: inventories.map((i) => i.target),
  };
}

function NewGrant({ onChanged, onClose }: { onChanged: () => Promise<unknown>; onClose: () => void }) {
  const users = useList<User>(api.users);
  const targets = useList<Target>(api.targets);
  const roles = useList<Role>(api.roles);

  const [username, setUsername] = useState("");
  const [hosts, setHosts] = useState<string[]>([]);
  const [groups, setGroups] = useState<string[]>([]);
  const [inventory, setInventory] = useState<Record<string, TargetGroups | { error: string }>>({});
  const [duration, setDuration] = useState<string>("4h");
  const [commands, setCommands] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [outcomes, setOutcomes] = useState<HostOutcome[]>([]);
  const [done, setDone] = useState(false);

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

  const loaded = useMemo(
    () => Object.values(inventory).filter((v): v is TargetGroups => !("error" in v)),
    [inventory],
  );
  const common = useMemo(() => commonGroups(loaded), [loaded]);
  const minGID = loaded[0]?.min_gid;
  const inventoryErrors = Object.entries(inventory).filter(
    (e): e is [string, { error: string }] => "error" in e[1],
  );
  const roleNames = roles.items.map((r) => r.name).sort((a, b) => a.localeCompare(b));
  // Rol adıyla çakışan hedef grubu bir kez listelenir — rol öbeğinde.
  const hostOnly = common.names.filter((n) => !roleNames.includes(n));

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
            ⚠️ HEDEFLER VE GRUPLAR MultiSelect: arama, etiket olarak
            seçilenler, tümünü seç. Yüz hedefli envanterde onay kutusu
            listesi de yerleşik <select multiple> da okunmuyordu
            (kullanıcı söyledi). Yükleme düğmesi hedeflerin hemen altında:
            akış hedef seç → yükle → grup seç.
          */}
          <div className="field-row">
            <MultiSelect
              label="Hosts"
              placeholder="Search hosts by name or address…"
              options={targets.items.map((t) => ({
                value: t.name,
                label: t.name,
                hint: `${t.host}:${t.port}`,
              }))}
              value={hosts}
              onChange={setHosts}
              note={
                hosts.length === 0
                  ? "Pick one or more hosts; the account is opened on each."
                  : `${hosts.length} host(s) selected.`
              }
            />
            <ErrorLine msg={targets.error} />
            <ActionButton onClick={loadGroups} disabled={hosts.length === 0}>
              Load groups from the selected hosts
            </ActionButton>
          </div>

          <div className="field-row">
            <MultiSelect
              label="Groups"
              placeholder="Search groups…"
              options={[
                ...roleNames.map((r) => ({ value: r, label: r, group: "Roles on postern" })),
                ...hostOnly.map((g) => ({
                  value: g,
                  label: g,
                  group:
                    common.hosts.length === 1
                      ? `On ${common.hosts[0]}`
                      : `Common to ${common.hosts.join(", ")}`,
                })),
              ]}
              value={groups}
              onChange={setGroups}
              note={
                common.hosts.length === 0
                  ? "A role's name becomes a group on the host; postern creates it if it is missing."
                  : common.hosts.length === 1
                    ? `${common.names.length} group(s) on ${common.hosts[0]}${
                        common.hidden
                          ? `; ${common.hidden} system group(s) below gid ${minGID} are not offered`
                          : ""
                      }.`
                    : `Only the ${common.names.length} group(s) present on all ${common.hosts.length} selected hosts are offered${
                        common.hidden
                          ? `; ${common.hidden} system group(s) below gid ${minGID} are not`
                          : ""
                      }.`
              }
            />
          </div>
          {inventoryErrors.map(([host, v]) => (
            <ErrorLine key={host} msg={`${host}: ${v.error}`} />
          ))}
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
