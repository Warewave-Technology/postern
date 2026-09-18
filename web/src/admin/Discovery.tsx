import { useCallback, useEffect, useMemo, useState } from "react";
import {
  DiscoveredMachine,
  DiscoveryOverview,
  MachineRef,
  Registered,
  Group,
  api,
  toMessage,
} from "../api";
import {
  ActionButton,
  ErrorLine,
  ListState,
  Timestamp,
  useList,
} from "./common";
import DataTable, { Column } from "./DataTable";
import GrowingTable from "./GrowingTable";
import Modal from "./Modal";
import MultiSelect from "./MultiSelect";

/*
 * Discovery — kaynakların BULDUĞU makineler.
 *
 * ⚠️ KAYNAKLAR AYRI EKRANDA. İkisi bir sayfada alt alta iki tablo olarak
 * duruyordu ve hangisinin ne olduğu karışıyordu (kullanıcı söyledi):
 * biri postern'in OKUDUĞU yer, öbürü orada BULDUĞU şey.
 *
 * ⚠️ VARSAYILAN LİSTE YALNIZCA KARAR BEKLEYENLER. Altı durum birden tek
 * tabloda duruyordu ve "ignored" ile "blocked"ın ne demek olduğunu
 * kimse bilmiyordu (kullanıcı söyledi). Kaydedilmiş makineler zaten
 * Targets ekranında; yok sayılmış, kayıp ve engelli olanlar ise
 * üzerinde iş yapılacak şeyler değil. Hepsi bir tık uzakta ve her biri
 * NE DEMEK OLDUĞUYLA birlikte duruyor — gizlemek, anlamını da
 * gizlemek olmasın diye.
 *
 * ⚠️ KOŞU HEDEF YAZMIYOR. CLI'daki `postern discover --apply` yazıyor,
 * çünkü orada önizlemeyi bir insan okuyup onaylıyor; zamanlayıcının okuru
 * yok. Bulunan makine burada bir satır; hedef olması "Register" ile ve
 * yöneticinin rolleri, etiketleri ve özet ekranında parmak izini görüp
 * onaylamasıyla oluyor. Sanallaştırma platformunda VM açabilen biri
 * böylece postern'de kimsenin erişebileceği bir makine yaratamıyor.
 *
 * ⚠️ DURUM SATIRDAN TÜRETİLİYOR (machineState): sunucu "durum" diye tek
 * bir alan vermiyor; yok sayılmış, kayıp, kayıtlı-ama-anahtarı-değişmiş,
 * engelli ve yeni birbirinden ayrı ve ilk ikisi seçilebilir ama
 * kaydedilemez. Anahtarı değişen makine KIRMIZI: hedefe dokunulmadı ve
 * "makine yenilendi" mi "makine değişti" mi kararını insan verecek.
 */

export type MachineState = {
  text:
    "new" | "registered" | "key changed" | "blocked" | "missing" | "ignored";
  cls: string;
  registrable: boolean;
};

export function machineState(m: DiscoveredMachine): MachineState {
  if (m.ignored)
    return { text: "ignored", cls: "badge badge-mono", registrable: false };
  if (m.missing_since)
    return { text: "missing", cls: "badge badge-danger", registrable: false };
  if (m.target) {
    if (m.problem)
      return {
        text: "key changed",
        cls: "badge badge-danger",
        registrable: false,
      };
    return { text: "registered", cls: "badge badge-ok", registrable: false };
  }
  if (m.problem || !m.fingerprint)
    return { text: "blocked", cls: "badge badge-warn", registrable: false };
  return { text: "new", cls: "badge badge-info", registrable: true };
}

/** LabelRow, etiket tablosunun tek satırı. */
export type LabelRow = { key: string; value: string };

/*
 * ⚠️ ANAHTAR KURALI SUNUCUNUNKİYLE AYNI (store.ValidateLabel). Panelde
 * daha gevşek bir kural, yazdırıp sonra reddedilen bir etiket demek;
 * daha katı bir kural, sunucunun kabul ettiği bir adı yazdırmamak.
 */
const labelKeyRe = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$/;

/*
 * labelsOf, tablo satırlarını etiket haritasına çevirir ve okunur bir
 * hata döner.
 *
 * ⚠️ SERBEST METİN YERİNE TABLO. Kutuya "env=prod" yazdırmak, yazım
 * biçimini öğretilmesi gereken bir şeye çeviriyordu: eşittir unutulunca
 * satır sessizce düşüyor, yer tutucu yazılmış sanılıyordu (kullanıcı
 * söyledi). İki alan, hangi parçanın anahtar hangisinin değer olduğunu
 * kendisi söylüyor.
 */
export function labelsOf(rows: LabelRow[]): {
  labels: Record<string, string>;
  error: string;
} {
  const labels: Record<string, string> = {};
  for (const r of rows) {
    const key = r.key.trim();
    const value = r.value.trim();
    if (key === "" && value === "") continue;
    if (key === "") return { labels, error: `"${value}" has no key` };
    if (!labelKeyRe.test(key)) {
      return {
        labels,
        error: `label key "${key}" is not allowed: letters, digits, dot, dash or underscore (max 63)`,
      };
    }
    if (key in labels)
      return { labels, error: `label key "${key}" is written twice` };
    labels[key] = value;
  }

  return { labels, error: "" };
}

const keyOf = (m: MachineRef) => `${m.source_id}/${m.ref}`;

export default function Discovery() {
  const [overview, setOverview] = useState<DiscoveryOverview | null>(null);
  const [listError, setListError] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [selected, setSelected] = useState<string[]>([]);
  /*
   * ⚠️ AÇILAN DURUMLAR SEÇİLİR, HEPSİ BİRDEN DEĞİL. "Show everything"
   * tek düğmesi, yöneticiyi aradığı iki satırı yirmi iki satırın içinde
   * aratırdı; durum durum açmak, ne açtığını da söylüyor.
   */
  const [alsoShow, setAlsoShow] = useState<string[]>([]);
  /*
   * ⚠️ KAYIT PENCERESİ AÇILDIĞI ANDAKİ LİSTEYİ TUTUYOR, CANLI OLANI
   * DEĞİL — EKRANDA GÖRÜLDÜ.
   *
   * Başlık ve sihirbaz `registrable`ı okuyordu; kayıt bitince onDone
   * seçimi temizliyor ve listeyi yeniden okuyor, kaydedilenler de artık
   * "kaydedilebilir" olmadığı için o sayı SIFIRA düşüyordu. Yönetici
   * yedi makineyi kaydediyor ve pencerenin başlığında "Register 0
   * machine(s)" yazıyordu — gövdede yedi satır sonuç dururken. Pencere
   * açıldığı andaki KÜMEYE ait; altından değişen bir liste onu
   * yeniden yazamamalı.
   */
  const [registering, setRegistering] = useState(false);
  const [registerSet, setRegisterSet] = useState<DiscoveredMachine[]>([]);
  const [round, setRound] = useState(0);

  const load = useCallback(
    () =>
      api
        .discovery()
        .then((v) => {
          setOverview(v);
          setListError("");
        })
        .catch((e: unknown) => setListError(toMessage(e)))
        .finally(() => setLoading(false)),
    [],
  );
  useEffect(() => {
    load();
  }, [load]);

  /*
   * Koşu arka planda sürerken liste birkaç saniyede bir tazeleniyor:
   * "Run now"a öbür ekrandan basan yönetici, bulunan makineleri görmek
   * için bu sayfayı elle yenilemek zorunda kalmasın.
   */
  const anyRunning = overview?.sources.some((s) => s.running) ?? false;
  useEffect(() => {
    if (!anyRunning) return;
    const t = setInterval(() => void load(), 3000);

    return () => clearInterval(t);
  }, [anyRunning, load]);

  const machines = overview?.machines ?? [];
  const byKey = useMemo(
    () => new Map(machines.map((m) => [keyOf(m), m])),
    [machines],
  );
  const chosen = selected
    .map((k) => byKey.get(k))
    .filter((m): m is DiscoveredMachine => !!m);
  const registrable = chosen.filter((m) => machineState(m).registrable);

  const setIgnored = async (ignored: boolean) => {
    setError("");
    const refs = chosen
      .filter((m) => m.ignored !== ignored)
      .map((m) => ({ source_id: m.source_id, ref: m.ref }));
    try {
      await api.ignoreDiscovered(refs, ignored);
      setSelected([]);
      await load();
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  const columns: Column<DiscoveredMachine>[] = [
    {
      key: "name",
      header: "Machine",
      className: "wrap",
      value: (m) => `${m.name} ${m.ref}`,
      render: (m) => (
        <>
          {m.name}
          <br />
          <code className="small">{m.ref}</code>
          {/*
            ⚠️ "KAPALI OLDUĞU İÇİN ANAHTARI OKUNAMADI" SATIRA YAZILMIYOR.
            Kapalı makineler zaten listelenmiyor (aşağıdaki süzgeç) ve o
            cümleyi her satıra koymak, gerçekten bakılacak sorunları
            gürültüye boğuyordu — yirmi dört satırın yirmi ikisi aynı
            cümleyi tekrar ediyordu (kullanıcı ekrana bakıp söyledi).
          */}
          {m.problem && !m.problem.startsWith("not running") && (
            <div className="small muted">{m.problem}</div>
          )}
        </>
      ),
    },
    {
      key: "source",
      header: "Source",
      className: "wrap",
      value: (m) => m.source,
    },
    {
      key: "host",
      header: "Address",
      className: "wrap",
      value: (m) => m.host || m.name,
      render: (m) => (
        <>
          {/* Adres yoksa adı ikinci kez yazmıyoruz: aynı hücrede aynı
              kelime, sütunu okunmaz yapıyordu. */}
          {m.host || (
            <span
              className="muted"
              title={`no address reported; postern would try ${m.name}`}
            >
              —
            </span>
          )}
          {m.fingerprint && (
            <>
              <br />
              {/* Tam parmak izi özet adımında; burada kısaltılmış, tamamı başlıkta. */}
              <code className="small" title={m.fingerprint}>
                {m.fingerprint.length > 20
                  ? `${m.fingerprint.slice(0, 20)}…`
                  : m.fingerprint}
              </code>
            </>
          )}
        </>
      ),
    },
    {
      key: "group",
      header: "Tag group",
      className: "wrap",
      value: (m) => m.group ?? "",
      render: (m) =>
        m.group ? (
          m.group
        ) : (
          <span className="muted">
            {m.tags.length ? `untagged (${m.tags.join(", ")})` : "untagged"}
          </span>
        ),
    },
    {
      key: "state",
      header: "State",
      className: "grant-state",
      value: (m) => machineState(m).text,
      render: (m) => {
        const st = machineState(m);
        return (
          <>
            <span className={st.cls}>{st.text}</span>
            {m.target && (
              <>
                {" "}
                <span className="small">as {m.target}</span>
              </>
            )}
            {m.missing_since && (
              <div className="small muted">
                not reported since <Timestamp value={m.missing_since} />
              </div>
            )}
          </>
        );
      },
    },
    {
      key: "seen",
      header: "Last seen",
      value: (m) => m.last_seen,
      render: (m) => <Timestamp value={m.last_seen} />,
    },
  ];

  /*
   * ⚠️ VARSAYILAN LİSTE: KARAR BEKLEYENLER.
   *
   * "new" kaydedilebilir, "key changed" ise bir insanın "makine yenilendi
   * mi, değiştirildi mi" sorusunu cevaplamasını bekliyor. Kalan dört
   * durumun hiçbirinde bu ekranda yapılacak bir iş yok: kaydedilmiş
   * olanlar Targets'ta, yok sayılmış olanlar bilerek dışarıda, engelli
   * ve kayıp olanlar ise kaydedilemiyor. Yirmi dört makinelik bir kümede
   * yirmi ikisi bu dört durumdaydı ve aranan iki satır aralarında
   * kayboluyordu (kullanıcı ekrana bakıp söyledi).
   */
  const needsYou = (t: string) => t === "new" || t === "key changed";
  const counts = new Map<string, number>();
  for (const m of machines) {
    const t = machineState(m).text;
    if (!needsYou(t)) counts.set(t, (counts.get(t) ?? 0) + 1);
  }
  const listed = machines.filter((m) => {
    const t = machineState(m).text;

    return needsYou(t) || alsoShow.includes(t);
  });
  const hidden = machines.length - listed.length;

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Discovery</h2>
          <p className="page-sub">
            What the discovery sources found, with the host key postern read
            from each. Only the ones waiting for a decision are listed; a
            machine becomes a target — and reachable — when you register it
            here, never on its own.
          </p>
        </div>
      </div>

      <ErrorLine msg={error} />

      {machines.length === 0 ? (
        !loading &&
        !listError && (
          <p className="muted">
            Machines appear here after a discovery source has run.
          </p>
        )
      ) : (
        <>
          <div className="page-actions">
            <ActionButton
              variant="primary"
              onClick={() => {
                setRegisterSet(registrable);
                setRound((r) => r + 1);
                setRegistering(true);
              }}
              disabled={registrable.length === 0}
            >
              Register{" "}
              {registrable.length > 0
                ? `${registrable.length} selected`
                : "selected"}
              …
            </ActionButton>
            <ActionButton
              onClick={() => setIgnored(true)}
              disabled={!chosen.some((m) => !m.ignored)}
            >
              Ignore selected
            </ActionButton>
            <ActionButton
              onClick={() => setIgnored(false)}
              disabled={!chosen.some((m) => m.ignored)}
            >
              Stop ignoring
            </ActionButton>
            {chosen.length > registrable.length && chosen.length > 0 && (
              <span className="small muted">
                {chosen.length - registrable.length} of the selected cannot be
                registered — see what each state means below.
              </span>
            )}
          </div>
          {hidden > 0 && (
            <OtherStates
              counts={counts}
              shown={alsoShow}
              onChange={setAlsoShow}
            />
          )}
          {/*
            ⚠️ BOŞ BİR TABLO YERİNE CÜMLE. Hepsi kaydedilince varsayılan
            liste boşalıyor ama makineler duruyor; başlıkları olan boş bir
            tablo, yöneticiye yaptığı işin kaybolduğunu düşündürür.
          */}
          {listed.length === 0 ? (
            <p className="muted">
              Nothing is waiting for a decision. Every machine the sources found
              is in one of the states above.
            </p>
          ) : (
            <DataTable
              rows={listed}
              columns={columns}
              rowKey={keyOf}
              selection={{
                selected,
                onChange: setSelected,
                label: (m) => `select ${m.name}`,
              }}
              initialSort={{ key: "name", dir: "asc" }}
              searchLabel="Search machines"
              searchPlaceholder="Search by name, address, source, tag or state…"
              extraSearch={(m) =>
                `${m.tags.join(" ")} ${m.problem ?? ""} ${m.target ?? ""}`
              }
              noun="machine"
            />
          )}
        </>
      )}

      <Modal
        open={registering}
        title={`Register ${registerSet.length} machine(s)`}
        description="Each becomes a target with the host key discovery read, joins the groups you pick, and carries the labels you add. Nothing is written until the last step."
        onClose={() => setRegistering(false)}
        wide
      >
        {registering && (
          <RegisterWizard
            key={round}
            machines={registerSet}
            onDone={async () => {
              setSelected([]);
              await load();
            }}
            onClose={() => setRegistering(false)}
          />
        )}
      </Modal>
    </section>
  );
}

/*
 * RegisterWizard — üç adım: roller, etiketler, özet → kayıt.
 *
 * ⚠️ ÖZET EKRANI PARMAK İZİNİ GÖSTERİYOR ve kayıt o anahtarı sabitliyor
 * (sunucu yeniden taramıyor). Yönetici neyi onayladıysa o yazılıyor.
 */
/*
 * OTHER_STATES — varsayılanda listelenmeyen dört durum ve NE DEMEK
 * OLDUKLARI.
 *
 * ⚠️ AÇIKLAMA ZORUNLU, ÇÜNKÜ SAKLAMAK ANLAMI DA SAKLAR. Tabloda yalnızca
 * "ignored" ve "blocked" rozetleri duruyordu ve ikisinin ne demek
 * olduğunu kimse bilmiyordu (kullanıcı söyledi). Bir durumu varsayılanda
 * gizleyip açıklamasını da vermemek, yöneticiyi rozetin anlamını tahmin
 * etmeye bırakırdı — ve "blocked" için doğru tahmin "postern bunu
 * engelledi" olurdu, oysa engelleyen makinenin kendisi.
 */
const OTHER_STATES: [string, string][] = [
  [
    "registered",
    "Already a target — they are on the Targets screen. Discovery keeps watching them so a host key that changes shows up as “key changed” here.",
  ],
  [
    "ignored",
    "You told postern to leave these alone. They stay in the source's list and are never offered for registration again until you stop ignoring them.",
  ],
  [
    "blocked",
    "postern could not read a host key: the machine is powered off, has no address, or the probe failed. Nothing can be registered without one — this is the machine's state, not a decision postern made.",
  ],
  [
    "missing",
    "The source stopped reporting these. They may have been deleted there, or the source's scope changed. postern keeps the row so a machine that comes back is recognised.",
  ],
];

/*
 * OtherStates — gizlenen durumları açan kutu.
 *
 * ⚠️ AÇILIR BAŞLIK, SESSİZ BİR DÜĞME DEĞİL. Önceki hâli metnin içine
 * gömülü "Show them anyway" yazan bir bağlantıydı ve düğme olduğu
 * anlaşılmıyordu (kullanıcı söyledi). <summary> her tarayıcıda bir açılır
 * üçgenle çiziliyor ve klavyeyle de gezilebiliyor.
 */
function OtherStates({
  counts,
  shown,
  onChange,
}: {
  counts: Map<string, number>;
  shown: string[];
  onChange: (next: string[]) => void;
}) {
  const present = OTHER_STATES.filter(
    ([state]) => (counts.get(state) ?? 0) > 0,
  );
  const total = present.reduce((n, [state]) => n + (counts.get(state) ?? 0), 0);

  return (
    <details className="state-filter">
      <summary>
        {total} machine{total === 1 ? "" : "s"} not listed — nothing here needs
        you
      </summary>
      <p className="muted small">
        The list above shows only what is waiting for a decision. Tick a state
        to add it back.
      </p>
      <ul>
        {present.map(([state, why]) => (
          <li key={state}>
            {/*
              ⚠️ "check" SINIFI ŞART: genel `label` kuralı
              `flex-direction: column` veriyor (form alanları için) ve
              onsuz onay kutusu, rozet ve sayı alt alta yığılıyordu —
              ekranda görüldü.
            */}
            <label className="check">
              <input
                type="checkbox"
                checked={shown.includes(state)}
                onChange={(e) =>
                  onChange(
                    e.target.checked
                      ? [...shown, state]
                      : shown.filter((x) => x !== state),
                  )
                }
              />
              <span className="badge badge-mono">{state}</span>
              <span className="small">{counts.get(state)}</span>
            </label>
            <p className="muted small">{why}</p>
          </li>
        ))}
      </ul>
    </details>
  );
}

/**
 * LabelTable — anahtar/değer satırları, doldukça büyüyen tabloda.
 *
 * ⚠️ BÜYÜME KURALI GrowingTable'DA, BURADA DEĞİL: aynı davranış sudo
 * komutlarında da lazım ve iki kopya zamanla ayrışır.
 */
function LabelTable({
  rows,
  onChange,
}: {
  rows: LabelRow[];
  onChange: (rows: LabelRow[]) => void;
}) {
  return (
    <GrowingTable<LabelRow>
      rows={rows}
      onChange={onChange}
      empty={{ key: "", value: "" }}
      removeLabel={(n) => `remove label row ${n}`}
      columns={[
        {
          key: "key",
          header: "Key",
          placeholder: "env",
          label: (n) => `label key ${n}`,
        },
        {
          key: "value",
          header: "Value",
          placeholder: "prod",
          label: (n) => `label value ${n}`,
        },
      ]}
    />
  );
}

function RegisterWizard({
  machines,
  onDone,
  onClose,
}: {
  machines: DiscoveredMachine[];
  onDone: () => Promise<void>;
  onClose: () => void;
}) {
  const groups = useList<Group>(api.groups);
  const [step, setStep] = useState(0);
  /*
   * ⚠️ MAKİNENİN ETİKETİNDEKİ ROL SEÇİLİ GELİYOR. Platformda "role_web"
   * yazan bir makineyi kaydederken aynı rolü bir kez daha elle seçtirmek,
   * zaten verilmiş bir bilgiyi ikinci kez sormak demekti (kullanıcı
   * söyledi). Seçili gelen rol bir çip olarak duruyor, yani kaldırılabilir:
   * öneri, dayatma değil.
   *
   * Yalnızca postern'de VAR OLAN roller seçiliyor; henüz olmayan bir rol
   * adı seçim kutusunda yok, onu aşağıdaki onay kutusu açıyor.
   */
  const [chosenRoles, setChosenRoles] = useState<string[]>([]);
  const [tagRoles, setTagRoles] = useState(true);
  const [preselected, setPreselected] = useState(false);
  // Sonda hep boş bir satır duruyor; dolduruldukça yenisi açılıyor.
  const [labelRows, setLabelRows] = useState<LabelRow[]>([
    { key: "", value: "" },
  ]);
  const [results, setResults] = useState<Registered[] | null>(null);
  const [error, setError] = useState("");

  const parsed = labelsOf(labelRows);
  const tagRoleNames = Array.from(
    new Set(machines.map((m) => m.group).filter((r): r is string => !!r)),
  );
  const missingRoles = tagRoleNames.filter(
    (r) => !groups.items.some((x) => x.name === r),
  );

  // Roller yüklendiğinde bir KEZ: etiketin söylediği ve postern'de var
  // olan roller seçili gelsin. Sonraki seçimler kullanıcının.
  useEffect(() => {
    if (preselected || groups.items.length === 0) return;
    setPreselected(true);
    const known = tagRoleNames.filter((r) =>
      groups.items.some((x) => x.name === r),
    );
    if (known.length > 0) setChosenRoles(known);
  }, [preselected, groups.items, tagRoleNames]);

  const register = async () => {
    setError("");
    try {
      const r = await api.registerDiscovered({
        machines: machines.map((m) => ({ source_id: m.source_id, ref: m.ref })),
        groups: chosenRoles,
        tag_roles: tagRoles,
        labels: parsed.labels,
      });
      setResults(r.results);
    } catch (e: unknown) {
      setError(toMessage(e));
    }
    await onDone();
  };

  if (results) {
    return (
      <>
        <ul className="host-outcomes">
          {results.map((r) => (
            <li key={`${r.source_id}/${r.ref}`}>
              <h4>{r.name || r.ref}</h4>
              {r.error ? (
                <ErrorLine msg={r.error} />
              ) : (
                <p className="small">
                  registered as <code>{r.target}</code>
                  {r.groups?.length
                    ? `, granted to ${r.groups.join(", ")}`
                    : ", granted to no group"}
                  {r.created_roles?.length
                    ? ` (created ${r.created_roles.join(", ")})`
                    : ""}
                </p>
              )}
            </li>
          ))}
        </ul>
        <ErrorLine msg={error} />
        <div className="page-actions">
          <ActionButton onClick={onClose}>Done</ActionButton>
        </div>
      </>
    );
  }

  return (
    <>
      <p className="muted small">Step {step + 1} of 3</p>
      {step === 0 && (
        <>
          <div className="field-row">
            <MultiSelect
              label="Groups"
              placeholder="Search groups…"
              options={groups.items.map((r) => ({
                value: r.name,
                label: r.name,
              }))}
              value={chosenRoles}
              onChange={setChosenRoles}
              note="Every registered machine is granted to these groups. Access comes from the people assigned to a group, which this does not change."
            />
            <ErrorLine msg={groups.error} />
          </div>
          <label className="check">
            <input
              type="checkbox"
              checked={tagRoles}
              onChange={(e) => setTagRoles(e.target.checked)}
            />
            Also grant each machine to the group its tag names
            {tagRoleNames.length
              ? ` (${tagRoleNames.join(", ")}${missingRoles.length ? `; ${missingRoles.join(", ")} would be created` : ""})`
              : " (none of the selected machines carries a group tag)"}
          </label>
        </>
      )}
      {step === 1 && (
        <>
          <LabelTable rows={labelRows} onChange={setLabelRows} />
          <ErrorLine msg={parsed.error} />
          <p className="muted small">
            {Object.keys(parsed.labels).length === 0
              ? "Labels are optional: leave the rows empty to attach none."
              : `${Object.keys(parsed.labels).length} label${
                  Object.keys(parsed.labels).length === 1 ? "" : "s"
                } will be attached to each machine.`}
          </p>
        </>
      )}
      {step === 2 && (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Machine</th>
                  <th>Address</th>
                  <th>Tags</th>
                  <th>Host key</th>
                  <th>Groups</th>
                </tr>
              </thead>
              <tbody>
                {machines.map((m) => (
                  <tr key={keyOf(m)}>
                    <td className="wrap">{m.name}</td>
                    <td className="wrap">{m.host || m.name}</td>
                    {/* ⚠️ PLATFORMUN ETİKETLERİ ÖZETTE. Rolün nereden geldiği
                        ("role_web" etiketi) yalnızca listede görünüyordu; onay
                        ekranında görünmeyince kaydeden kişi neye dayanarak rol
                        verildiğini göremiyordu. */}
                    <td className="wrap">
                      {m.tags.length ? (
                        <span className="chips">
                          {m.tags.map((t) => (
                            <span key={t} className="chip">
                              {t}
                            </span>
                          ))}
                        </span>
                      ) : (
                        <span className="muted">none</span>
                      )}
                    </td>
                    <td className="wrap">
                      <code className="small">{m.fingerprint}</code>
                    </td>
                    <td className="wrap">
                      {/* ⚠️ TEKİLLEŞTİRİLİYOR: seçilen rol ile etiketin söylediği
                          rol aynı olduğunda özet "developer, developer" yazıyordu.
                          Sunucu zaten tek kez veriyor; yanlış olan ekrandı. */}
                      {Array.from(
                        new Set([
                          ...chosenRoles,
                          ...(tagRoles && m.group ? [m.group] : []),
                        ]),
                      ).join(", ") || <span className="muted">none</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="muted small">
            {Object.keys(parsed.labels).length === 0 ? (
              "No labels will be attached."
            ) : (
              <>
                Labels attached to each machine:{" "}
                <span className="chips">
                  {Object.entries(parsed.labels).map(([k, v]) => (
                    <span key={k} className="chip">
                      {k}={v}
                    </span>
                  ))}
                </span>
              </>
            )}
          </p>
          <p className="muted small">
            The host keys above are pinned as shown; postern does not re-read
            them now.
          </p>
        </>
      )}
      <ErrorLine msg={error} />
      <div className="page-actions">
        {step > 0 && (
          <ActionButton onClick={() => setStep(step - 1)}>Back</ActionButton>
        )}
        {step < 2 && (
          <ActionButton
            variant="primary"
            onClick={() => setStep(step + 1)}
            disabled={step === 1 && parsed.error !== ""}
          >
            Next
          </ActionButton>
        )}
        {step === 2 && (
          <ActionButton variant="primary" onClick={register}>
            Register {machines.length} machine(s)
          </ActionButton>
        )}
      </div>
    </>
  );
}
