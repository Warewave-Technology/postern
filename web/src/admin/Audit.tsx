import { useState } from "react";
import { api, LogEntry, Session, SessionFile, toMessage } from "../api";
import {
  ActionButton,
  ErrorLine,
  ListState,
  WarnLine,
  useList,
} from "./common";
import CastPlayer from "./CastPlayer";
import DataTable, { Column } from "./DataTable";
import type { Resolved } from "../theme/mode";

/*
 * Sunucunun döndürdüğü en fazla satır sayısı (internal/httpapi/admin.go:
 * Sessions(…, 200) ve AdminLog(…, 500)). Panelde YAZILI duruyorlar:
 * denetim ekranında sessizce kırpılmış bir liste, operatöre "olan biten
 * bu kadar" dedirtir — oysa 201'inci oturum da olmuş olabilir ve onu
 * aramaya bile kalkmaz.
 *
 * ⚠️ SIRALAMA VE ARAMA İSTEMCİDE, dolayısıyla yalnızca GELEN satırlar
 * üzerinde. Sınıra dayanmış bir listede arama, elde olmayanı bulamaz —
 * kart eteğindeki uyarı tam da bunun için duruyor.
 */
const SESSION_CAP = 200;
const LOG_CAP = 500;

/*
 * Damgalar KISA biçimde yazılıyor ("28 Aug 09:31:56").
 *
 * toLocaleString() "8/28/2026, 9:31:56 AM" üretiyordu; iki damgalı bir
 * satır tabloyu ~200px genişletiyor ve sağdaki EYLEM sütununu yatay
 * kaydırmanın ardına itiyordu.
 */
const stampFmt = new Intl.DateTimeFormat(undefined, {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

/**
 * Timestamp renders an RFC3339 stamp compactly and keeps the exact
 * original in the title, for copying into a report or a log query.
 */
function Timestamp({ value }: { value: string }) {
  const d = new Date(value);
  // Ayrıştıramadığımız damgayı "Invalid Date" diye göstermek kaydın
  // kendisini gizlemek olurdu: ham değer hiç yoktan iyidir.
  if (Number.isNaN(d.getTime())) return <>{value}</>;
  return (
    <time dateTime={value} title={value}>
      {stampFmt.format(d)}
    </time>
  );
}

/**
 * sortableTime, sıralama için sayısal damga.
 *
 * ⚠️ METİN SIRALAMASI YANLIŞ OLURDU: gösterilen biçimde yıl yok ve
 * "28 Aug" ile "3 Sep" alfabetik sıralandığında Ağustos, Eylül'den
 * sonra gelir. Sıralama ham değerin zamanına bakıyor.
 */
function sortableTime(v: string | null): number {
  if (!v) return 0;
  const t = new Date(v).getTime();
  return Number.isNaN(t) ? 0 : t;
}

/*
 * Bayt sayısını okunur hâle getirir.
 *
 * Denetçinin sorusu "4823905 bayt mı" değil "4,6 MB mı". Ham sayı, iki
 * transferi gözle karşılaştırmayı imkânsız kılıyordu.
 */
function bytes(n: number): string {
  if (n === 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}

/*
 * SessionFiles, bir oturumda dokunulan dosyaları listeler.
 *
 * ⚠️ NİYE OYNATICININ YANINDA DURUYOR: SFTP oturumunun terminal kaydı
 * BOŞTUR — protokol ham ikili aktığı için kayda hiç yazılmıyor
 * (proxy/sftp.go). Bu tablo olmasa denetçi boş bir oynatıcı görür ve
 * "bu oturumda bir şey olmamış" sonucuna varırdı; oysa tam o oturumda
 * dosya taşınmış olabilir.
 */
function SessionFiles({
  files,
  failed,
}: {
  files: SessionFile[];
  failed?: boolean;
}) {
  if (failed) {
    return (
      <WarnLine
        msg={
          "The file events for this session could not be read, so this is " +
          "not a statement that no files were touched."
        }
      />
    );
  }
  if (files.length === 0) return null;

  return (
    <div className="card">
      <h3>Files</h3>
      <p className="page-sub">
        What this session did over SFTP. A transfer row counts the bytes that
        actually crossed, not the bytes requested.
      </p>
      <table className="data">
        <thead>
          <tr>
            <th>Time</th>
            <th>Op</th>
            <th>Path</th>
            <th>Read</th>
            <th>Wrote</th>
            <th>Result</th>
          </tr>
        </thead>
        <tbody>
          {files.map((f) => (
            <tr key={f.id}>
              <td>
                <Timestamp value={f.at} />
              </td>
              <td>{f.op}</td>
              <td>
                <code title={f.path}>{f.path}</code>
                {f.new_path && (
                  <>
                    {" → "}
                    <code title={f.new_path}>{f.new_path}</code>
                  </>
                )}
              </td>
              <td>{bytes(f.read)}</td>
              <td>{bytes(f.wrote)}</td>
              <td>
                {/*
                  Başarısız satırlar SİLİNMİYOR, işaretleniyor: reddedilen
                  bir silme denemesi engelin çalıştığının kanıtı ve
                  denetimin göstermesi gereken tam olarak bu.
                */}
                {f.ok ? (
                  "ok"
                ) : (
                  <span className="bad" title={f.detail}>
                    denied{f.detail ? ` — ${f.detail}` : ""}
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Sessions({ theme }: { theme: Resolved }) {
  const { items, error, denied, loading, refresh } = useList<Session>(
    api.sessions,
  );
  // Oynatılan oturum. Aynı anda tek kayıt: iki terminali yan yana
  // izlemenin bir faydası yok, ikisini birden beslemenin maliyeti var.
  const [playing, setPlaying] = useState<string | null>(null);
  const [why, setWhy] = useState("");
  // Açılan oturumun dosya olayları. Oynatıcıdan BAĞIMSIZ tutuluyor:
  // kaydı olmayan bir oturumun bile dosya olayları olabilir.
  const [files, setFiles] = useState<SessionFile[]>([]);
  const [filesFailed, setFilesFailed] = useState(false);

  /*
   * ⚠️ OYNATMADAN ÖNCE KAYDIN DURUMU SORULUYOR.
   *
   * Düğme koşulsuz oynatıcıyı açıyordu ve kaydı olmayan bir oturumda
   * oynatıcı boş açılıp hata veriyordu — denetçi "kayıt tutulmadı" ile
   * "dosya kayıp"ı ayırt edemiyor, ikisini de bozuk bir oynatıcı
   * sanıyordu. İkisi çok farklı şeyler: biri politikanın sonucu,
   * öbürü kaybolmuş kanıt.
   *
   * Sunucu bu ayrımı ilk günden veriyordu (dört değerli durum); onu
   * soran yoktu.
   */
  const watch = (id: string) => {
    setWhy("");
    setFiles([]);
    setFilesFailed(false);
    return api
      .sessionDetail(id)
      .then((d) => {
        // ⚠️ Dosya olayları KAYITTAN ÖNCE yerleşiyor. Aşağıdaki
        // dallardan bazıları erken dönüyor (kayıt yok / kayıp) ve
        // olaylar sonra atansaydı, tam da kaydı olmayan oturumlarda
        // hiç görünmezlerdi — oysa denetçinin elinde kalan tek kanıt
        // orada bunlar oluyor.
        setFiles(d.files ?? []);
        setFilesFailed(Boolean(d.files_error));
        const hasFiles = (d.files ?? []).length > 0;
        switch (d.recording.state) {
          case "none":
            setWhy(
              hasFiles
                ? "No terminal recording was kept for this session, but the " +
                    "file events below show what it did."
                : "No recording was kept for this session — the bastion was " +
                    "not recording when it ran.",
            );
            return;
          case "missing":
            setWhy(
              "This session was recorded, but the file is no longer on disk. " +
                "It was either removed by the retention policy or deleted " +
                "outside postern — the admin log says which.",
            );
            return;
          /*
            ⚠️ ARŞİVLENMİŞ KAYIT "KAYIP" DEĞİL.
            Aynı cümleyi göstermek, denetçiye var olan bir kanıtı yok
            diye bildirmek olurdu. Nesnenin yeri yazılıyor çünkü panel
            onu indirmiyor: bastion'a bir okuma kimliği koymak, bütün
            arşivi tek bir ele geçirmeyle dışarı çıkarılabilir yapardı.
          */
          case "archived": {
            const a = d.recording.archive;
            setWhy(
              a
                ? `This recording is no longer on the bastion — it was ` +
                  `archived to ${a.bucket}/${a.object_key}. Fetch it with ` +
                  `your own credentials; postern does not hold a read key.`
                : "This recording was archived off the bastion.",
            );
            return;
          }
          case "partial":
            // ⚠️ Yarım kayıt YİNE DE OYNATILIYOR: elde olanı
            // göstermemek, hiç olmamasından iyi değil.
            setWhy(
              "This recording is incomplete — the session ended abruptly. " +
                "What was captured is shown below.",
            );
            break;
        }
        setPlaying(id);
      })
      .catch((e: unknown) => setWhy(toMessage(e)));
  };

  const columns: Column<Session>[] = [
    {
      key: "id",
      header: "ID",
      value: (s) => s.id,
      // Kısaltılmış kimliğin tamamı title'da: bir olayı sunucu
      // günlüğünde aratacak olan kişiye 12 hane yetmiyor.
      render: (s) => <code title={s.id}>{s.id.slice(0, 12)}…</code>,
    },
    { key: "user", header: "User", value: (s) => s.user },
    { key: "target", header: "Target", value: (s) => s.target },
    { key: "os_user", header: "OS user", value: (s) => s.os_user },
    { key: "src", header: "Src", value: (s) => s.src_ip },
    {
      key: "started",
      header: "Started",
      value: (s) => sortableTime(s.started_at),
      render: (s) => <Timestamp value={s.started_at} />,
    },
    {
      key: "ended",
      header: "Ended",
      // Süren oturum sıralamada EN SONA: 0 verseydik "hâlâ açık" olanlar
      // en eski oturumlarla karışırdı.
      value: (s) =>
        s.ended_at ? sortableTime(s.ended_at) : Number.MAX_SAFE_INTEGER,
      render: (s) =>
        s.ended_at ? (
          <Timestamp value={s.ended_at} />
        ) : (
          <span className="badge badge-ok">running</span>
        ),
    },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (s) => (
        <ActionButton
          onClick={() => watch(s.id)}
          label={`watch the recording of ${s.user} on ${s.target}, started ${s.started_at}`}
        >
          Watch
        </ActionButton>
      ),
    },
  ];

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Sessions</h2>
          <p className="page-sub">
            Every connection this bastion proxied, with the recording it kept.
          </p>
        </div>
        {/*
          Elle yenileme. Bu liste SÜREN oturumları da gösteriyor ama tek
          başına hiç tazelenmiyordu: açık bırakılmış bir sekme, o andan
          sonra bağlanan herkesi gizliyor ve "kimse bağlı değil" diyormuş
          gibi okunuyordu.
        */}
        <ActionButton onClick={refresh} label="refresh the session list">
          Refresh
        </ActionButton>
      </div>
      <ErrorLine msg={error} />

      {why && <WarnLine msg={why} />}

      {playing && (
        <CastPlayer
          sessionId={playing}
          theme={theme}
          onClose={() => {
            setPlaying(null);
            setFiles([]);
            setFilesFailed(false);
          }}
        />
      )}

      {/*
        ⚠️ Oynatıcıya BAĞLI DEĞİL. SFTP oturumunda terminal kaydı boş
        olduğu için oynatıcı hiç açılmayabiliyor; tabloyu oynatıcının
        içine koymak, tam da onun gerektiği oturumlarda gizlerdi.
      */}
      <SessionFiles files={files} failed={filesFailed} />

      <ListState
        loading={loading}
        denied={denied}
        empty={items.length === 0}
        emptyText="No sessions recorded — nobody has connected through this bastion yet."
      />

      {items.length > 0 && (
        <DataTable
          rows={items}
          columns={columns}
          rowKey={(s) => s.id}
          initialSort={{ key: "started", dir: "desc" }}
          noun="session"
          searchLabel="search sessions by user, target or address"
          searchPlaceholder="Search sessions…"
          foot={
            <p>
              postern lists at most the {SESSION_CAP} most recent sessions, and
              sorting and search work on what was returned.
              {items.length >= SESSION_CAP &&
                " This list is at that limit, so older sessions exist and are not shown here."}
            </p>
          }
        />
      )}
    </section>
  );
}

export function AdminLog() {
  const { items, error, denied, loading, refresh } = useList<LogEntry>(
    api.adminLog,
  );

  const columns: Column<LogEntry>[] = [
    {
      key: "at",
      header: "At",
      value: (e) => sortableTime(e.at),
      render: (e) => <Timestamp value={e.at} />,
    },
    { key: "actor", header: "Actor", value: (e) => e.actor },
    {
      key: "via",
      header: "Via",
      value: (e) => e.via,
      render: (e) => <span className="badge">{e.via}</span>,
    },
    {
      key: "action",
      header: "Action",
      value: (e) => e.action,
      render: (e) => <code>{e.action}</code>,
    },
    { key: "entity", header: "Entity", value: (e) => e.entity },
    {
      key: "details",
      header: "Details",
      className: "wrap",
      value: (e) => e.details,
    },
  ];

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Admin log</h2>
          <p className="page-sub">
            Who changed what, and through which door — the CLI, the panel, the
            directory sync, or a first sign-in.
          </p>
        </div>
        <ActionButton onClick={refresh} label="refresh the admin log">
          Refresh
        </ActionButton>
      </div>
      <ErrorLine msg={error} />

      <ListState
        loading={loading}
        denied={denied}
        empty={items.length === 0}
        emptyText="No admin actions logged yet."
      />

      {items.length > 0 && (
        <DataTable
          rows={items}
          columns={columns}
          // ⚠️ Anahtar dizinden DEĞİL satırın kendi alanlarından. Liste
          // komple yeniden çekiliyor ve en yeni başta geliyor: yeni bir
          // kayıt eklendiğinde dizin anahtarları bir kayıyor ve React
          // eski satırın durumunu yeni satıra devrediyordu.
          rowKey={(e) =>
            `${e.at}|${e.actor}|${e.via}|${e.action}|${e.entity}|${e.details}`
          }
          initialSort={{ key: "at", dir: "desc" }}
          noun="entry"
          searchLabel="search the admin log by actor, action or entity"
          searchPlaceholder="Search the log…"
          foot={
            <p>
              postern lists at most the {LOG_CAP} most recent entries, and
              sorting and search work on what was returned.
              {items.length >= LOG_CAP &&
                " This list is at that limit, so older entries exist and are not shown here."}
            </p>
          }
        />
      )}
    </section>
  );
}
