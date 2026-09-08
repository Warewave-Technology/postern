import { useState } from "react";
import {
  api,
  LogEntry,
  Session,
  SessionFile,
  SessionJournal,
  toMessage,
} from "../api";
import {
  ActionButton,
  ErrorLine,
  ListState,
  Timestamp,
  WarnLine,
  bytes,
  sortableTime,
  useList,
} from "./common";
import CastPlayer from "./CastPlayer";
import ChainStatus from "./ChainStatus";
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
 * journalMsg, defterdeki açığın operatöre yazılacak cümlesi.
 *
 * ⚠️ CÜMLENİN GÖVDESİ SUNUCUDAN GELİYOR (internal/verify), burada
 * yeniden yazılmıyor: aynı kararı `postern session verify` de basıyor
 * ve iki metin ayrıştığı gün aynı oturum için iki farklı cevap veren
 * bir denetim aracı ortaya çıkardı. Panelin eklediği tek şey, listenin
 * neden eksiksiz sayılamayacağını söyleyen ön cümle.
 */
function journalMsg(j: SessionJournal): string {
  /*
   * ⚠️ "ALTERED" AYRI BİR CÜMLE. Diğerlerinde liste EKSİK; burada liste
   * tam ama SATIRLARIN KENDİSİ değişmiş. "Hepsi burada değil" demek,
   * denetçiyi olmayan bir eksiği aramaya gönderirdi.
   */
  const head =
    j.state === "altered"
      ? "These rows do not say what the recording says."
      : j.state === "extra"
        ? "This list holds more rows than the recording sealed."
        : "This list is NOT the whole story.";

  return `${head} — ${j.detail}.`;
}

/*
 * SessionFiles, bir oturumda dokunulan dosyaları listeler.
 *
 * ⚠️ NİYE OYNATICININ YANINDA DURUYOR. Eskiden gerekçe "SFTP oturumunun
 * terminal kaydı BOŞTUR" idi ve artık doğru değil: kayıt oturumun
 * çözülmüş anlatısını taşıyor ve zincir onu mühürlüyor
 * (proxy/sftpcast.go). Tablo yine de duruyor, çünkü iki farklı soruya
 * cevap veriyorlar. Kayıt MÜHÜRLÜ olan: "bu dosya yazıldığından beri
 * değişmedi" diyen şey o. Tablo ARANABİLİR olan: "bu yola kim dokundu",
 * "kaç bayt çıktı", "hangi istekler reddedildi" sorularının cevabı bir
 * oynatıcıyı baştan sona izlemeden alınabilsin diye burada.
 *
 * Yani biri diğerinin yerine geçmiyor; kayıt kanıt, tablo sorgu.
 */
function SessionFiles({
  files,
  failed,
  journal,
}: {
  files: SessionFile[];
  failed?: boolean;
  journal?: SessionJournal;
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

  /*
   * ⚠️ UYARI, TABLONUN VARLIĞINDAN BAĞIMSIZ VE ONDAN ÖNCE.
   *
   * En tehlikeli hâl BOŞ tablo: bütün satırları düşmüş ya da silinmiş
   * bir oturum, bu ekranda "hiçbir dosyaya dokunulmamış" gibi
   * görünüyordu. Uyarıyı tablonun içine koymak, tam da o oturumda
   * gizlerdi — `files.length === 0` dalı aşağıda hiçbir şey çizmiyor.
   */
  const gap = journal && journal.state !== "intact" && journal.state !== "unmeasured";

  if (files.length === 0) {
    return gap ? <WarnLine msg={journalMsg(journal)} /> : null;
  }

  return (
    <div className="card">
      {gap && <WarnLine msg={journalMsg(journal)} />}
      {/*
        ⚠️ card-head, ÇIPLAK h3 DEĞİL. `.card`ın kendi dolgusu yok
        (styles.css); başlık sarmalayıcısız bırakılınca kartın üst
        kenarına yapışıyordu. Tablo kenardan kenara kalıyor — bu
        deponun her kart+tablo ekranında olduğu gibi.
      */}
      <div className="card-head">
        <h3>Files</h3>
        <p>
          What this session did over SFTP. A transfer row counts the bytes that
          actually crossed, not the bytes requested.
        </p>
      </div>
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
  const { items, error, denied, loading, failed, refresh } = useList<Session>(
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
   * journal, listenin eksiksiz olup olmadığı.
   *
   * ⚠️ files İLE AYNI ANDA SIFIRLANIYOR. Önceki oturumun "defteri tam"
   * cevabı yeni oturumun listesinin üstünde kalsaydı, ekran eksik bir
   * listeyi onaylamış olurdu.
   */
  const [journal, setJournal] = useState<SessionJournal | undefined>(undefined);
  /*
   * chainOf, açılan oturumun zincir başı (varsa) ve kimliği.
   *
   * ⚠️ OYNATICIYA BAĞLI DEĞİL. SFTP oturumunda oynatıcı açılmayabiliyor
   * ve arşivlenmiş kayıtta hiç açılmıyor; zincir durumunu oynatıcının
   * içine koymak, tam da en çok merak edilen oturumlarda gizlerdi.
   */
  const [opened, setOpened] = useState<Session | null>(null);
  const [chainOf, setChainOf] = useState<{ id: string; chain?: string } | null>(
    null,
  );

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
  const watch = (row: Session) => {
    const id = row.id;
    // Sütundan çıkan alanlar detay başlığında görünsün.
    setOpened(row);
    setWhy("");
    setFiles([]);
    setFilesFailed(false);
    setJournal(undefined);
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
        setJournal(d.journal);
        setChainOf({ id, chain: d.recording.chain });
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
      /*
       * ⚠️ BU SÜTUN ONAY VERMEZ, YALNIZCA İŞARET EDER.
       *
       * Denetçinin listeye gelirken sorduğu soru "hangisini açayım".
       * Bugün liste bunu hiç cevaplamıyor: /etc/shadow'un reddedildiği
       * bir oturum, hiçbir şey yapılmamış bir oturumla birebir aynı
       * görünüyor ve fark ancak satır açılınca çıkıyor.
       *
       * ⚠️ HÜCRE TEK YÖNLÜ: en fazla dikkat çeker, ASLA "tamam" demez.
       * Yeşil bir rozet buraya konsaydı, listeden hesaplanamayan bir
       * onay verilmiş olurdu — özet karşılaştırması satırların
       * İÇERİĞİNİ ister (verify.JournalOf) ve listede yalnızca sayılar
       * var. Yani boş bir hücre "doğrulandı" değil, "bu iki şey
       * işaretlenmedi" demek; sütunun altındaki not bunu yazıyor.
       *
       * ⚠️ MÜHÜRSÜZLÜK VE ÖLÇÜLMEMİŞLİK BURAYA GİRMİYOR. İkisi de
       * BULGU değil, bulgunun YOKLUĞU — ve göç 034/037'den önce
       * kapanmış her oturum öyle. Onları da işaretlemek, geçmişin
       * tamamını alarma çevirip iki gerçek sinyali boğardı; ikisi de
       * satır açılınca zincir kartında ve defter satırında duruyor.
       */
      key: "evidence",
      header: "Evidence",
      // Sıralama işaretliyi öne alıyor: kayıp > ret > işaretsiz.
      value: (s) => (s.lost ? 2 : s.denied ? 1 : 0),
      render: (s) => {
        if (s.lost) {
          return (
            <span className="badge badge-warn">
              {s.lost} {s.lost === 1 ? "event" : "events"} lost
            </span>
          );
        }
        if (s.denied) {
          /*
           * badge-danger DEĞİL: kırmızı, bu panelde ÇELİŞKİYE ayrılmış
           * (ChainStatus: dosya tutuyor ama arşiv tutmuyor). Reddedilen
           * bir istek kuralın ÇALIŞTIĞI anlamına da geliyor; kırmızı
           * çizmek onu arıza gibi okuturdu.
           */
          return <span className="badge">{s.denied} refused</span>;
        }
        return null;
      },
    },
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
    /*
     * ⚠️ "OS user" VE "Src" SÜTUNDAN ÇIKTI, VERİDEN ÇIKMADI. İlk bakışın
     * cevaplaması gereken soru "hangisini açayım"; hedefteki hesap ve
     * kaynak adres o soruya değil, açtıktan SONRAKİ soruya ait. İkisi de
     * açılan oturumun başlığında duruyor ve ARAMADA kalıyor
     * (extraSearch) — yani "10.0.0.7" yazan denetçi yine buluyor,
     * yalnızca sütun taşımıyor.
     */
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
      /*
       * ⚠️ "AÇIK" İLE "AKIYOR" AYNI ŞEY DEĞİL ve rozet ikisini
       * karıştırıyordu: yeşil "running", ended_at'in BOŞLUĞUNDAN
       * çiziliyordu. Sunucu ayrıca `running` gönderiyor ve Overview onu
       * doğru kullanıyor (orada "sahipsiz" diye ayrılıyor) — postern
       * çöktüğünde aynı oturum bir ekranda sahipsiz, burada yeşil
       * görünüyordu. Yeşil, olmayan bir sağlık iddiasıydı.
       */
      render: (s) =>
        s.ended_at ? (
          <Timestamp value={s.ended_at} />
        ) : s.running === false ? (
          <span className="badge badge-info">open, not streaming</span>
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
          onClick={() => watch(s)}
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
            setJournal(undefined);
            setChainOf(null);
            setOpened(null);
          }}
        />
      )}

      {/*
        ⚠️ Oynatıcıya BAĞLI DEĞİL. SFTP oturumunda terminal kaydı boş
        olduğu için oynatıcı hiç açılmayabiliyor; tabloyu oynatıcının
        içine koymak, tam da onun gerektiği oturumlarda gizlerdi.
      */}
      {/*
        ⚠️ SÜTUNDAN ÇIKAN ALANLAR BURADA. Satırdan kaldırılan bir alanın
        hiçbir yerde görünmemesi, "sadeleştirme" adı altında bilgi
        kaybetmek olurdu; açılan oturumun başlığı onları geri veriyor.
      */}
      {opened && (
        <div className="card detail-head">
          <dl>
            <div>
              <dt>OS user</dt>
              <dd className="mono">{opened.os_user}</dd>
            </div>
            <div>
              <dt>From</dt>
              <dd className="mono">{opened.src_ip}</dd>
            </div>
            <div>
              <dt>Session</dt>
              <dd className="mono">{opened.id}</dd>
            </div>
          </dl>
        </div>
      )}

      {chainOf && <ChainStatus sessionId={chainOf.id} chain={chainOf.chain} />}

      <SessionFiles files={files} failed={filesFailed} journal={journal} />

      <ListState
        loading={loading}
        denied={denied}
        failed={failed}
        empty={items.length === 0}
        emptyText="No sessions recorded — nobody has connected through this bastion yet."
      />

      {/*
        ⚠️ BOŞ HÜCRENİN NE DEMEK OLMADIĞINI YAZMAK ŞART. "Evidence"
        altında boşluk gören biri bunu kolayca "doğrulandı" diye
        okuyabilir; oysa listeden hesaplanabilen tek şey iki sayı.
        Yazmayan bir sütun, hak edilmemiş bir onay dağıtırdı — bu turda
        üç kez düzelttiğimiz hatanın aynısı. Notu tablonun eteğinde.
      */}
      {items.length > 0 && (
        <DataTable
          rows={items}
          columns={columns}
          rowKey={(s) => s.id}
          initialSort={{ key: "started", dir: "desc" }}
          noun="session"
          searchLabel="search sessions by user, target or address"
          searchPlaceholder="Search sessions…"
          // Sütundan çıkanlar aramada KALIYOR (bkz. os_user/src notu).
          extraSearch={(s) => `${s.os_user} ${s.src_ip} ${s.id}`}
          foot={
            <p>
              An empty <b>Evidence</b> cell means neither of two things was
              flagged: postern losing audit events, and postern refusing a
              request. It is not a verdict on the recording or the journal —
              open a session and press <b>Verify</b> for that.
              {" "}
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
  const { items, error, denied, loading, failed, refresh } = useList<LogEntry>(
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
        failed={failed}
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
