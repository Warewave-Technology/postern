import { useState } from "react";
import {
  api,
  FileCriteria,
  FileHistory as History,
  FileTouch,
  toMessage,
} from "../api";
import {
  ActionButton,
  ErrorLine,
  Timestamp,
  WarnLine,
  bytes,
  sortableTime,
} from "./common";
import DataTable, { Column } from "./DataTable";

/**
 * "Bu dosyaya kim dokundu" — soruşturmanın ekranı.
 *
 * ⚠️ TERS YÖN ZATEN VARDI, BU YÖN YOKTU. Oturum detayı "bu oturum
 * hangi dosyalara dokundu"yu cevaplıyor; soruşturmanın elinde ise
 * oturum değil YOL oluyor ("/etc/shadow'u kim aldı"). Depoda doğru
 * sorgu ilk günden duruyordu ama hiçbir yerden çağrılmıyordu: SFTP
 * denetimini yazma gerekçesi olan sorunun cevabı, yazılmış ve
 * ulaşılamaz hâlde bekliyordu.
 *
 * ⚠️ EKRANIN EN ÖNEMLİ CÜMLESİ KAPSAM UYARISI. Bu tablo YALNIZCA SFTP
 * olaylarını biliyor. Kabuk oturumunda `cat /etc/shadow` yazan biri
 * buraya hiçbir satır bırakmaz — o iz terminal kaydında durur. Boş bir
 * sonucu "kimse almamış" diye okumak, bu ekranın verebileceği en pahalı
 * yanlış cevap ve tam da denetçinin en çok güvendiği anda gelir.
 */

/*
 * ⚠️ ÜÇ AYRI DURUM, ÜÇ AYRI EKRAN.
 *
 *   idle  — henüz aranmadı. "Sonuç yok" DEĞİL.
 *   empty — arandı, kayıt çıkmadı.
 *   error — bakılamadı.
 *
 * İkisini aynı boşlukla göstermek, sorulmamış bir soruyu cevaplanmış
 * gibi okutmak olurdu.
 */
type State =
  | { kind: "idle" }
  | { kind: "busy" }
  | { kind: "done"; result: History }
  | { kind: "error"; msg: string };

export default function FileHistory() {
  const [path, setPath] = useState("");
  const [under, setUnder] = useState(false);
  const [user, setUser] = useState("");
  const [target, setTarget] = useState("");
  const [state, setState] = useState<State>({ kind: "idle" });

  const criteria: FileCriteria = {
    path: path.trim(),
    /*
     * ⚠️ YOL YOKSA AĞAÇ KİPİ DE YOK.
     *
     * Onay kutusu yol boşken devre dışı ama DURUMU KALICI: yol yazıp
     * kutuyu işaretleyip sonra yolu silen ve kişi yazan biri,
     * "under=1&user=ayse" gönderiyordu. Sunucu bunu doğru biçimde
     * reddediyor (400) ama panel, gönderdiği anda geçersiz olduğunu
     * bildiği bir isteği yollamamalı — operatöre çıkışsız bir hata
     * gösterirdi.
     */
    under: under && path.trim() !== "",
    user: user.trim(),
    target: target.trim(),
  };
  /*
   * ⚠️ EN AZ BİR ÖLÇÜT. Üçü de boşken arama "her şeyi göster"e
   * dönerdi ve bu ekranın kaçındığı şey tam olarak o: sorulmamış bir
   * soruya dolu bir ekranla cevap vermek.
   */
  const askable =
    criteria.path !== "" || criteria.user !== "" || criteria.target !== "";

  const search = async () => {
    if (!askable) return;
    setState({ kind: "busy" });
    try {
      setState({ kind: "done", result: await api.fileHistory(criteria) });
    } catch (err: unknown) {
      setState({ kind: "error", msg: toMessage(err) });
    }
  };

  return (
    <section>
      <div className="page-head">
        <h2>File history</h2>
        <p className="page-sub">
          Every SFTP event that matches, newest first — who did it, from where,
          and whether it succeeded. Search by path, by person, by machine, or
          any combination.
        </p>
      </div>

      {/*
        ⚠️ KAPSAM UYARISI SONUÇTAN ÖNCE VE HER ZAMAN GÖRÜNÜR. Yalnızca
        boş sonuçta gösterseydik, dolu bir liste gören denetçi listeyi
        eksiksiz sanırdı — oysa aynı dosya kabuktan da okunmuş olabilir.
      */}
      <WarnLine
        msg={
          "This searches SFTP file events only. A file read or written " +
          "inside an interactive shell — cat, scp over exec, an editor — " +
          "leaves no row here; that trace is in the session recording. " +
          "An empty result means no SFTP event matched, not that nobody " +
          "read the file."
        }
      />

      {/*
        ⚠️ FORM, ÇÜNKÜ ENTER ÇALIŞMALI. Bir arama kutusuna yazıp Enter'a
        basmak refleks; yalnızca düğmeye bağlı bir arama, hiçbir şey
        olmamış gibi görünürdü.
      */}
      <form
        className="card"
        onSubmit={(e) => {
          e.preventDefault();
          void search();
        }}
      >
        {/*
          ⚠️ card-body ŞART, SÜS DEĞİL. `.card`ın kendi dolgusu YOK
          (styles.css: yalnızca kenarlık ve yuvarlatma); dolguyu
          `.card-head`/`.card-body` veriyor. Sarmalayıcı olmadan etiket
          kartın üst kenarına yapışıyor ve alan kenardan kenara
          uzuyordu — panelin geri kalanının hiçbir yerinde öyle
          durmuyor.
        */}
        <div className="card-body">
          <div className="wfield">
            <label className="wfield-label" htmlFor="file-history-path">
              Path
            </label>
            <input
              id="file-history-path"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="/etc/shadow"
              autoComplete="off"
              spellCheck={false}
            />
            {/*
              ⚠️ EŞLEŞMENİN NASIL YAPILDIĞI YAZILI VE KİPE GÖRE
              DEĞİŞİYOR. "/etc" yazıp altındaki her şeyi bekleyen biri
              tam eşleşmede boş sonuç alır ve onu "dokunulmamış" diye
              okur — bu ekranın en pahalı yanlış anlaması.
            */}
            <p className="small muted">
              {under
                ? "Treated as a directory: everything at or below it. A neighbour that merely starts with the same letters (/etcetera) is not included."
                : "Matched exactly, not as a prefix — and the path is the one the client asked for, as the server recorded it."}
            </p>
            {/* .toggle: SyncPanel'in kullandığı sınıf. Yeni bir stil
                uydurmak, aynı işi yapan iki onay kutusu görünümü
                demek olurdu. */}
            <label className="toggle">
              <input
                type="checkbox"
                checked={under}
                onChange={(e) => setUnder(e.target.checked)}
                disabled={path.trim() === ""}
              />
              <span>Everything under this directory</span>
            </label>
          </div>

          {/*
            ⚠️ KİŞİ VE MAKİNE SUNUCUDA SÜZÜLÜYOR, TABLODA DEĞİL.
            Aşağıdaki tablonun kendi filtre kutusu yalnızca GELEN
            satırları süzüyor ve sunucu en fazla 200 satır dönüyor:
            oraya "ayse" yazan denetçi, ayse'nin 500 olayı varken boş
            sonuç görebilir — ve onu "ayse dokunmamış" diye okur.
          */}
          <div className="wfield">
            <label className="wfield-label" htmlFor="file-history-user">
              Person
            </label>
            <input
              id="file-history-user"
              value={user}
              onChange={(e) => setUser(e.target.value)}
              placeholder="ayse"
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div className="wfield">
            <label className="wfield-label" htmlFor="file-history-target">
              Target
            </label>
            <input
              id="file-history-target"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="web01"
              autoComplete="off"
              spellCheck={false}
            />
            <p className="small muted">
              Any one of these three is enough. Leave the path empty to ask what
              one person did, or what happened on one machine.
            </p>
          </div>

          <div className="card-actions">
            <ActionButton
              variant="primary"
              label="search the file history"
              disabled={!askable || state.kind === "busy"}
              onClick={search}
            >
              {state.kind === "busy" ? "Searching…" : "Search"}
            </ActionButton>
          </div>
        </div>
      </form>

      {state.kind === "error" && <ErrorLine msg={state.msg} />}
      {state.kind === "done" && <Result result={state.result} />}
    </section>
  );
}

/*
 * Result, bulunanı çizer.
 *
 * ⚠️ ARANAN YOL BAŞLIKTA TEKRARLANIYOR. Kutuya başka bir şey yazıp
 * aramayı unutan biri, önceki aramanın sonucunu yenisi sanabilirdi.
 */
function Result({ result }: { result: History }) {
  const q = result.path;

  if (result.events.length === 0) {
    return (
      <div className="card">
        <div className="card-body">
          <h3>Nothing found</h3>
          {/*
            ⚠️ NE ARANDIĞI TEKRARLANIYOR. Üç kutulu bir formda, hangi
            ölçütlerle arandığını göstermeyen bir "bulunamadı", yanlış
            kutuya yazmış birine "dokunulmamış" diye okunur.
          */}
          <p className="page-sub">
            No SFTP event matched <Criteria result={result} />. That is not the
            same as saying the file was never read — see the note above — and it
            is also not the same as saying the path never existed.
          </p>
        </div>
      </div>
    );
  }

  /*
   * ⚠️ SÜTUN SIRASI SORUŞTURMANIN OKUMA SIRASI.
   *
   * Ölçüldü: 11 sütun 1500px'lik bir pencerede 1438px yer istiyor,
   * kapsayıcı 1022px veriyor — 416px yatay taşma. Yani ilk bakışta
   * hangi sütunların görüneceği bir tercih değil, bir karar.
   *
   * İlk hâlinde taşıp kaybolan sütun RESULT'tı: bir denetim ekranında
   * "işlem tuttu mu" sorusunun cevabı. /etc/shadow satırlarında görünen
   * her şey doğruydu ve ekran, erişimin REDDEDİLDİĞİNİ söylemiyordu.
   *
   * Sıra artık: ne zaman → kim → nerede → ne yaptı → hangi dosya →
   * tuttu mu → ne kadar taşındı. Bağlam sütunları (os user, src,
   * session) sona; kaybolurlarsa cevap yine elde kalıyor.
   */
  const columns: Column<FileTouch>[] = [
    {
      key: "at",
      header: "When",
      value: (f) => sortableTime(f.at),
      render: (f) => <Timestamp value={f.at} />,
    },
    {
      key: "user",
      header: "Who",
      value: (f) => f.user,
      // ⚠️ BOŞ KULLANICI GİZLENMİYOR, İŞARETLENİYOR. Sunucu LEFT JOIN
      // kullanıyor: oturum üstverisi okunamayan bir olay yine geliyor
      // ve satırı yutmak, elimizdeki kanıtı saklamak olurdu.
      render: (f) =>
        f.user || (
          <span className="muted" title="session metadata missing">
            —
          </span>
        ),
    },
    { key: "target", header: "Target", value: (f) => f.target },
    { key: "op", header: "Op", value: (f) => f.op },
    {
      key: "path",
      header: "Path",
      className: "wrap",
      value: (f) => `${f.path} ${f.new_path ?? ""}`,
      /*
       * ⚠️ EŞLEŞMENİN HANGİ YARIDA OLDUĞU YAZILIYOR. Aranan yol
       * `new_path`teyse, dosya oraya bir rename ile GELMİŞ demektir ve
       * satırdaki `path` bambaşka bir yol gösterir. İşaretlemeseydik,
       * denetçi aradığı dosyayı hiç görünmeyen bir satır sanırdı.
       */
      render: (f) => (
        <>
          <code title={f.path}>{f.path}</code>
          {f.new_path && (
            <>
              {" → "}
              <code title={f.new_path}>{f.new_path}</code>
            </>
          )}
          {/*
            ⚠️ AĞAÇ KİPİNDE DE İŞARETLENİYOR. Aranan "/tmp" ise ve
            dosya "/tmp/exfil"e rename ile geldiyse, eşleşme yine
            new_path'te — rozeti yalnızca tam eşleşmeye bağlamak,
            sızdırmanın en ucuz biçimini tam da onu arayan kipte
            işaretsiz bırakırdı.
          */}
          {f.new_path && matchesQuery(f.new_path, result) && (
            <span className="badge" title="the file arrived at this path here">
              {" "}
              moved here
            </span>
          )}
        </>
      ),
    },
    {
      key: "ok",
      header: "Result",
      value: (f) => (f.ok ? "ok" : "denied"),
      // Reddedilen bir işlem, engelin çalıştığının kanıtı: silinmiyor,
      // işaretleniyor.
      render: (f) =>
        f.ok ? (
          "ok"
        ) : (
          <span className="bad" title={f.detail}>
            denied{f.detail ? ` — ${f.detail}` : ""}
          </span>
        ),
    },
    {
      key: "read",
      header: "Read",
      value: (f) => f.read,
      render: (f) => bytes(f.read),
    },
    {
      key: "wrote",
      header: "Wrote",
      value: (f) => f.wrote,
      render: (f) => bytes(f.wrote),
    },
    { key: "os_user", header: "OS user", value: (f) => f.os_user },
    { key: "src", header: "Src", value: (f) => f.src_ip },
    {
      key: "session",
      header: "Session",
      value: (f) => f.session_id,
      render: (f) => (
        <code title={f.session_id}>{f.session_id.slice(0, 12)}…</code>
      ),
    },
  ];

  return (
    <DataTable
      rows={result.events}
      columns={columns}
      rowKey={(f) => f.id}
      initialSort={{ key: "at", dir: "desc" }}
      noun="event"
      searchLabel="filter these events by user, target or operation"
      searchPlaceholder="Filter events…"
      foot={
        <p>
          Events matching <Criteria result={result} />. Copy a session id into
          the Sessions screen to see everything else that session did.
          {/*
            ⚠️ KESİLDİYSE SÖYLE. Sessizce ilk N'i göstermek, denetçinin
            "olan biten bu" sanması demek.

            ⚠️ "DAHA ESKİLERİ VAR" DEMİYOR, "OLMAYABİLİR" DİYOR. Sunucu
            bunu tam sayıdan anlıyor (len == limit) ve tam da sınırda
            duran bir liste, gerçekten sınıra dayanmış da olabilir tesadüfen
            o kadar da olabilir. Var olmayan kayıtları var diye bildirmek,
            yok olanları yok saymak kadar yanlış.
          */}
          {result.truncated &&
            ` postern stopped at the ${result.limit} most recent events, so this may not be the whole history.`}
        </p>
      }
    />
  );
}

/*
 * matchesQuery, bir yolun aramanın ölçütüne uyup uymadığı.
 *
 * Sunucudaki koşulun panel tarafındaki karşılığı — yalnızca "moved
 * here" rozetini çizmek için. Satırın sonuca GİRİP girmediğine sunucu
 * karar veriyor; burası yalnızca eşleşmenin hangi yarıda olduğunu
 * söylüyor.
 */
function matchesQuery(p: string, result: History): boolean {
  if (result.path === "") return false;
  if (!result.under) return p === result.path;
  // ⚠️ KÖK DİZİN AYRI: "/" + "/" iki eğik çizgi eder ve hiçbir yol
  // öyle başlamaz. Sunucu "/" altında her şeyi döndürürken panel
  // hiçbirini işaretlemezdi.
  if (result.path === "/") return p.startsWith("/");
  return p === result.path || p.startsWith(result.path + "/");
}

/*
 * Criteria, aramanın NE olduğunu tek satırda yazar.
 *
 * ⚠️ KUTUYA BAŞKA BİR ŞEY YAZIP ARAMAYI UNUTAN BİRİ, önceki aramanın
 * sonucunu yenisi sanabilirdi. Ölçütler sunucunun cevabından geliyor,
 * formun o anki hâlinden değil — yani gösterilen şey, gerçekten
 * çalıştırılan arama.
 */
function Criteria({ result }: { result: History }) {
  const parts: React.ReactNode[] = [];
  if (result.path) {
    parts.push(
      <span key="p">
        {result.under ? "under " : ""}
        <code>{result.path}</code>
      </span>,
    );
  }
  if (result.user) {
    parts.push(
      <span key="u">
        by <code>{result.user}</code>
      </span>,
    );
  }
  if (result.target) {
    parts.push(
      <span key="t">
        on <code>{result.target}</code>
      </span>,
    );
  }
  return (
    <>
      {parts.map((p, i) => (
        <span key={i}>
          {i > 0 ? ", " : ""}
          {p}
        </span>
      ))}
    </>
  );
}
