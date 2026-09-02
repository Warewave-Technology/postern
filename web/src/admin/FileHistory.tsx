import { useState } from "react";
import { api, FileHistory as History, FileTouch, toMessage } from "../api";
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
  const [state, setState] = useState<State>({ kind: "idle" });

  const search = async () => {
    const q = path.trim();
    if (q === "") return;
    setState({ kind: "busy" });
    try {
      setState({ kind: "done", result: await api.fileHistory(q) });
    } catch (err: unknown) {
      setState({ kind: "error", msg: toMessage(err) });
    }
  };

  return (
    <section>
      <div className="page-head">
        <h2>File history</h2>
        <p className="page-sub">
          Every SFTP event that touched one path, newest first — who did it,
          from where, and whether it succeeded.
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
          "An empty result means no SFTP event touched this path, not that " +
          "nobody read the file."
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
        <div className="wfield">
          <label className="wfield-label" htmlFor="file-history-path">
            Full path
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
            ⚠️ TAM EŞLEŞME OLDUĞU YAZILI. "/etc" yazıp altındaki her şeyi
            bekleyen biri boş sonuç alır ve onu "dokunulmamış" diye okur.
          */}
          <p className="small muted">
            Matched exactly, not as a prefix — and the path is the one the
            client asked for, as the server recorded it.
          </p>
        </div>
        <div className="card-actions">
          <ActionButton
            variant="primary"
            label="search the file history"
            disabled={path.trim() === "" || state.kind === "busy"}
            onClick={search}
          >
            {state.kind === "busy" ? "Searching…" : "Search"}
          </ActionButton>
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
        <h3>
          Nothing found for <code>{q}</code>
        </h3>
        <p className="page-sub">
          No SFTP event recorded against this exact path. That is not the same
          as saying the file was never read — see the note above — and it is
          also not the same as saying the path never existed.
        </p>
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
        f.user || <span className="muted" title="session metadata missing">—</span>,
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
          {f.new_path === q && (
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
    { key: "read", header: "Read", value: (f) => f.read, render: (f) => bytes(f.read) },
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
      render: (f) => <code title={f.session_id}>{f.session_id.slice(0, 12)}…</code>,
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
          Events for <code>{q}</code>. Copy a session id into the Sessions
          screen to see everything else that session did.
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
