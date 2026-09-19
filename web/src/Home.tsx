import { useMemo, useState } from "react";
import { Me, MyTarget, api } from "./api";
import { ErrorLine, ListState, Timestamp, useList } from "./admin/common";
import { HostIcon, SearchIcon } from "./icons";
import ShellMenu from "./ShellMenu";
import { targetURL } from "./TargetPage";
import { Fields, describe as explain, matches, parse } from "./query";
import { groupTargets } from "./grouping";

/**
 * Home — herkesin ekranı: erişebildiğin makineler.
 *
 * KUTU, SATIR DEĞİL: bir hedefin adı, etiketleri ve son görülme bilgisi
 * bir satıra sığmıyordu; sığdırmaya çalışmak ya etiketleri kesiyor ya
 * satırı okunmaz yapıyordu. Kutu, her hedefe kendi alanını veriyor ve
 * göz taraması ızgarada satırdan hızlı.
 */

const seenFmt = new Intl.DateTimeFormat(undefined, {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

function toFields(t: MyTarget): Fields {
  return {
    name: t.name,
    labels: t.labels,
    extra: { version: t.server_version ?? "" },
  };
}

/**
 * openShell, tam ekran kabuğu YENİ SEKMEDE açar.
 *
 * ⚠️ noopener: açılan sekme window.opener üzerinden bu sayfayı
 * yönlendirebilirdi. Aynı kaynak olduğu için tehlike düşük ama bedeli
 * de sıfır, ve kabuk sayfası ileride ayrı bir kaynağa taşınabilir.
 */
export function shellURL(target: string): string {
  return `/shell/${encodeURIComponent(target)}`;
}

/*
 * shellHint, sayfa altındaki örnek komut.
 *
 * Adres bilinmiyorsa yer tutucu kalıyor — uydurma bir adres yazmak,
 * kopyalayan kişiyi yanlış makineye göndermek olurdu.
 */
function shellHint(me: Me): string {
  const target = "<target>";
  if (!me.ssh_host) return `ssh ${me.name}:${target}@<bastion>`;
  const p = me.ssh_port && me.ssh_port !== 22 ? `-p ${me.ssh_port} ` : "";
  return `ssh ${p}${me.name}:${target}@${me.ssh_host}`;
}

/**
 * TargetCard — bir hedefin kutusu.
 *
 * ⚠️ AYRI BİR BİLEŞEN, ÇÜNKÜ İKİ YERDE ÇİZİLİYOR: düz ızgarada ve
 * gruplanmış düzende. Kopyalamak, kartın bir yerde düzeltilip öbüründe
 * eskimesi demekti.
 */
function TargetCard({ t, me }: { t: MyTarget; me: Me }) {
  return (
    <article className="tcard">
      <header className="tcard-head">
        {/*
                ⚠️ TIKLANABİLİR OLAN AD, KARTIN TAMAMI DEĞİL.
                
                Kartın içinde bir menü düğmesi var; kartı komple
                bağlantıya çevirmek, menüye her basışta sayfayı da
                değiştirirdi. Ayrıca bağlantı olarak <a> kullanmak
                orta tık ve "yeni sekmede aç" davranışını
                koruyor — bir onClick sarmalayıcısı ikisini de
                kaybettirirdi.
              */}
        <a className="tcard-name" href={targetURL(t.name)}>
          <HostIcon />
          {t.name}
        </a>
        {/*
                ⚠️ MENÜ, web terminali KAPALI olsa da çiziliyor.
                Eskiden düğme tamamen terminale bağlıydı ve
                terminali kapatan kurulumda kartta hiçbir eylem
                kalmıyordu — oysa ssh komutu o kurulumda da
                geçerli, hatta tek yol o.
              */}
        <ShellMenu
          target={t.name}
          user={me.name}
          sshHost={me.ssh_host}
          sshPort={me.ssh_port}
          connectHref={me.terminal_enabled ? shellURL(t.name) : undefined}
        />
      </header>

      <div className="tcard-body">
        {Object.keys(t.labels).length === 0 ? (
          <span className="muted small">no labels</span>
        ) : (
          <div className="chips">
            {Object.entries(t.labels).map(([k, v]) => (
              <span key={k} className="label-chip">
                <span className="k">{k}</span>
                <span className="v">{v}</span>
              </span>
            ))}
          </div>
        )}
      </div>

      <footer className="tcard-foot">
        {/*
                ⚠️ SÜRELİ HAK KARTTA YAZIYOR: "temporary until …".
                Hak bitince kutu kaybolacak; bunu önceden söylemeyen
                bir kart, kaybolduğu gün bir arıza gibi okunur.
              */}
        {t.temporary && (
          <span
            className="badge badge-warn"
            title={`granted by ${t.temporary.granted_by}`}
          >
            temporary until <Timestamp value={t.temporary.until} />
          </span>
        )}
        {/*
                Gözlemler: bağlanmadan önce sorulmaya değer sorular.
                "Hiç bağlanılmadı" ile "dün bağlanıldı" arasındaki
                fark, bir makinenin gerçekten ayakta olup olmadığı.
              */}
        {t.last_seen_at ? (
          <span title={t.last_seen_at}>
            last reached {seenFmt.format(new Date(t.last_seen_at))}
          </span>
        ) : (
          <span>never reached from this bastion</span>
        )}
        {t.server_version && (
          <code title={t.server_version}>
            {t.server_version.replace(/^SSH-2\.0-/, "")}
          </code>
        )}
      </footer>
    </article>
  );
}

export default function Home({ me }: { me: Me }) {
  const { items, error, denied, loading, failed } = useList<MyTarget>(
    api.myTargets,
  );
  const [q, setQ] = useState("");

  const query = useMemo(() => parse(q), [q]);
  const shown = useMemo(
    () => items.filter((t) => matches(query, toFields(t))),
    [items, query],
  );

  const searching = q.trim() !== "";

  /*
   * ⚠️ ÖNCE SÜZ, SONRA GRUPLA. Tersi, aramanın boşalttığı bir başlığı
   * ekranda bırakırdı: "shop" yazan bir öbek altında hiç kart olmadan
   * durur ve okuyan onu bir arıza sanardı.
   *
   * null = gruplanacak bir şey yok (hiçbir hedefte app ya da env
   * label'ı yok); o hâlde bugünkü düz ızgara çiziliyor.
   */
  const groups = useMemo(() => groupTargets(shown), [shown]);

  return (
    <section>
      <div className="page-head">
        <h2>Your targets</h2>
        <p className="page-sub">
          The hosts your groups reach. Every session through them is recorded.
        </p>
      </div>

      <ErrorLine msg={error} />

      <ListState
        loading={loading}
        denied={denied}
        failed={failed}
        empty={items.length === 0}
        emptyText="No targets granted. An administrator has to grant your group a target before you can connect."
      />

      {items.length > 0 && (
        <>
          <div className="search-bar">
            <div className="search">
              <SearchIcon />
              <input
                type="search"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                aria-label="filter targets by name or label"
                placeholder="name: web and env: prod"
              />
              {searching && (
                <button
                  type="button"
                  className="search-clear"
                  onClick={() => setQ("")}
                  aria-label="clear the filter"
                >
                  ×
                </button>
              )}
            </div>
            <span className="count" role="status">
              {searching
                ? `${shown.length} of ${items.length}`
                : `${items.length} target${items.length === 1 ? "" : "s"}`}
            </span>
          </div>

          {/*
            Sorgunun NASIL ANLAŞILDIĞI yazılıyor. Sonuç boş çıktığında
            "eşleşme yok" tek başına yetmiyor: kullanıcı sorgusunu mu
            yanlış yazdı yoksa gerçekten mi yok, ayırt edemiyor.
          */}
          {searching && (
            <p className="query-echo">
              Looking for: <b>{explain(query)}</b>
            </p>
          )}

          {/* Süzgeç ile sonuç arasında ayırıcı: ikisi bitişik durunca tek
              bir öbek gibi okunuyordu. */}
          <hr className="list-sep" />

          {shown.length === 0 ? (
            <p className="state">
              Nothing matches that filter. Try a label like{" "}
              <code>env: prod</code>, or clear the box.
            </p>
          ) : groups === null ? (
            <div className="card-grid">
              {shown.map((t) => (
                <TargetCard key={t.name} t={t} me={me} />
              ))}
            </div>
          ) : (
            /*
              ⚠️ BAŞLIK BİR LABEL'IN DEĞERİ, UYDURULMUŞ BİR AD DEĞİL.
              "Others" ve "Other env" ise label'ı olmayanların yeri ve
              her zaman en sonda duruyor — alfabetik sıraya karışsalardı
              göz onları aramayı öğrenemezdi.
            */
            groups.map((g) => (
              <section key={g.app} className="tgroup">
                <h3 className="tgroup-head">
                  <span className={g.other ? "muted" : undefined}>{g.app}</span>
                  <span className="tgroup-count">
                    {g.count} {g.count === 1 ? "machine" : "machines"}
                  </span>
                </h3>
                {g.envs.map((e) => (
                  <div key={e.env} className="tgroup-env">
                    <h4 className="tgroup-env-head">
                      <span className={e.other ? "muted" : undefined}>
                        {e.env}
                      </span>
                    </h4>
                    <div className="card-grid">
                      {e.targets.map((t) => (
                        <TargetCard key={t.name} t={t} me={me} />
                      ))}
                    </div>
                  </div>
                ))}
              </section>
            ))
          )}
        </>
      )}

      <p className="note">
        {/*
          ⚠️ ADRES BİLİNİYORSA YER TUTUCU YAZILMIYOR.
          
          Kart menüsü gerçek adresli bir komut kopyalatırken bu notun
          "<bastion>" demesi, aynı sayfada iki farklı gerçek gösterirdi
          ve okuyan hangisinin doğru olduğunu bilemezdi.
        */}
        {me.terminal_enabled ? (
          <>
            From a shell, connect with <code>{shellHint(me)}</code>.
          </>
        ) : (
          <>
            The browser terminal is switched off on this bastion. Connect over
            SSH: <code>{shellHint(me)}</code>
          </>
        )}
      </p>
    </section>
  );
}
