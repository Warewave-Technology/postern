import { useMemo, useState } from "react";
import { Me, MyTarget, api } from "./api";
import { ErrorLine, ListState, useList } from "./admin/common";
import { ExternalIcon, HostIcon, SearchIcon, ShellIcon } from "./icons";
import { Fields, describe as explain, matches, parse } from "./query";

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

export default function Home({ me }: { me: Me }) {
  const { items, error, denied, loading } = useList<MyTarget>(api.myTargets);
  const [q, setQ] = useState("");

  const query = useMemo(() => parse(q), [q]);
  const shown = useMemo(
    () => items.filter((t) => matches(query, toFields(t))),
    [items, query],
  );

  const searching = q.trim() !== "";

  return (
    <section>
      <div className="page-head">
        <h2>Your targets</h2>
        <p className="page-sub">
          The hosts your roles reach. Every session through them is recorded.
        </p>
      </div>

      <ErrorLine msg={error} />

      <ListState
        loading={loading}
        denied={denied}
        empty={items.length === 0}
        emptyText="No targets granted. An administrator has to grant your role a target before you can connect."
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
          ) : (
            <div className="card-grid">
              {shown.map((t) => (
                <article key={t.name} className="tcard">
                  <header className="tcard-head">
                    <span className="tcard-name">
                      <HostIcon />
                      {t.name}
                    </span>
                    {me.terminal_enabled && (
                      <a
                        className="btn btn-primary btn-shell"
                        href={shellURL(t.name)}
                        target="_blank"
                        rel="noopener noreferrer"
                        aria-label={`open a shell on ${t.name} in a new tab`}
                      >
                        <ShellIcon />
                        Shell
                        <ExternalIcon />
                      </a>
                    )}
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
              ))}
            </div>
          )}
        </>
      )}

      <p className="note">
        {me.terminal_enabled ? (
          <>
            From a shell, connect with{" "}
            <code>ssh {me.name}:&lt;target&gt;@&lt;bastion&gt;</code>.
          </>
        ) : (
          <>
            The browser terminal is switched off on this bastion. Connect over
            SSH: <code>ssh {me.name}:&lt;target&gt;@&lt;bastion&gt;</code>
          </>
        )}
      </p>
    </section>
  );
}
