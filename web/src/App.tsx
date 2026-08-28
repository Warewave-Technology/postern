import { useCallback, useEffect, useState } from "react";
import { ApiError, api, Me, toMessage } from "./api";
import Users from "./admin/Users";
import Targets from "./admin/Targets";
import Roles from "./admin/Roles";
import { AdminLog, Sessions } from "./admin/Audit";
import Mappings from "./admin/Mappings";
import Settings from "./admin/Settings";
import Terminal from "./Terminal";

// Rota kütüphanesi yok: sekiz sekmelik bir panel için useState yeter.
type Tab = "home" | "users" | "targets" | "roles" | "mappings" | "settings" | "sessions" | "log";

/**
 * GateMark, ürünün işareti: bir postern küçük bir yan kapıdır.
 *
 * Satır içi SVG, dosya değil — CSP img-src 'self' data: olsa da harici
 * bir varlık istemiyoruz ve tek renkli bir işaret currentColor ile
 * temayı kendiliğinden takip ediyor.
 */
function GateMark({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
      {/* Kemer + eşik + orta dikme: ilk denemede tek nokta vardı ve
          16px'te ZİL gibi okunuyordu. Orta dikme iki kanatlı bir kapı
          yapıyor, şekli tartışmasız hale getiriyor. */}
      <path
        d="M3.4 13.8V6.9a4.6 4.6 0 0 1 9.2 0v6.9"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <path d="M1.7 13.8h12.6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M8 13.8V2.4" stroke="currentColor" strokeWidth="1.1" opacity="0.55" />
    </svg>
  );
}

/** HostMark, hedef satırlarındaki küçük sunucu işareti. */
function HostMark() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <rect x="2.2" y="2.8" width="11.6" height="4.6" rx="1.3" stroke="currentColor" strokeWidth="1.3" />
      <rect x="2.2" y="8.6" width="11.6" height="4.6" rx="1.3" stroke="currentColor" strokeWidth="1.3" />
      <circle cx="4.9" cy="5.1" r="0.75" fill="currentColor" />
      <circle cx="4.9" cy="10.9" r="0.75" fill="currentColor" />
    </svg>
  );
}

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  // unreachable, "oturum yok" ile "sunucuya ulaşamıyorum"u AYIRIR.
  const [unreachable, setUnreachable] = useState("");
  const [tab, setTab] = useState<Tab>("home");
  const [terminal, setTerminal] = useState<string | null>(null);

  const loadMe = useCallback(() => {
    setLoading(true);
    setUnreachable("");
    api
      .me()
      .then((v) => setMe(v))
      .catch((e: unknown) => {
        // ⚠️ Eskiden HER hata "giriş yapmamışsın" ekranına düşüyordu.
        // Yani veritabanı çökmüşken kullanıcıya "oturum aç" deniyor, o
        // da IdP'ye gidip geri dönüyor ve aynı arızaya düşüyordu —
        // çıkışı olmayan bir döngü. Reddetmek dürüst olmalı: ne
        // olduğunu bilmiyorsak öyle diyeceğiz.
        setMe(null);
        if (!(e instanceof ApiError && e.status === 401)) {
          setUnreachable(toMessage(e));
        }
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadMe();
  }, [loadMe]);

  // Oturum öncesi üç ekran da ortalanmış tek kart: kullanıcının o anda
  // yapabileceği tek şey ekranın ortasında dursun.
  if (loading) {
    return (
      <main className="center">
        <div className="center-card">
          <span className="brand">
            <GateMark size={18} />
            postern
          </span>
          <p className="state">Loading…</p>
        </div>
      </main>
    );
  }

  if (unreachable) {
    return (
      <main className="center">
        <div className="center-card">
          <span className="brand">
            <GateMark size={18} />
            postern
          </span>
          <h1>Cannot reach the bastion</h1>
          <p className="msg msg-error" role="alert">
            {unreachable}
          </p>
          <p>
            This is not a sign-in problem — postern answered, but not with your
            identity. Signing in again will not help until it recovers.
          </p>
          <button className="btn-primary" onClick={loadMe}>
            Retry
          </button>
        </div>
      </main>
    );
  }

  if (!me) {
    return (
      <main className="center">
        <div className="center-card">
          <span className="brand">
            <GateMark size={18} />
            postern
          </span>
          <h1>Sign in</h1>
          <p>
            Access is granted by your identity provider. postern never sees your
            password.
          </p>
          <a className="btn btn-primary" href="/auth/login">
            Sign in with your identity provider
          </a>
        </div>
      </main>
    );
  }

  const tabs: [Tab, string][] = me.admin
    ? [["home", "Home"], ["users", "Users"], ["targets", "Targets"], ["roles", "Roles"],
       ["mappings", "Mappings"], ["settings", "LDAP"], ["sessions", "Sessions"], ["log", "Admin log"]]
    : [["home", "Home"]];

  const closeTerminal = () => {
    // Onay: açık bir kabuk kapatmak geri alınamaz ve kullanıcı komutun
    // ortasında olabilir.
    if (window.confirm("Close the terminal? The session will end.")) {
      setTerminal(null);
    }
  };

  return (
    <div className="shell">
      <header className="topbar">
        <div className="topbar-inner">
          <span className="brand">
            <GateMark />
            postern
          </span>
          <div className="account">
            <span className="who">{me.name}</span>
            {me.admin && <span className="badge badge-accent">admin</span>}
            <form method="post" action="/auth/logout">
              <button className="btn-quiet">Sign out</button>
            </form>
          </div>
        </div>
      </header>

      <nav className="tabs" aria-label="Sections">
        <div className="tabs-inner">
          {tabs.map(([t, label]) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              // ⚠️ disabled DEĞİL aria-current. disabled, bulunulan
              // sekmeyi sekme sırasından ÇIKARIYOR ve ekran okuyucuya
              // "kullanılamaz" dedirtiyordu — klavye kullanıcısı olduğu
              // yere odaklanamıyordu.
              aria-current={tab === t ? "page" : undefined}
            >
              {label}
            </button>
          ))}
        </div>
      </nav>

      <main className="app">
        {/*
          Terminal sekmeden BAĞIMSIZ ve monte kalıyor.

          Eskiden yalnızca "home" sekmesinde çiziliyordu, yani oturumlara
          bakmak için sekme değiştiren kullanıcının çalışan kabuğu
          uyarısız ölüyordu (unmount ws.close çağırıyor). Gizlemek
          yeterli: React ağacı korunuyor, WebSocket yaşıyor.
        */}
        {terminal && (
          <div hidden={tab !== "home"}>
            <Terminal target={terminal} onClose={closeTerminal} />
          </div>
        )}

        {tab === "home" && !terminal && (
          <section className="narrow">
            <div className="page-head">
              <h2>Your targets</h2>
              <p className="page-sub">
                The hosts your roles reach. Every session through them is
                recorded.
              </p>
            </div>

            {me.targets.length === 0 ? (
              <p className="state">
                No targets granted. An administrator has to grant your role a
                target before you can connect.
              </p>
            ) : (
              <div className="card">
                <ul className="rows">
                  {me.targets.map((t) => (
                    <li key={t} className="row">
                      <span className="row-name">
                        <HostMark />
                        {t}
                      </span>
                      {me.terminal_enabled && (
                        <button
                          onClick={() => setTerminal(t)}
                          aria-label={`open terminal to ${t}`}
                        >
                          Open terminal
                        </button>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <p className="note">
              {me.terminal_enabled ? (
                <>
                  From a shell, connect with{" "}
                  <code>ssh {me.name}:&lt;target&gt;@&lt;bastion&gt;</code>.
                </>
              ) : (
                <>
                  The browser terminal is switched off on this bastion. Connect
                  over SSH: <code>ssh {me.name}:&lt;target&gt;@&lt;bastion&gt;</code>
                </>
              )}
            </p>
          </section>
        )}

        {tab === "users" && <Users />}
        {tab === "targets" && <Targets />}
        {tab === "roles" && <Roles />}
        {tab === "mappings" && <Mappings />}
        {tab === "settings" && <Settings />}
        {tab === "sessions" && <Sessions />}
        {tab === "log" && <AdminLog />}
      </main>
    </div>
  );
}
