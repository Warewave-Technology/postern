import { ReactNode, useCallback, useEffect, useState } from "react";
import { ApiError, api, Me, toMessage } from "./api";
import Users from "./admin/Users";
import Targets from "./admin/Targets";
import Roles from "./admin/Roles";
import { AdminLog, Sessions } from "./admin/Audit";
import Mappings from "./admin/Mappings";
import Settings from "./admin/Settings";
import Overview from "./admin/Overview";
import Terminal from "./Terminal";
import {
  DirectoryIcon,
  GateMark,
  HostIcon,
  LogIcon,
  MapIcon,
  PlayIcon,
  PulseIcon,
  RolesIcon,
  TargetIcon,
  UsersIcon,
} from "./icons";

// Rota kütüphanesi yok: iki üst sekme ve bir kenar listesi için useState
// yeter. URL'de yer tutmamanın bedeli, paylaşılabilir bağlantı olmaması.
type Top = "home" | "settings";
type Section =
  | "overview"
  | "users"
  | "roles"
  | "mappings"
  | "targets"
  | "ldap"
  | "sessions"
  | "log";

/*
 * Kenar listesi GRUPLANMIŞ.
 *
 * Sekiz düz madde bir liste değil yığın olur; "erişimi kim veriyor",
 * "nereye bağlanılıyor", "ne olmuş" ayrı sorular ve ayrı başlıklar
 * altında durmaları hangi ekranda ne aranacağını söylüyor.
 */
const NAV: { title?: string; items: [Section, string, ReactNode][] }[] = [
  { items: [["overview", "Overview", <PulseIcon key="i" />]] },
  {
    title: "Access",
    items: [
      ["users", "Users", <UsersIcon key="i" />],
      ["roles", "Roles", <RolesIcon key="i" />],
      ["mappings", "Mappings", <MapIcon key="i" />],
    ],
  },
  { title: "Infrastructure", items: [["targets", "Targets", <TargetIcon key="i" />]] },
  { title: "Directory", items: [["ldap", "LDAP", <DirectoryIcon key="i" />]] },
  {
    title: "Audit",
    items: [
      ["sessions", "Sessions", <PlayIcon key="i" />],
      ["log", "Admin log", <LogIcon key="i" />],
    ],
  },
];

function Brand({ size = 20 }: { size?: number }) {
  return (
    <span className="brand">
      <GateMark size={size} />
      <span className="brand-word">postern</span>
    </span>
  );
}

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  // unreachable, "oturum yok" ile "sunucuya ulaşamıyorum"u AYIRIR.
  const [unreachable, setUnreachable] = useState("");
  const [top, setTop] = useState<Top>("home");
  const [section, setSection] = useState<Section>("overview");
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
        // çıkışı olmayan bir döngü. Reddetmek dürüst olmalı.
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
          <Brand size={22} />
          <p className="state">Loading…</p>
        </div>
      </main>
    );
  }

  if (unreachable) {
    return (
      <main className="center">
        <div className="center-card">
          <Brand size={22} />
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
          <Brand size={22} />
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

  const closeTerminal = () => {
    // Onay: açık bir kabuk kapatmak geri alınamaz ve kullanıcı komutun
    // ortasında olabilir.
    if (window.confirm("Close the terminal? The session will end.")) {
      setTerminal(null);
    }
  };

  // Home HERKESİN ekranı; geri kalan her şey yönetim ve Settings'in
  // altında. Admin olmayan için Settings sekmesi HİÇ çizilmiyor —
  // görünüp 403 vermek, olmayan bir yetkiyi vaat etmektir.
  const tops: [Top, string][] = me.admin
    ? [["home", "Home"], ["settings", "Settings"]]
    : [["home", "Home"]];

  return (
    <div className="shell">
      <header className="topbar">
        <div className="topbar-inner">
          <Brand />
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
          {tops.map(([t, label]) => (
            <button
              key={t}
              onClick={() => setTop(t)}
              // ⚠️ disabled DEĞİL aria-current. disabled, bulunulan
              // sekmeyi sekme sırasından ÇIKARIYOR ve ekran okuyucuya
              // "kullanılamaz" dedirtiyordu.
              aria-current={top === t ? "page" : undefined}
            >
              {label}
            </button>
          ))}
        </div>
      </nav>

      <main className="app">
        {/*
          Terminal üst sekmeden BAĞIMSIZ ve monte kalıyor.

          Eskiden yalnızca kendi sekmesinde çiziliyordu, yani başka bir
          ekrana bakmak için sekme değiştiren kullanıcının çalışan kabuğu
          uyarısız ölüyordu (unmount ws.close çağırıyor). Gizlemek
          yeterli: React ağacı korunuyor, WebSocket yaşıyor.
        */}
        {terminal && (
          <div hidden={top !== "home"}>
            <Terminal target={terminal} onClose={closeTerminal} />
          </div>
        )}

        {top === "home" && !terminal && (
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
                        <HostIcon />
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

        {top === "settings" && me.admin && (
          <div className="settings">
            <nav className="side-nav" aria-label="Settings sections">
              {NAV.map((group, gi) => (
                <div className="side-group" key={group.title ?? `g${gi}`}>
                  {group.title && <div className="side-title">{group.title}</div>}
                  {group.items.map(([s, label, icon]) => (
                    <button
                      key={s}
                      onClick={() => setSection(s)}
                      aria-current={section === s ? "page" : undefined}
                    >
                      {icon}
                      {label}
                    </button>
                  ))}
                </div>
              ))}
            </nav>

            <div>
              {section === "overview" && <Overview />}
              {section === "users" && <Users />}
              {section === "roles" && <Roles />}
              {section === "mappings" && <Mappings />}
              {section === "targets" && <Targets />}
              {section === "ldap" && <Settings />}
              {section === "sessions" && <Sessions />}
              {section === "log" && <AdminLog />}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
