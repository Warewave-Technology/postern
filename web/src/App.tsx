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

  if (loading) {
    return (
      <main className="app">
        <h1>postern</h1>
        <p className="state">Loading…</p>
      </main>
    );
  }

  if (unreachable) {
    return (
      <main className="app">
        <h1>postern</h1>
        <p className="msg msg-error" role="alert">
          {unreachable}
        </p>
        <p className="muted small">
          This is not a sign-in problem — postern answered, but not with your
          identity. Signing in again will not help until it recovers.
        </p>
        <button onClick={loadMe}>Retry</button>
      </main>
    );
  }

  if (!me) {
    return (
      <main className="app" style={{ maxWidth: "28rem" }}>
        <h1>postern</h1>
        <a href="/auth/login">Sign in with your identity provider →</a>
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
    <main className="app">
      <header className="app-header">
        <h1>postern</h1>
        <span className="who">
          {me.name}
          {me.admin && " · admin"}
        </span>
        <form method="post" action="/auth/logout">
          <button>Sign out</button>
        </form>
      </header>

      <nav className="tabs" aria-label="Sections">
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
      </nav>

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
        <section>
          <h2>Your targets</h2>
          {me.targets.length === 0 ? (
            <p className="state">
              No targets granted. An administrator has to grant your role a
              target before you can connect.
            </p>
          ) : (
            <ul>
              {me.targets.map((t) => (
                <li key={t}>
                  <code>{t}</code>{" "}
                  {me.terminal_enabled && (
                    <button
                      className="small"
                      onClick={() => setTerminal(t)}
                      aria-label={`open terminal to ${t}`}
                    >
                      open terminal
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
          {!me.terminal_enabled && (
            <p className="muted small">
              The browser terminal is switched off on this bastion. Connect over
              SSH: <code>ssh {me.name}:&lt;target&gt;@&lt;bastion&gt;</code>
            </p>
          )}
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
  );
}
