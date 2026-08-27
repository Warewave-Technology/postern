import { useEffect, useState } from "react";
import { api, Me } from "./api";
import Users from "./admin/Users";
import Targets from "./admin/Targets";
import Roles from "./admin/Roles";
import { AdminLog, Sessions } from "./admin/Audit";

// Rota kütüphanesi yok: beş sekmelik bir panel için useState yeter.
// (S4.3'te terminal sayfası eklenince gerekirse gerçek router'a geçeriz.)
type Tab = "home" | "users" | "targets" | "roles" | "sessions" | "log";

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>("home");

  useEffect(() => {
    api.me().then(setMe).catch(() => setMe(null)).finally(() => setLoading(false));
  }, []);

  if (loading) return null;

  if (!me) {
    return (
      <main style={{ fontFamily: "system-ui", maxWidth: "28rem", margin: "4rem auto" }}>
        <h1>postern</h1>
        <a href="/auth/login">Sign in with your identity provider →</a>
      </main>
    );
  }

  const tabs: [Tab, string][] = me.admin
    ? [["home", "Home"], ["users", "Users"], ["targets", "Targets"], ["roles", "Roles"], ["sessions", "Sessions"], ["log", "Admin log"]]
    : [["home", "Home"]];

  return (
    <main style={{ fontFamily: "system-ui", maxWidth: "60rem", margin: "2rem auto", padding: "0 1rem" }}>
      <header style={{ display: "flex", gap: "1rem", alignItems: "baseline" }}>
        <h1 style={{ marginRight: "auto" }}>postern</h1>
        <span>{me.name}{me.admin && " (admin)"}</span>
        <form method="post" action="/auth/logout"><button>Sign out</button></form>
      </header>
      <nav style={{ display: "flex", gap: "0.75rem", margin: "1rem 0" }}>
        {tabs.map(([t, label]) => (
          <button key={t} onClick={() => setTab(t)} disabled={tab === t}>{label}</button>
        ))}
      </nav>

      {tab === "home" && (
        <section>
          <h2>Your targets</h2>
          {me.targets.length === 0 ? <p>No targets granted.</p> : (
            <ul>{me.targets.map((t) => <li key={t}>{t}</li>)}</ul>
          )}
        </section>
      )}
      {tab === "users" && <Users />}
      {tab === "targets" && <Targets />}
      {tab === "roles" && <Roles />}
      {tab === "sessions" && <Sessions />}
      {tab === "log" && <AdminLog />}
    </main>
  );
}
