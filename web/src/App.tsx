import { ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api, Me, onSessionLost, toMessage } from "./api";
import Users from "./admin/Users";
import Targets from "./admin/Targets";
import Roles from "./admin/Roles";
import { AdminLog, Sessions } from "./admin/Audit";
import Mappings from "./admin/Mappings";
import Settings from "./admin/Settings";
import Overview from "./admin/Overview";
import Home from "./Home";
import ShellPage, { shellTargetFromPath } from "./ShellPage";
import ThemeSwitch from "./theme/ThemeSwitch";
import { useThemeMode } from "./theme/mode";
import {
  DirectoryIcon,
  GateMark,
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
  const [mode, setMode, resolved] = useThemeMode();
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  // unreachable, "oturum yok" ile "sunucuya ulaşamıyorum"u AYIRIR.
  const [unreachable, setUnreachable] = useState("");
  // expired, "hiç giriş yapmadın" ile "oturumun bitti"yi AYIRIR: ikisi
  // de giriş ekranını gösteriyor ama ikincisinde ne olduğunu söylemek
  // gerekiyor — yoksa kullanıcı çalışırken neden atıldığını bilmiyor.
  const [expired, setExpired] = useState(false);
  const [top, setTop] = useState<Top>("home");
  const [section, setSection] = useState<Section>("overview");

  // ⚠️ Kabuk artık PANELİN İÇİNDE DEĞİL, kendi sekmesinde (/shell/…).
  // Panel içindeki terminal ekranın yarısını çevre kabuğa veriyordu ve
  // sekme değiştirmek çalışan oturumu gizliyordu. Kendi sekmesinde
  // açılan bir kabuk, kullanıcının zaten alışkın olduğu şey.
  const shellTarget = shellTargetFromPath(window.location.pathname);

  /*
   * Oturum HERHANGİ BİR uçta düşerse giriş ekranına dön.
   *
   * ⚠️ Alt sayfalar 401'i kendi hata satırlarında çiziyordu ve sonuç,
   * yönetim ekranında "Error: unauthenticated" yazısıyla oturup kalan
   * bir kullanıcıydı: ekrandaki her sayı artık geçersiz ama ekran
   * duruyor. Dinleyici api.ts'te tek yerde — sayfa sayfa yakalamak,
   * bir sonraki eklenen sayfayı unutmak demekti.
   */
  const meRef = useRef<Me | null>(null);
  meRef.current = me;

  useEffect(() => {
    onSessionLost(() => {
      // Yalnızca OTURUM VARKEN anlamlı: açılışta /api/me zaten 401
      // döndürüyor ve o "bitti" değil, "hiç başlamadı".
      if (meRef.current) {
        setMe(null);
        setExpired(true);
      }
    });
  }, []);

  const loadMe = useCallback(() => {
    setLoading(true);
    setUnreachable("");
    api
      .me()
      .then((v) => {
        setMe(v);
        setExpired(false);
      })
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
          <div className="center-top">
            <Brand size={22} />
            <ThemeSwitch mode={mode} onChange={setMode} />
          </div>
          <h1>{expired ? "Session ended" : "Sign in"}</h1>
          <p>
            {expired
              ? "Your session is no longer valid, so the screen you were on was showing figures that had stopped being true. Sign in again to continue."
              : "Access is granted by your identity provider. postern never sees your password."}
          </p>
          <a className="btn btn-primary" href="/auth/login">
            Sign in with your identity provider
          </a>
        </div>
      </main>
    );
  }

  // /shell/<target>: tam ekran kabuk. Kimlik kontrolü YUKARIDA yapıldı,
  // yani bu sayfa da oturum istiyor — adres çubuğuna yazarak atlanamaz.
  if (shellTarget) {
    return (
      <ShellPage
        target={shellTarget}
        mode={mode}
        onMode={setMode}
        resolved={resolved}
      />
    );
  }

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
            <ThemeSwitch mode={mode} onChange={setMode} />
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
        {top === "home" && <Home me={me} />}

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
              {section === "users" && <Users publicKeyLogin={me.public_key_login} />}
              {section === "roles" && <Roles />}
              {section === "mappings" && <Mappings />}
              {section === "targets" && <Targets />}
              {section === "ldap" && <Settings />}
              {section === "sessions" && <Sessions theme={resolved} />}
              {section === "log" && <AdminLog />}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
