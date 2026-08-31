import { ReactNode, useCallback, useEffect, useRef, useState } from "react";
import {
  ApiError,
  AuthMethods,
  api,
  Me,
  onSessionLost,
  toMessage,
} from "./api";
import { ErrorLine } from "./admin/common";
import Users from "./admin/Users";
import Targets from "./admin/Targets";
import Roles from "./admin/Roles";
import { AdminLog, Sessions } from "./admin/Audit";
import Mappings from "./admin/Mappings";
import Pending from "./admin/Pending";
import AuthSource from "./admin/AuthSource";
import Settings from "./admin/Settings";
import Setup from "./admin/Setup";
import ChangePassword from "./ChangePassword";
import Overview from "./admin/Overview";
import Home from "./Home";
import ShellPage, { shellTargetFromPath } from "./ShellPage";
import ThemeSwitch from "./theme/ThemeSwitch";
import { useThemeMode } from "./theme/mode";
import {
  DirectoryIcon,
  KeyIcon,
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
  | "setup"
  | "overview"
  | "users"
  | "roles"
  | "mappings"
  | "pending"
  | "targets"
  | "signin"
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
      ["pending", "Pending", <UsersIcon key="i" />],
    ],
  },
  {
    title: "Infrastructure",
    items: [["targets", "Targets", <TargetIcon key="i" />]],
  },
  {
    /*
     * ⚠️ "Directory" DEĞİL.
     *
     * Bu grup üç kaynağın da evi: yerel hesaplar, kimlik sağlayıcısı ve
     * dizin. "Directory" başlığı üçünden yalnızca birinde doğruydu —
     * OIDC kurulumunda kullanıcı bir dizin aramaya, yerel kurulumda ise
     * olmayan bir dizini yapılandırmaya çıkıyordu.
     *
     * Kaynağa göre başlık YAZDIRMADIK: her modda doğru olan tek bir
     * kelime, üç koşullu daldan hem daha kısa hem daha az kırılgan.
     */
    title: "Identity",
    items: [
      ["signin", "Sign-in", <KeyIcon key="i" />],
      ["ldap", "LDAP", <DirectoryIcon key="i" />],
    ],
  },
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

/*
 * LocalSignIn, postern'in kendi kapısı.
 *
 * ⚠️ BURASI BİR PAROLA KUTUSU DEĞİL. Değeri kullanıcı seçmiyor;
 * `postern admin bootstrap` üretiyor ve bir kez basıyor. Metinlerin
 * "password" değil "secret" demesi bu yüzden: kullanıcının buraya
 * kurumsal parolasını yazma refleksini beslememek gerekiyor. Sunucu
 * zaten biçimi tutmayan bir değeri hiç doğrulamıyor, ama arayüzün de
 * aynı şeyi söylemesi lazım.
 */
function LocalSignIn({
  onDone,
  directory = false,
}: {
  onDone: () => void;
  /*
   * ⚠️ AYNI FORM, BAMBAŞKA BİR SIR.
   *
   * Dizin kapısı açıkken buraya KURUMSAL parola yazılıyor; yerel kapıda
   * ise makinenin ürettiği bir sır. Metinleri ayırmamak, kullanıcıya
   * "her zaman aynı şeyi yaz" öğretmenin en kısa yolu — ve o alışkanlık,
   * kurumsal parolanın yanlış kutuya girildiği gün pahalıya patlar.
   */
  directory?: boolean;
}) {
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    api
      .localLogin(username.trim(), secret)
      .then(onDone)
      .catch((err: unknown) => setError(toMessage(err)))
      .finally(() => setBusy(false));
  };

  return (
    <form className="local-signin" onSubmit={submit}>
      <label>
        Username
        <input
          value={username}
          autoComplete="username"
          onChange={(e) => setUsername(e.target.value)}
        />
      </label>
      <label>
        {directory ? "Directory password" : "Sign-in secret"}
        <input
          type="password"
          value={secret}
          // ⚠️ Yerelde current-password DEĞİL: tarayıcının parola
          // yöneticisine makine üretimi bir sırrı "parola" diye
          // kaydettirmek, kullanıcıyı tam da kaçındığımız zihniyete
          // iten ilk adım. Dizin kipinde ise gerçekten parola.
          autoComplete={directory ? "current-password" : "one-time-code"}
          onChange={(e) => setSecret(e.target.value)}
        />
      </label>
      <ErrorLine msg={error} />
      <button
        className="btn btn-primary"
        disabled={busy || !username || !secret}
      >
        {busy ? "Signing in…" : "Sign in"}
      </button>
      {directory ? (
        <p className="note">
          Your directory username and the password you use everywhere else.
          postern checks it against the directory and never stores it. Your SSH
          access does not use this password — that is your key.
        </p>
      ) : (
        <p className="note">
          Generated by <code>postern admin bootstrap</code> on the bastion host.
          If this is a new install and you do not have one, run it there.
        </p>
      )}
    </form>
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
  // methods, sunucunun HANGİ giriş yollarını sunduğu. null = henüz
  // sorulmadı; giriş ekranı bu cevaba göre çiziliyor, varsayıma göre
  // değil.
  const [methods, setMethods] = useState<AuthMethods | null>(null);
  const [top, setTop] = useState<Top>("home");
  const [section, setSection] = useState<Section>("overview");

  /*
   * ⚠️ KURULUM YAPILMAMIŞSA PANEL SADECE SİHİRBAZDAN İBARET.
   *
   * Bir menü maddesi olarak bırakıldığında atlanıyordu ve geriye
   * kaynağı seçilmemiş — kapısı config dosyasından TÜRETİLEN — bir
   * kurulum kalıyordu. Ürünün en kritik kararı, keşfedilmeyi bekleyen
   * bir bağlantı olamaz.
   *
   * Karar SUNUCUDAN geliyor (setup_required): panelin kendi çıkarımı
   * olsaydı, ikinci bir doğruluk kaynağı olurdu.
   */
  const needsSetup = me?.setup_required === true;

  /*
   * ⚠️ YEREL KAYNAKTA GRUP DİYE BİR ŞEY YOK.
   *
   * Kodda doğrulandı: hiçbir RolesForGroups çağrısı yerel giriş
   * yolunda değil, ve onay kuyruğuna yazma (admitOrQueue /
   * ErrAccountNotProvisioned) yalnızca kaynak kapılarından geçiyor.
   * Yani yerel modda Mappings ve Pending ekranları hiçbir şeye
   * bakmıyor. Boş duran iki menü maddesi, operatöre "burada bir şey
   * yapmam gerekiyor mu" diye sordurur ve eşleme yapıp neden
   * çalışmadığını aratır.
   *
   * Kaynak değiştiğinde geri geliyorlar: karar sunucudan okunuyor,
   * panelin kendi çıkarımı değil.
   */
  const [sourceIsLocal, setSourceIsLocal] = useState(false);
  useEffect(() => {
    if (!me?.admin || needsSetup) return;
    api
      .authSource()
      .then((st) => setSourceIsLocal(st.source === "local"))
      .catch(() => {
        // Menüyü daraltmak bir kolaylık; hatası ekranı bozmamalı.
      });
  }, [me?.admin, needsSetup]);

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

    // Giriş yollarını AYRI soruyoruz: /api/me 401 dönse de bu cevap
    // gerekiyor, çünkü tam da o durumda giriş ekranı çiziliyor.
    // Başarısızlığı ekranı bozmamalı — cevap gelmezse düğme
    // çizilmiyor ve kullanıcı en azından yanlış yönlendirilmiyor.
    api.authMethods().then(setMethods, () => setMethods(null));
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
              : methods?.oidc
                ? "Access is granted by your identity provider. postern never sees your password."
                : methods?.ldap
                  ? "Sign in with your directory account. postern checks your password against the directory and never stores it."
                  : "This bastion signs in with its own credentials."}
          </p>
          {/*
            ⚠️ DÜĞME SUNUCUNUN CEVABINA GÖRE. Eskiden koşulsuz
            çiziliyordu çünkü OIDC'siz bir panel diye bir şey yoktu.
            Artık var, ve o kurulumda bu düğme 404'e gider — kullanıcı
            ürünün bozuk olduğunu düşünürdü.
          */}
          {methods?.oidc && (
            <a className="btn btn-primary" href="/auth/login">
              Sign in with your identity provider
            </a>
          )}

          {methods?.local && <LocalSignIn onDone={loadMe} />}
          {methods?.ldap && <LocalSignIn onDone={loadMe} directory />}

          {methods && !methods.oidc && !methods.local && !methods.ldap && (
            <p className="msg msg-warn" role="status">
              No sign-in method is available on this bastion. On the host, run{" "}
              <code>postern admin bootstrap</code> to create the first
              administrator, or configure an identity provider.
            </p>
          )}
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
    ? [
        ["home", "Home"],
        ["settings", "Settings"],
      ]
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

      {/*
        ⚠️ PAROLA DEĞİŞTİRİLMEDEN BAŞKA HİÇBİR ŞEY YOK — ve bu kontrol
        kurulum sihirbazından da ÖNCE.

        Sıra kasıtlı: yönetici tarafından verilen değeri veren de
        biliyor, yani bu hâldeki bir oturum henüz "o kişinin" oturumu
        değil. O oturuma kurulum sihirbazını açmak, kurulumun tamamını
        değeri bilen ikinci kişiye açmak olurdu.

        Asıl koruma sunucuda (requireSession, weblogin.go): ekranın
        doğru çizilmesine güvenerek açık bırakılan bir kapı, kapalı
        değildir. Buradaki iş yalnızca kullanıcıya çıkış yolunu
        göstermek.
      */}
      {me.must_change_password && (
        <main className="app">
          <ChangePassword
            name={me.name}
            policy={me.password_policy}
            onDone={() => {
              // Sunucu belirteci yeniledi ve kısıt kalktı. /api/me'yi
              // yeniden okumak yerine sayfayı tazeliyoruz: ekranın her
              // parçası artık farklı bir yetkiyle çiziliyor.
              window.location.assign("/");
            }}
          />
        </main>
      )}

      {/*
        ⚠️ KURULUM BİTMEDİYSE BAŞKA HİÇBİR ŞEY YOK.
        Sekmeler ve bölümler çizilmiyor: yarım kurulmuş bir bastion'ın
        yönetim ekranlarını gezdirmek, ayarları kaynağı seçilmeden
        değiştirmeye davet etmek olurdu.
      */}
      {!me.must_change_password && needsSetup && me.admin && (
        <main className="app">
          <Setup meName={me.name} dirBound={me.dir_bound} />
        </main>
      )}

      {/* Kurulum bitmemiş ve YÖNETİCİ DEĞİLSE: girecek yer yok, ama
          sebebini söylüyoruz — boş bir ekran arıza gibi görünürdü. */}
      {!me.must_change_password && needsSetup && !me.admin && (
        <main className="center">
          <div className="center-card">
            <h1>Not set up yet</h1>
            <p>
              This bastion has not finished its first-run setup. An
              administrator has to choose how people sign in before it can be
              used.
            </p>
          </div>
        </main>
      )}

      {!me.must_change_password && !needsSetup && (
        <>
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
                  {NAV.map((group, gi) => {
                    // Kaynağa bağlı ekranlar yerel modda listelenmiyor.
                    const items = group.items.filter(
                      ([s]) =>
                        !sourceIsLocal || (s !== "mappings" && s !== "pending"),
                    );
                    if (items.length === 0) return null;
                    return (
                      <div className="side-group" key={group.title ?? `g${gi}`}>
                        {group.title && (
                          <div className="side-title">{group.title}</div>
                        )}
                        {items.map(([s, label, icon]) => (
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
                    );
                  })}
                </nav>

                <div>
                  {section === "setup" && (
                    <Setup meName={me.name} dirBound={me.dir_bound} />
                  )}
                  {section === "overview" && <Overview />}
                  {section === "users" && (
                    <Users publicKeyLogin={me.public_key_login} />
                  )}
                  {section === "roles" && <Roles />}
                  {section === "mappings" && <Mappings />}
                  {section === "pending" && <Pending />}
                  {section === "targets" && <Targets />}
                  {section === "signin" && <AuthSource />}
                  {section === "ldap" && <Settings meName={me.name} />}
                  {section === "sessions" && <Sessions theme={resolved} />}
                  {section === "log" && <AdminLog />}
                </div>
              </div>
            )}
          </main>
        </>
      )}
    </div>
  );
}
