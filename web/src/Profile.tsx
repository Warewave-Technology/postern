import { useState } from "react";
import { Me, api, toMessage } from "./api";
import { ErrorLine, OkLine } from "./admin/common";
import Authenticator from "./Authenticator";
import MyKeys from "./MyKeys";

/*
 * Profile — giriş yapan kişinin KENDİ hesabı.
 *
 * NEDEN AYRI BİR SEKME: kimlik doğrulayıcı ve SSH anahtarları ana
 * sayfada, hedef listesinin altında duruyordu. İkisi de "nereye
 * bağlanabilirim" sorusunun cevabı değil, "hesabım nasıl korunuyor"
 * sorusunun cevabı — ve ana sayfayı, her gün bakılan hedef listesiyle
 * yılda bir dokunulan güvenlik ayarlarının karışımı hâline getiriyordu.
 *
 * ⚠️ SAYFA HER ZAMAN BİR ŞEY SÖYLÜYOR. Anahtar girişi kapalı, kimlik
 * doğrulayıcı kurulmamış ve parola dizinden geliyor olabilir — üç kart
 * da çizilmediğinde geriye boş bir sekme kalırdı ve kullanıcı sekmenin
 * BOZUK olduğunu düşünürdü. Kimlik kartı koşulsuz duruyor: hesabın
 * nereden geldiğini ve neyin neden kapalı olduğunu söylüyor.
 */

/*
 * PasswordCard, parolayı GÖNÜLLÜ değiştirme.
 *
 * ⚠️ NEDEN VAR: uç (POST /api/me/password) ilk günden beri duruyordu
 * ama panelde yalnızca ZORUNLU değişiklik akışında çiziliyordu
 * (App.tsx, must_change_password). Parolasının sızdığını düşünen bir
 * kullanıcının onu değiştirmek için hiçbir yolu yoktu — özellik
 * yazılmış, test edilmiş ve çağrılamıyordu.
 *
 * ⚠️ MEVCUT DEĞER SORULUYOR. Sunucu zaten istiyor (password.go) ve
 * gerekçesi orada yazılı: oturumu ele geçiren biri, mevcut değeri
 * bilmeden parolayı kendi seçtiğine çevirip hesabı kalıcı olarak
 * alabilirdi.
 */
function PasswordCard({ me }: { me: Me }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const [busy, setBusy] = useState(false);

  const min = me.password_policy?.min_length ?? 12;
  const tooShort = next.length > 0 && next.length < min;
  const mismatch = again.length > 0 && next !== again;
  const ready = current !== "" && next !== "" && next === again && !tooShort;

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    setOk("");
    api
      .changePassword(current, next)
      .then(() => {
        setOk("Password changed.");
        setCurrent("");
        setNext("");
        setAgain("");
      })
      .catch((err: unknown) => setError(toMessage(err)))
      .finally(() => setBusy(false));
  };

  return (
    <div className="card mykeys">
      <div className="card-head">
        <h3>Password</h3>
        <p>The value you use to sign in to this panel.</p>
      </div>
      <div className="card-body">
        <ErrorLine msg={error} />
        <OkLine msg={ok} />
        <form className="key-form" onSubmit={submit}>
          <label>
            Current password
            <input
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
            />
          </label>
          <label>
            New password
            <input
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
            />
            {/*
              ⚠️ KURALIN TEK KAYNAĞI SUNUCU. Sayıyı ekrana sabit yazmak,
              bir güvenlik kuralının ikinci kopyasını tutmak olurdu ve
              iki kopyadan biri er ya da geç geride kalır.
            */}
            <span className="wfield-hint">At least {min} characters.</span>
          </label>
          <label>
            New password again
            <input
              type="password"
              autoComplete="new-password"
              value={again}
              onChange={(e) => setAgain(e.target.value)}
            />
          </label>
          {tooShort && (
            <p className="msg msg-warn" role="status">
              That is shorter than {min} characters.
            </p>
          )}
          {mismatch && (
            <p className="msg msg-warn" role="status">
              The two new passwords do not match.
            </p>
          )}
          <button className="btn btn-primary" disabled={busy || !ready}>
            {busy ? "Changing…" : "Change password"}
          </button>
        </form>
      </div>
    </div>
  );
}

/*
 * IdentityCard, "ben kimim ve buraya nasıl giriyorum".
 *
 * ⚠️ NEDEN KOŞULSUZ: aşağıdaki kartların her biri kapalı olabiliyor ve
 * SEBEPLERİ farklı — anahtar girişi bastion'da kapalı, parola dizinde
 * yaşıyor, kimlik doğrulayıcı henüz kurulmamış. Sebebi söylemeyen bir
 * ekran, üçünü de "bozuk" diye okutur.
 */
function IdentityCard({ me, source }: { me: Me; source?: string }) {
  const signsInWith =
    me.can_change_password === true
      ? "a password postern holds for you"
      : source === "ldap"
        ? "your organisation's directory"
        : source === "oidc"
          ? "your identity provider"
          : me.admin
            ? "a break-glass secret issued on the host"
            : "your organisation";

  return (
    <div className="card mykeys">
      <div className="card-head">
        <h3>Account</h3>
        <p>Who postern thinks you are, and how you get in.</p>
      </div>
      <div className="card-body">
        <dl className="kv">
          <dt>Username</dt>
          <dd>
            <code>{me.name}</code>
          </dd>
          {/*
            ⚠️ os_user AYRI BİR SATIR. Hedeflerde AÇILAN hesap bu ve
            kullanıcı adıyla aynı olmak zorunda değil; komut satırında
            "ssh yigit:web01@bastion" yazan kişi hedefte "deploy" olarak
            açılıyorsa bunu bir yerden görebilmeli.
          */}
          <dt>On targets you are</dt>
          <dd>
            <code>{me.os_user}</code>
          </dd>
          <dt>You sign in with</dt>
          <dd className="prose">{signsInWith}</dd>
          {me.admin && (
            <>
              <dt>Role</dt>
              <dd className="prose">administrator</dd>
            </>
          )}
        </dl>
      </div>
    </div>
  );
}

export default function Profile({ me, source }: { me: Me; source?: string }) {
  return (
    <section>
      <div className="page-head">
        <h2>Your profile</h2>
        <p className="page-sub">
          Your account and the two things that protect it: an authenticator app
          and the SSH keys that can open a session as you.
        </p>
      </div>

      <IdentityCard me={me} source={source} />

      {me.can_change_password && <PasswordCard me={me} />}

      {/*
        ⚠️ SIRA: kimlik doğrulayıcı ÖNCE. Anahtar kartı, ikinci bir
        anahtar için yeniden doğrulama gerektiğini söylüyor ve çözümü bu
        kart. Altında dursaydı kullanıcı çözümü görmeden çıkmazı okurdu.
      */}
      {/*
        ⚠️ KİMLİK DOĞRULAYICI ANAHTAR GİRİŞİNE BAĞLI. Bugün tek işi
        ikinci bir anahtar eklemeyi yetkilendirmek (mykeys.go); anahtar
        girişi kapalıyken kaydolmak hiçbir şey açmaz ve kullanıcıya
        işlevsiz bir kurulum yaptırmak olurdu.
      */}
      {me.public_key_login && <Authenticator />}

      {/*
        ⚠️ ANAHTAR LİSTESİ HER ZAMAN ÇİZİLİYOR.
        
        ÖLÇÜLEN BOŞLUK: sunucu yalnızca EKLEMEYİ kapatıyor; okuma ve
        silme açık. Kartı public_key_login'e bağlamak, ayar
        kapatıldığında elinde anahtar olan kullanıcıyı onları görmekten
        de iptal etmekten de mahrum bırakıyordu — üstelik iptal, bu
        ekrandaki acil olan işlem. Kapatılan yalnızca ekleme formu.
      */}
      <MyKeys canAdd={me.public_key_login} />
    </section>
  );
}
