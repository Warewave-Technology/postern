import { useCallback, useEffect, useState } from "react";
import { OIDCSettings as Settings, api, toMessage } from "../api";
import { ActionButton, ErrorLine, OkLine, WarnLine } from "./common";

/**
 * Kimlik sağlayıcı (OIDC) ayarları.
 *
 * ⚠️ NEDEN AYRI BİR EKRAN VAR: bu ayarlar bir süre YALNIZCA kurulum
 * sihirbazının içinden yazılabiliyordu. Sihirbaz bir kez bittikten
 * sonra bir daha çizilmiyor, dolayısıyla ilk kurulumda OIDC'yi
 * seçmeyen bir kurulum onu SONRADAN HİÇ yapılandıramıyordu — ve
 * yapılandıramadığı için de kaynağı OIDC'ye çeviremiyordu. Dizin
 * ayarlarının kendi ekranı vardı; bunun yoktu.
 *
 * ⚠️ EKRAN KAYNAKTAN BAĞIMSIZ ÇİZİLİYOR. "OIDC aktif değilse
 * gizleyelim" denebilirdi ve bu, aynı çıkmazın daha küçük bir hâli
 * olurdu: kaynağı OIDC'ye çevirebilmek için önce onu yapılandırmak
 * gerekiyor. LDAP ekranı da aynı sebeple her zaman görünür.
 */
export default function OIDCSettingsScreen() {
  const [state, setState] = useState<Settings | null>(null);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");
  const [loading, setLoading] = useState(true);
  const [denied, setDenied] = useState(false);

  const [issuer, setIssuer] = useState("");
  const [clientID, setClientID] = useState("");
  const [secret, setSecret] = useState("");
  const [groupsClaim, setGroupsClaim] = useState("");
  const [scopes, setScopes] = useState("");

  const load = useCallback((keepFields = false) => {
    setLoading(true);
    return api
      .oidcSettings()
      .then((s) => {
        setState(s);
        setError("");
        if (!keepFields) {
          setIssuer(s.issuer_url);
          setClientID(s.client_id);
        }
      })
      .catch((e: unknown) => {
        const msg = toMessage(e);
        if (/forbidden|unauthorized/i.test(msg)) setDenied(true);
        setError(msg);
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const save = () => {
    setError("");
    setSaved("");
    return api
      .setOIDCSettings(
        issuer.trim(),
        clientID.trim(),
        // ⚠️ Boş bırakmak "DEĞİŞTİRME" demek, "temizle" değil. Boşu
        // temizleme saymak, sırsız bir public client kurulumunu kazayla
        // silmenin yolu olurdu.
        secret === "" ? undefined : secret,
        groupsClaim.trim(),
        scopes.trim(),
      )
      .then((r) => {
        setSecret("");
        setSaved(
          r.live
            ? "saved, and postern reached the provider"
            : "saved, but postern could not reach the provider yet",
        );
        /*
         * ⚠️ SEBEP, YENİDEN OKUMADAN SONRA YAZILIYOR.
         *
         * Önce yazılıyordu ve load() kendi başarısında setError("")
         * çağırdığı için sebep anında SİLİNİYORDU: operatör "saved, but
         * postern could not reach the provider yet" görüyor ama NEDEN
         * ulaşılamadığını hiçbir zaman göremiyordu — oysa cevap
         * genellikle tek satırlık ("connection refused", "x509:
         * certificate signed by unknown authority").
         *
         * Alanlar KORUNUYOR (keepFields): sağlayıcıya ulaşılamadıysa
         * operatör aynı ekranda düzeltecek, yazdıklarının silinmesi
         * işini geri alır.
         */
        return load(true).then(() => {
          if (!r.live && r.error) setError(r.error);
        });
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  const ready = issuer.trim() !== "" && clientID.trim() !== "";

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          {/*
            ⚠️ BAŞLIK PROTOKOLÜN ADI, "Identity provider" DEĞİL.

            Yanındaki madde "LDAP" diyor; ikisi aynı grupta, aynı işi
            yapıyor ve biri protokolüyle öbürü genel bir tabirle
            anılırsa menüde hangisinin ne olduğu okunmuyor. "Identity
            provider" ayrıca LDAP'ı da kapsayan bir tabir — yani
            ayırmak için kullanılan kelime, ayırmıyordu.

            Genel tabir KAYNAK SEÇİMİ ekranında kalıyor ("Identity
            provider (OIDC)"): orada okuyan kişi kavramlar arasında
            seçim yapıyor ve ne olduğunun anlatılması gerekiyor.
            Burada ise zaten o kapıyı seçmiş, hangi kapı olduğunu
            biliyor.
          */}
          <h2>OIDC</h2>
          <p className="page-sub">
            Where the browser goes to prove who somebody is. Configuring this
            does not switch anyone over — the panel opens to whichever source is
            chosen on the <b>Sign-in</b> screen.
          </p>
        </div>
      </div>

      {denied ? (
        <WarnLine msg="You are not an administrator, so these settings are not shown." />
      ) : (
        <>
          <ErrorLine msg={error} />
          <OkLine msg={saved} />

          {loading && !state && <p className="state">Loading…</p>}

          {state && (
            <>
              {/*
                ⚠️ "AYARLI" İLE "ÇALIŞIYOR" AYRI SORULAR ve ayrı
                satırları hak ediyorlar. Ayarlı ama ulaşılamayan bir
                sağlayıcıya geçmek, kimsenin giremediği bir panel
                bırakır — o yüzden ekran ikisini karıştırmıyor.
              */}
              {!state.configured ? (
                <WarnLine msg="Not configured yet. Until it is, the identity provider cannot be chosen as the sign-in source." />
              ) : state.live ? (
                <OkLine msg="postern reached the provider and read its configuration." />
              ) : (
                <WarnLine msg="Configured, but postern has not been able to reach the provider. Signing in through it will fail until that is fixed." />
              )}

              <div className="card">
                <div className="card-head">
                  <h3>Connection</h3>
                  <p>
                    postern reads{" "}
                    <code>&lt;issuer&gt;/.well-known/openid-configuration</code>{" "}
                    from the address below and follows what it finds there.
                  </p>
                </div>
                <div className="card-body">
                  <div className="wizard-form">
                    <div className="wfield">
                      <label className="wfield-label" htmlFor="oidc-issuer">
                        Issuer address
                        <span className="wfield-req">required</span>
                      </label>
                      <input
                        id="oidc-issuer"
                        value={issuer}
                        placeholder="https://idp.example/realms/company"
                        onChange={(e) => setIssuer(e.target.value)}
                      />
                      <p className="wfield-hint">
                        Plain http:// is only accepted for loopback addresses.
                      </p>
                    </div>

                    <div className="wfield">
                      <label className="wfield-label" htmlFor="oidc-client">
                        Client id
                        <span className="wfield-req">required</span>
                      </label>
                      <input
                        id="oidc-client"
                        value={clientID}
                        onChange={(e) => setClientID(e.target.value)}
                      />
                    </div>

                    <div className="wfield">
                      <label className="wfield-label" htmlFor="oidc-secret">
                        Client secret
                      </label>
                      <input
                        id="oidc-secret"
                        type="password"
                        value={secret}
                        placeholder={state.client_secret_set ? "••••••••" : ""}
                        onChange={(e) => setSecret(e.target.value)}
                      />
                      {/*
                        ⚠️ Sır geri OKUNMUYOR — panelin okuyabildiği bir
                        sır, panele erişen herkesin okuyabildiği sırdır.
                      */}
                      <p className="wfield-hint">
                        Stored encrypted and never shown again. Leave it empty
                        to keep the current one. A public client using PKCE has
                        none, and that is a valid setup.
                      </p>
                    </div>
                  </div>

                  {/*
                    ⚠️ SAĞLAYICIYA ÖZEL ALANLAR.

                    postern bunları hep destekliyordu (OIDCConfig'te alan
                    duruyor) ama doldurulacak bir yer yoktu: pratikte
                    "groups" ve "openid email" sabitti. Entra grupları
                    "roles" claim'inde gönderiyor, Okta ve Auth0 ise
                    grupları ancak açıkça istenirse veriyor — o
                    kurulumlarda postern grupsuz kalıyor ve sebebi
                    hiçbir ekranda görünmüyordu.
                  */}
                  <div className="wizard-form">
                    <div className="wfield">
                      <label className="wfield-label" htmlFor="oidc-groups">
                        Groups claim
                      </label>
                      <input
                        id="oidc-groups"
                        value={groupsClaim}
                        placeholder="groups"
                        onChange={(e) => setGroupsClaim(e.target.value)}
                      />
                      <p className="wfield-hint">
                        Which claim in the token carries the group names. Empty
                        means <code>groups</code>. Entra sends them in{" "}
                        <code>roles</code>; some setups use{" "}
                        <code>memberOf</code>. Group names are what the Mappings
                        screen turns into roles.
                      </p>
                    </div>

                    <div className="wfield">
                      <label className="wfield-label" htmlFor="oidc-scopes">
                        Scopes
                      </label>
                      <input
                        id="oidc-scopes"
                        value={scopes}
                        placeholder="openid email profile"
                        onChange={(e) => setScopes(e.target.value)}
                      />
                      <p className="wfield-hint">
                        Space separated. Empty means{" "}
                        <code>openid email profile</code>; <code>openid</code>{" "}
                        is always sent whether you list it or not. Okta and
                        Auth0 only send groups when a scope asks for them.
                      </p>
                    </div>
                  </div>

                  <div className="wizard-check">
                    <ActionButton
                      variant="primary"
                      onClick={save}
                      disabled={!ready}
                      /*
                       * ⚠️ ERİŞİLEBİLİR AD, GÖRÜNEN METNİ İÇERİYOR.
                       * label görünen yazının YERİNE geçiyor; içinde
                       * "Save and test" geçmezse ekranda o yazıyı okuyup
                       * sesle "Save and test" diyen kişinin komutu
                       * hiçbir düğmeyle eşleşmiyor.
                       */
                      label="Save and test the identity provider settings"
                    >
                      Save and test
                    </ActionButton>
                    <span className="note">
                      Saved first, then contacted. If it cannot be reached the
                      settings are still kept — otherwise a provider that is
                      down could never be corrected.
                    </span>
                  </div>

                  {/*
                    ⚠️ HEDEF DEĞİŞİRSE SIR DÜŞÜYOR ve bunu önceden
                    söylüyoruz. Sunucudaki kural: panel yöneticisi
                    issuer'ı kendi sunucusuna çevirip saklanan sırrı
                    oraya gönderemesin. Söylenmezse operatör, sırrın
                    neden kaybolduğunu bir arıza sanır.
                  */}
                  {state.client_secret_set && (
                    <p className="note">
                      Changing the issuer or the client id drops the stored
                      secret: postern will not send a secret it holds for one
                      provider to a different one. You will be asked for it
                      again.
                    </p>
                  )}
                </div>
              </div>

              <AdminGroupCard />

              {!state.managed_in_db && state.configured && (
                <p className="note">
                  These values currently come from the configuration file on the
                  bastion host. Saving here moves them into the database, and
                  the file is no longer consulted.
                </p>
              )}
            </>
          )}
        </>
      )}
    </section>
  );
}

/**
 * Yönetici grubu — kimlik sağlayıcı kurulumu için.
 *
 * ⚠️ NEDEN BURADA DA VAR: aynı ayarın tam hâli DİZİN ekranında yaşıyor
 * ve orası dizin yapılandırılmadan çizilmiyor. OIDC girişinde
 * yöneticilik YALNIZCA grup iddiasından geliyor ve kaynağı OIDC'ye
 * çevirmek grubun ayarlı olmasını şart koşuyor — yani dizini olmayan
 * bir kurulum, ayarı yapamadığı için OIDC'ye hiç geçemiyordu.
 *
 * ⚠️ ÖNİZLEME YOK ve bu bir eksiklik değil, kaynağın gerçeği: bir
 * kimlik sağlayıcıya "bu grupta kimler var" diye sorulamıyor. Cevap
 * yalnızca kişi giriş yaptığında belirtecinde geliyor. Dizin ekranındaki
 * onay listesini burada taklit etmek, veremediğimiz bir güvenceyi
 * veriyormuş gibi yapmak olurdu.
 */
function AdminGroupCard() {
  const [group, setGroup] = useState("");
  const [saved, setSaved] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const [current, setCurrent] = useState<string | null>(null);

  useEffect(() => {
    api
      .adminGroup()
      .then((s) => {
        setCurrent(s.group);
        setGroup(s.group);
      })
      .catch(() => setCurrent(""));
  }, []);

  const save = () => {
    setErr("");
    setSaved(null);
    return api
      .setAdminGroup(group.trim(), [])
      .then((r) => {
        setCurrent(r.group);
        setSaved(
          r.group === ""
            ? "cleared — nobody gets administrator from a group any more"
            : r.deferred
              ? `saved — anyone arriving with “${r.group}” becomes an administrator at their next sign-in`
              : `saved — ${r.granted.length} granted, ${r.revoked.length} revoked`,
        );
      })
      .catch((e: unknown) => setErr(toMessage(e)));
  };

  return (
    <div className="card">
      <div className="card-head">
        <h3>Administrator group</h3>
        <p>
          With the identity provider signed in, administrator comes only from a
          group claim. Nothing else on this panel hands it out.
        </p>
      </div>
      <div className="card-body">
        {err && <ErrorLine msg={err} />}
        {saved && <OkLine msg={saved} />}

        <div className="wizard-form">
          <div className="wfield">
            <label className="wfield-label" htmlFor="oidc-admin-group">
              Group name
            </label>
            <input
              id="oidc-admin-group"
              value={group}
              placeholder="platform-admins"
              onChange={(e) => setGroup(e.target.value)}
            />
            <p className="wfield-hint">
              Exactly as the provider spells it in the token. postern cannot ask
              who is in it — it only sees the claim when somebody signs in, so
              there is no list to check this against beforehand.
            </p>
          </div>
        </div>

        <div className="wizard-check">
          <ActionButton
            variant="primary"
            onClick={save}
            disabled={current === null || group.trim() === current}
            confirm={
              group.trim() === ""
                ? "Clear the administrator group? Everyone who holds administrator through it loses it at their next sign-in."
                : `Set “${group.trim()}” as the administrator group? Anyone whose token carries it becomes an administrator when they sign in — postern cannot show you that list in advance.`
            }
            label="Save the administrator group"
          >
            Save
          </ActionButton>
          <span className="note">
            {/*
              ⚠️ "Şimdi kimse değişmiyor" cümlesi ŞART. Dizin ekranında
              kaydetmek anında yetki dağıtıyor; burada dağıtmıyor ve
              operatörün ikisini aynı sanması, yetkinin uygulanmadığını
              düşünüp ikinci kez uğraşmasına yol açar.
            */}
            Nobody changes right now: each person is evaluated at their own next
            sign-in. Your own break-glass account is not affected either way.
          </span>
        </div>
      </div>
    </div>
  );
}
