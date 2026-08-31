import { useEffect, useState } from "react";
import { AuthSourceStatus, api, toMessage } from "../api";
import { ActionButton, ErrorLine, OkLine } from "./common";

/**
 * Aktif giriş kaynağı.
 *
 * ⚠️ ÜRÜNÜN EN KİLİTLENME EĞİLİMLİ EKRANI. Yanlış kaynağa geçmek paneli
 * herkese kapatır — düzeltecek kişiye de. Bu yüzden ekran hiçbir
 * seçeneği "dener misin" diye sunmuyor: sunucu her seçenek için o
 * kapının gerçekten birini içeri alabildiğini önceden hesaplıyor,
 * alamıyorsa seçenek kapalı geliyor ve NEDEN kapalı olduğu yazıyor.
 *
 * Üç şey ekranda kalmak zorunda:
 *   1. Aynı anda tek kapı açık; birine geçmek diğerlerini kapatır.
 *   2. Seçilmemiş bir kurulumda kaynak TÜRETİLİYOR — "seçtim" ile
 *      "öyle denk geldi" aynı şey değil.
 *   3. Her hâlde host'tan geri dönüş yolu var, ve komutu burada yazıyor.
 */

const LABEL: Record<string, string> = {
  local: "postern's own credentials",
  oidc: "Identity provider (OIDC)",
  ldap: "Directory (LDAP)",
};

const BLURB: Record<string, string> = {
  local:
    "postern's own accounts. Administrators get a break-glass secret issued on the host with `postern admin issue`; everyone else can be given a sign-in value from the Users screen and sets their own password on first use.",
  oidc: "The browser goes to your identity provider. Administrator comes from the group claim — postern cannot list who is in it beforehand.",
  ldap: "Directory username and corporate password, checked against the directory and never stored. Only directory users who already have a postern account can sign in.",
};

export default function AuthSource() {
  const [status, setStatus] = useState<AuthSourceStatus | null>(null);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  const load = () =>
    api
      .authSource()
      .then(setStatus)
      .catch((e: unknown) => setError(toMessage(e)));

  useEffect(() => {
    void load();
    // yalnızca ilk çizimde
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const switchTo = (src: string) => {
    setError("");
    setDone("");
    return api
      .setAuthSource(src)
      .then((r) => {
        setDone(r.note);
        return load();
      })
      .catch((e: unknown) => setError(toMessage(e)));
  };

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Sign-in</h2>
          <p className="page-sub">
            Which source opens the panel. <b>Only one at a time</b> — switching
            to one closes the others. This does not touch SSH: server access is
            proved with a key and stays working whatever is chosen here.
          </p>
        </div>
      </div>

      <ErrorLine msg={error} />
      <OkLine msg={done} />

      {status && (
        <>
          {/*
            ⚠️ "SEÇİLDİ" İLE "TÜRETİLDİ" AYRI. Ayarı hiç yazmamış bir
            kurulumda kaynak config dosyasından çıkarılıyor; bunu
            "seçildi" gibi göstermek, operatöre hiç vermediği bir kararı
            verdiğini düşündürürdü.
          */}
          {!status.stored && (
            <p className="msg msg-warn" role="status">
              <b>Nothing is stored, so this was derived.</b> postern is using{" "}
              <code>{status.source}</code> because that is what the config file
              implies. Choosing one below writes it down, and the answer stops
              depending on a file nobody has read in a year.
            </p>
          )}

          {/*
            ⚠️ Kaynak değişiminin sessiz maliyeti: eşlemeler yerinde
            kalır ama hiçbiri tutmaz. Sonuç "grup gelmiyor" ile birebir
            aynı görünür ve operatör yanlış yerde arar.
          */}
          {!!status.unseen_mappings?.length && (
            <p className="msg msg-warn" role="status">
              <b>
                {status.unseen_mappings.length} mapping(s) name a group postern
                has never seen.
              </b>{" "}
              Mappings survive a source change — but the group names do not: a
              directory says <code>sysadmins</code>, a claim may say something
              else entirely, and a mapping that no longer matches looks exactly
              like a source that sends no groups at all. Not seen yet:{" "}
              <code>{status.unseen_mappings.join(", ")}</code>
            </p>
          )}

          <div className="card">
            <div className="card-body">
              {status.options.map((o) => {
                const active = o.source === status.source;
                return (
                  <div className="source-row" key={o.source}>
                    <div>
                      <h3>
                        {LABEL[o.source] ?? o.source}{" "}
                        {active && (
                          <span className="badge badge-ok">active</span>
                        )}
                      </h3>
                      <p className="note">{BLURB[o.source]}</p>
                      {/*
                        Seçenek kapalıysa SEBEBİ yazıyor. Gri bir düğme
                        gösterip susmak, operatöre config dosyasında ne
                        eksik olduğunu aratırdı.
                      */}
                      {!o.eligible && !active && (
                        <p className="msg msg-warn" role="status">
                          {o.why}
                        </p>
                      )}
                    </div>
                    <div>
                      {active ? (
                        <span className="muted">in use</span>
                      ) : (
                        <ActionButton
                          variant="primary"
                          disabled={!o.eligible}
                          label={`switch panel sign-in to ${o.source}`}
                          confirm={
                            `Switch panel sign-in to ${LABEL[o.source] ?? o.source}?` +
                            `\n\nEvery other sign-in method closes. Open sessions keep working;` +
                            `\nthe next sign-in goes through this one.` +
                            `\n\nTo undo it from the bastion host:` +
                            `\n  postern settings set --key auth.source --value local`
                          }
                          onClick={() => switchTo(o.source)}
                        >
                          Use this
                        </ActionButton>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/*
            Parola politikası YALNIZCA yerel kaynakta çiziliyor.

            ⚠️ Diğer iki kaynakta postern parola DOĞRULAMIYOR: dizinde
            bind ediyor, kimlik sağlayıcıda belirteç alıyor. Orada bir
            parola kuralı göstermek, postern'in uygulayamadığı bir kural
            vaat etmek olurdu — ve operatör onu sıkılaştırıp korunduğunu
            sanırdı.
          */}
          {status.source === "local" && <PasswordPolicyBox />}

          {/*
            ⚠️ ÇIKIŞ YOLU HER ZAMAN GÖRÜNÜR. Bu ekranın en olası kötü
            günü, seçilen kaynağın çalışmaması ve panelin açılmaması —
            yani bu metnin okunamadığı an. O yüzden burada, iyi günde,
            okunacak yerde duruyor.
          */}
          <p className="note">
            If a source stops working and nobody can sign in, this is the way
            back, on the bastion host:
            <br />
            <code>postern settings set --key auth.source --value local</code>
            <br />
            followed by <code>postern admin issue --name &lt;name&gt;</code> if
            no local administrator has a secret.
          </p>
        </>
      )}
    </section>
  );
}

/**
 * Parola politikası.
 *
 * ⚠️ TEK DÜĞME UZUNLUK ve bu kasıtlı. "Büyük harf + rakam + sembol
 * şart" kuralı bilerek yok: ölçülen sonucu insanların "Parola1!"
 * yazması ve kuralın sağlanmış olması. Ürettiği şey tahmin edilebilir
 * bir kalıp, entropi değil. Gerisi taban ve kapatılamıyor — bir ayar
 * gibi görünen "politikayı kapat" düğmesi olmasın diye.
 */
function PasswordPolicyBox() {
  const [value, setValue] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  useEffect(() => {
    api
      .settings()
      .then((rows) => {
        const row = rows.find((r) => r.key === "password.min_length");
        setValue(row?.value ?? "12");
        setLoaded(true);
      })
      .catch((e: unknown) => setError(toMessage(e)));
  }, []);

  const save = () => {
    setError("");
    setDone("");
    return api
      .setSetting("password.min_length", value.trim())
      .then(() =>
        setDone("Saved. It applies to the next password anyone sets."),
      )
      .catch((e: unknown) => setError(toMessage(e)));
  };

  return (
    <div className="card">
      <div className="card-head">
        <h3>Password policy</h3>
        <p>
          What postern accepts when somebody sets their own password. Only
          length is a setting — the rest is a floor and cannot be switched off.
        </p>
      </div>
      <div className="card-body">
        {error && <ErrorLine msg={error} />}
        {done && <OkLine msg={done} />}

        <div className="source-row">
          <div>
            <label>
              Minimum length
              <input
                type="number"
                min={8}
                max={256}
                value={value}
                disabled={!loaded}
                onChange={(e) => setValue(e.target.value)}
              />
            </label>
            <p className="page-sub">
              Between 8 and 256. The lower bound is not adjustable: a policy
              that can be turned off from the panel is not a policy.
            </p>
          </div>
          <div>
            <ActionButton onClick={save} label="save password policy">
              Save
            </ActionButton>
          </div>
        </div>

        <ul className="policy-list">
          <li>Not one of the most commonly chosen passwords</li>
          <li>Must not contain the account name, or “postern”</li>
          <li>Not a run of neighbouring keys (qwerty…, abcdef…, 123456…)</li>
          <li>At least 5 different characters</li>
        </ul>

        <p className="note">
          Administrators are not covered: their credential is a break-glass
          secret issued on the host and can never be a password.
        </p>
      </div>
    </div>
  );
}
