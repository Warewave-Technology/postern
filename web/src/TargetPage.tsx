import { useEffect, useState } from "react";
import { Me, MyTargetDetail, api, toMessage } from "./api";
import { ErrorLine } from "./admin/common";
import { HostIcon } from "./icons";
import ShellMenu from "./ShellMenu";

/*
 * TargetPage — kullanıcının tek bir hedefi.
 *
 * NEDEN AYRI SAYFA: kart, ızgarada bir satır kadar yer tutuyor ve
 * oraya sığmayan şeyler var — etiketlerin tamamı ve kişinin o hedefteki
 * kendi oturum geçmişi. Kartı büyütmek ızgarayı okunmaz yapardı.
 *
 * ⚠️ ADRES YOK. Sunucu host/port göndermiyor (httpapi/targets.go) ve
 * bu bilinçli: kullanıcı hedefe postern üzerinden bağlanıyor. Adresi
 * göstermek, bir bastion'ın varlık sebebi olan "ağ topolojisini
 * kullanıcıya açmama"yı panelden sızdırırdı.
 */

/*
 * targetFromPath, /target/<ad> yolundan hedefi çıkarır.
 *
 * Rota kütüphanesi yok — /shell/<ad> ile aynı gerekçe (ShellPage.tsx).
 * Sunucu bilinmeyen yollara index.html döndüğü için bu sayfa adres
 * çubuğuna yazılarak da açılıyor, yani bağlantısı paylaşılabilir.
 */
export function targetFromPath(pathname: string): string | null {
  const m = /^\/target\/([^/]+)\/?$/.exec(pathname);
  if (!m) return null;
  try {
    const name = decodeURIComponent(m[1]);
    return name.trim() === "" ? null : name;
  } catch {
    // Bozuk yüzde kaçışı: adres uydurulmuş demektir.
    return null;
  }
}

export function targetURL(name: string): string {
  return `/target/${encodeURIComponent(name)}`;
}

const stamp = (v: string) => new Date(v).toLocaleString();

export default function TargetPage({ me, name }: { me: Me; name: string }) {
  const [t, setT] = useState<MyTargetDetail | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .myTarget(name)
      .then(setT)
      .catch((e: unknown) => setError(toMessage(e)));
  }, [name]);

  if (error) {
    return (
      <section>
        {/*
          ⚠️ Erişimi olmayan hedef ile OLMAYAN hedef aynı cevabı
          alıyor (sunucuda 404). Ekranın da ikisini ayırmaması
          gerekiyor, yoksa envanteri adları deneyerek çıkarmak
          mümkün olurdu.
        */}
        <div className="page-head">
          <h2>Target</h2>
        </div>
        <ErrorLine msg={error} />
        <p className="note">
          <a href="/">Back to your targets</a>
        </p>
      </section>
    );
  }
  if (!t) return null;

  const labels = Object.entries(t.labels ?? {});

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2 className="target-title">
            <HostIcon />
            <code>{t.name}</code>
          </h2>
          <p className="page-sub">
            Every session through this host is recorded.
          </p>
        </div>
        <ShellMenu
          target={t.name}
          user={me.name}
          sshHost={me.ssh_host}
          sshPort={me.ssh_port}
          connectHref={
            me.terminal_enabled
              ? `/shell/${encodeURIComponent(t.name)}`
              : undefined
          }
        />
      </div>

      <div className="card">
        <div className="card-head">
          <h3>What postern knows</h3>
        </div>
        <div className="card-body">
          <dl className="kv">
            <dt>Last reached</dt>
            <dd className="prose">
              {t.last_seen_at
                ? stamp(t.last_seen_at)
                : /*
                     ⚠️ "Hiç ulaşılmadı" ile "bilinmiyor" ayrı: hedef
                     yeni eklenmiş olabilir de erişilemiyor olabilir de,
                     ve panel hangisi olduğunu bilmiyor.
                   */
                  "never reached from this bastion"}
            </dd>
            {t.server_version && (
              <>
                <dt>SSH server</dt>
                <dd>{t.server_version}</dd>
              </>
            )}
          </dl>

          {labels.length === 0 ? (
            <p className="muted small">no labels</p>
          ) : (
            <div className="chips">
              {labels.map(([k, v]) => (
                <span key={k} className="label-chip">
                  <span className="k">{k}</span>
                  <span className="v">{v}</span>
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h3>Your sessions here</h3>
          {/*
            ⚠️ YALNIZCA KENDİ oturumları. Aynı hedefe başkalarının ne
            zaman bağlandığı bir denetim sorusu ve yönetici ekranında
            duruyor; burada göstermek, sıradan bir kullanıcıya
            meslektaşlarının çalışma saatlerini verirdi.
          */}
          <p>The last ten times you opened a session on this host.</p>
        </div>
        <div className="card-body">
          {t.sessions_error ? (
            /* ⚠️ Sunucu bunu zaten log'a yazıyordu; eksik olan aynı
               ayrımın EKRANDA olmasıydı. Log'daki bir uyarıyı
               kullanıcı görmüyor. */
            <p className="msg msg-warn">
              Your history for this host could not be read, so this is not a
              statement that you have never connected to it.
            </p>
          ) : t.sessions.length === 0 ? (
            <p className="state">You have not connected to this host yet.</p>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Ended</th>
                  <th>As</th>
                </tr>
              </thead>
              <tbody>
                {t.sessions.map((s) => (
                  <tr key={s.id}>
                    <td>{stamp(s.started)}</td>
                    {/* Bitmemiş oturum: "—" değil, hâlâ açık olduğunu söyle. */}
                    <td>{s.ended ? stamp(s.ended) : "still open"}</td>
                    <td>
                      <code>{s.os_user}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <p className="note">
        <a href="/">Back to your targets</a>
      </p>
    </section>
  );
}
