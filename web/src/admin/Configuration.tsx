import { useEffect, useState } from "react";
import { ConfigView, api, toMessage } from "../api";
import ArchiveCredential from "./ArchiveCredential";
import { ErrorLine } from "./common";

/**
 * Configuration — host'taki yapılandırma dosyası, salt-okunur.
 *
 * ⚠️ BURADAN HİÇBİR ŞEY DEĞİŞMİYOR, VE BU BİR ÖZELLİK. Dinleme adresi,
 * kayıt hedefi, güven zinciri ve veritabanı makinede duruyor; panelden
 * ele geçirilen bir oturumun bunlara dokunabilmesi, denetim izini
 * yönlendirebilmesi demek olurdu. Ekranın işi, "bu bastion hangi
 * değerlerle koşuyor" sorusunu host'a girmeden cevaplamak.
 *
 * ⚠️ SIR TAŞIYAN ALANLAR ADIYLA LİSTELENİYOR, DEĞERİYLE DEĞİL. Hiç
 * görünmeselerdi operatör ayarın yazılmadığını sanıp ikinci kez yazmaya
 * kalkardı; hangi alanların bilerek gösterilmediği de bir bilgi.
 */
export default function Configuration() {
  const [view, setView] = useState<ConfigView | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .config()
      .then(setView)
      .catch((e: unknown) => setError(toMessage(e)));
  }, []);

  return (
    <section>
      <div className="page-head">
        <h2>Configuration</h2>
        <p>
          What this bastion is running with. These values come from the file on the
          host and are shown here read-only — change them there and restart.
        </p>
      </div>

      <ErrorLine msg={error} />

      {view && (
        <>
          <div className="card">
            <div className="card-head">
              <h3>File</h3>
              <p>
                <code>{view.path}</code>
              </p>
            </div>
          </div>

          {view.groups.map((g) => (
            <div className="card" key={g.title}>
              <div className="card-head">
                <h3>{g.title}</h3>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Setting</th>
                      <th>Value</th>
                      <th>What it does</th>
                    </tr>
                  </thead>
                  <tbody>
                    {g.entries.map((e) => (
                      <tr key={e.key}>
                        <td>
                          <code>{e.key}</code>
                        </td>
                        <td className="wrap">
                          <code>{e.value}</code>
                        </td>
                        <td className="wrap muted">{e.note}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}

          {view.withheld.length > 0 && (
            <div className="card">
              <div className="card-head">
                <h3>Not shown</h3>
                <p>
                  These are set in the same file. Their values never leave the host,
                  not even to an administrator's browser.
                </p>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Setting</th>
                      <th>Why</th>
                    </tr>
                  </thead>
                  <tbody>
                    {view.withheld.map((e) => (
                      <tr key={e.key}>
                        <td>
                          <code>{e.key}</code>
                        </td>
                        <td className="wrap muted">{e.note}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {/*
        ⚠️ ARŞİV KİMLİĞİ BU EKRANDA, LDAP'TA DEĞİL.
        Kart, kimlik kaynağı sihirbazının dışına çıkarılmış ama LDAP
        ekranının altında bırakılmıştı: yorumu "kimlik kaynağından
        bağımsız" diyordu, oysa yerel kimlikle çalışan bir kurulum onu
        HİÇ görmüyordu. Arşivin hedefi buradaki tablonun konusu; anahtarı
        da onun yanında duruyor.
      */}
      <ArchiveCredential />
    </section>
  );
}
