import { useCallback, useEffect, useState } from "react";
import { ArchiveStatus, api, toMessage } from "../api";
import { ActionButton, ErrorLine, OkLine } from "./common";

/**
 * Kayıt arşivinin kimliği.
 *
 * ⚠️ YALNIZCA KİMLİK — HEDEF DEĞİL. endpoint, bucket, prefix ve
 * ca_file config dosyasında duruyor ve buradan değiştirilemiyor.
 *
 * Sebebi ölçülmüş bir saldırı sınıfı: panel admini hedefi kendi
 * kovasına çevirebilseydi, bundan sonraki HER oturum kaydı oraya
 * yüklenirdi — ve bu, "hedef değişirse sırrı düşür" ile kapanmıyor,
 * çünkü saldırgan taze bir kimlik de girebilir. Panelden `is_admin`
 * verilmemesiyle aynı raf: ele geçirilmiş bir panel oturumu denetim
 * izini başka bir yere yönlendirebilmemeli.
 *
 * Anahtar döndürmek rutin bir iş ve burada; hedefi taşımak bir kurulum
 * kararı ve host'ta.
 */
export default function ArchiveCredential() {
  const [status, setStatus] = useState<ArchiveStatus | null>(null);
  const [keyID, setKeyID] = useState("");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState("");
  const [okMsg, setOkMsg] = useState("");

  const load = useCallback(
    () =>
      api
        .archiveStatus()
        .then((s) => {
          setStatus(s);
          setError("");
        })
        .catch((e: unknown) => setError(toMessage(e))),
    [],
  );

  useEffect(() => {
    load();
  }, [load]);

  if (!status) {
    return <ErrorLine msg={error} />;
  }

  // Hedef yapılandırılmamışsa kimlik girmenin anlamı yok — ve bunu
  // söylemek, boş bir formdan iyidir.
  if (!status.configured) {
    return (
      <div className="card">
        <div className="card-head">
          <h3>Recording archive</h3>
          <p>
            No destination is configured. Set{" "}
            <code>recording.archive.endpoint</code> and <code>bucket</code> in
            the config file; the key can then be entered here.
          </p>
        </div>
      </div>
    );
  }

  const fromHost = status.credential_source === "host";

  const save = async () => {
    setError("");
    setOkMsg("");
    try {
      await api.setArchiveCredential(keyID.trim(), secret);
      setSecret("");
      setOkMsg("Archive key saved. Uploading resumes within a minute.");
      await load();
    } catch (e: unknown) {
      const msg = toMessage(e);
      await load();
      setError(msg);
    }
  };

  const clear = async () => {
    setError("");
    setOkMsg("");
    try {
      await api.clearArchiveCredential();
      setOkMsg("Archive key removed. Uploading has stopped.");
      await load();
    } catch (e: unknown) {
      const msg = toMessage(e);
      await load();
      setError(msg);
    }
  };

  return (
    <div className="card">
      <div className="card-head">
        <h3>Recording archive</h3>
        {/*
          ⚠️ HEDEFİN BURADAN YÖNETİLMEDİĞİ AÇIKÇA YAZILIYOR.
          Salt okunur bir değeri sebepsiz göstermek, operatöre
          "değiştirebilirim ama tutmuyor" dedirtirdi.
        */}
        <p>
          Recordings are uploaded to <code>{status.bucket}</code> at{" "}
          <code>{status.endpoint}</code>
          {status.prefix ? (
            <>
              {" "}
              under <code>{status.prefix}</code>
            </>
          ) : null}
          . The destination is set in the config file and cannot be changed from
          here — a panel session must not be able to redirect the audit trail.
        </p>
      </div>

      {/*
        ⚠️ card-body ŞART. `.card`ın kendi dolgusu yok (styles.css);
        onu `.card-head`/`.card-body` veriyor. Sarmalayıcı olmadan
        alanlar ve düğmeler kartın kenarına yapışıyordu — panelin
        başka hiçbir kartı öyle durmuyor. Dosya geçmişi ekranı aynı
        kusurla çıktı ve ikisi tek seferde düzeltildi.
      */}
      <div className="card-body">
        <ErrorLine msg={error} />
        <OkLine msg={okMsg} />

        {fromHost ? (
          <p className="small muted">
            This bastion takes its archive key from the host (
            <code>secret_key_file</code> or{" "}
            <code>POSTERN_ARCHIVE_SECRET_KEY</code>), so it cannot be changed
            here. Access key in use: <code>{status.access_key_id || "—"}</code>.
          </p>
        ) : (
          <>
            <p className="small muted">
              {status.credential_source === "panel" ? (
                <>
                  Current access key: <code>{status.access_key_id}</code>. The
                  secret is never shown again — entering a new one replaces it.
                </>
              ) : (
                <>
                  No key is set, so nothing is being uploaded — and nothing can
                  be pruned while it waits.
                </>
              )}
            </p>

            <div className="wfield">
              <label className="wfield-label" htmlFor="archive-key-id">
                Access key ID
              </label>
              <input
                id="archive-key-id"
                value={keyID}
                onChange={(e) => setKeyID(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <div className="wfield">
              <label className="wfield-label" htmlFor="archive-secret">
                Secret access key
              </label>
              {/* type=password: omuz üstünden okunmasın. Değer zaten
                geri okunmuyor; bu yalnızca yazarken. */}
              <input
                id="archive-secret"
                type="password"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                autoComplete="new-password"
              />
            </div>

            <div className="card-actions">
              <ActionButton
                variant="primary"
                label="save the archive key"
                disabled={keyID.trim() === "" || secret === ""}
                onClick={save}
              >
                Save key
              </ActionButton>
              {status.credential_source === "panel" && (
                <ActionButton
                  variant="danger"
                  label="remove the archive key"
                  confirm={
                    "Remove the archive key?\n\n" +
                    "Uploading stops. Recordings are kept locally and will not " +
                    "be pruned while they wait, so the disk will grow until a " +
                    "key is set again."
                  }
                  onClick={clear}
                >
                  Remove
                </ActionButton>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
