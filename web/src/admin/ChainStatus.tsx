import { useEffect, useState } from "react";
import { api, toMessage, type VerifyResult } from "../api";
import { ActionButton } from "./common";

/**
 * ChainStatus — bir kaydın zincirinin ne söylediği.
 *
 * ⚠️ NİYE VAR: göç 034'ün notu panelin "doğrulandı" ile "doğrulanamaz"ı
 * AYRI göstermesini şart koşuyordu ve panel hiçbirini göstermiyordu —
 * doğrulanmış bir kayıtla hiç doğrulanmamış bir kayıt aynı görünüyordu.
 *
 * ⚠️ BU EKRANIN EN BÜYÜK RİSKİ HAK EDİLMEMİŞ ONAY. Veritabanında bir
 * zincir başı olması, dosyanın o başla TUTTUĞU anlamına gelmiyor: bunu
 * ancak dosyayı baştan sona okuyup yeniden hesaplamak söyler. Bu yüzden
 * yeşil rozet YALNIZCA sunucu gerçekten doğruladıktan sonra çiziliyor.
 * Hiç doğrulanmamış bir kaydı doğrulanmış göstermek, hiçbir şey
 * göstermemekten kötüdür.
 *
 * ⚠️ AÇILIR AÇILMAZ KOŞUYOR. Önceki hâli nötr bir cümle ve bir "Verify"
 * düğmesi gösteriyordu: kontrolü istemek için düğmeye basan kişiden bir
 * düğmeye daha basmasını istiyordu (kullanıcı söyledi). Bu, hak
 * edilmemiş onay kuralını BOZMUYOR — rozet hâlâ yalnızca sunucu
 * gerçekten doğruladıktan sonra çiziliyor; değişen tek şey, o
 * doğrulamanın ne zaman istendiği.
 *
 * ⚠️ KENDİ KARTINI VE BAŞLIĞINI ÇİZMİYOR. Modalın içinde duruyor ve
 * modalın kendi başlığı var; ikisi birden "Recording chain" yazınca
 * ekranda iç içe iki pencere gibi görünüyordu (kullanıcı ekran
 * görüntüsüyle gösterdi).
 */

/** Yerel eksenin sunumu. */
const LOCAL: Record<
  VerifyResult["local"],
  { badge: string; label: string; text: string }
> = {
  verified: {
    badge: "badge-ok",
    label: "verified",
    text: "The file on this host matches its chain.",
  },
  changed: {
    badge: "badge-danger",
    label: "changed",
    text: "The file does not match the chain stored with the session.",
  },
  /*
   * ⚠️ NÖTR, ALARM DEĞİL. Zincirlerden önce kapanmış her oturum böyle
   * görünür — ilk yükseltmede bu, geçmişin TAMAMI demek. Kırmızı bir
   * rozet, kimsenin yapmadığı bir şey için operatörü alarma geçirirdi.
   */
  unsealed: {
    badge: "badge-info",
    label: "not sealed",
    text: "No chain was stored for this session, so there is nothing to check against.",
  },
  in_progress: {
    badge: "badge-info",
    label: "in progress",
    text: "The chain is written when the session closes.",
  },
  no_local_copy: {
    badge: "badge-warn",
    label: "not on this host",
    text: "The recording was archived and pruned, so its bytes were not checked here.",
  },
  not_recorded: {
    badge: "badge-info",
    label: "no recording",
    text: "This session has no recording to verify.",
  },
  error: {
    badge: "badge-warn",
    label: "could not read",
    text: "The recording could not be read on this host.",
  },
};

/** Kutu dışı eksenin sunumu — yerel eksenden AYRI satır. */
const OFFBOX: Record<
  VerifyResult["off_box"]["state"],
  { badge: string; label: string }
> = {
  match: { badge: "badge-ok", label: "archive confirms" },
  /*
   * ⚠️ EN GÜÇLÜ KURCALAMA İŞARETİ. Dosya veritabanıyla tutuyorken
   * kovadaki baş tutmuyorsa, ikisini birden üretebilmenin tek yolu bu
   * makineyi elinde tutmaktır.
   */
  mismatch: { badge: "badge-danger", label: "archive disagrees" },
  no_chain: { badge: "badge-info", label: "archived copy has no chain" },
  unchecked: { badge: "badge-info", label: "archive not checked" },
};

export default function ChainStatus({
  sessionId,
  chain,
}: {
  sessionId: string;
  /** Veritabanındaki baş. Boşsa oturum mühürsüz. */
  chain?: string;
}) {
  const [result, setResult] = useState<VerifyResult | null>(null);
  // Mühürlü bir kayıtta iş daha ilk çizimde başlıyor: "kontrol edilmedi"
  // cümlesinin bir an görünüp kaybolması, okunacak bir şey sanılırdı.
  const [busy, setBusy] = useState(Boolean(chain));
  const [error, setError] = useState("");

  const run = () => {
    setBusy(true);
    setError("");
    api
      .verifyRecording(sessionId)
      .then(setResult)
      .catch((e: unknown) => setError(toMessage(e)))
      .finally(() => setBusy(false));
  };

  /*
   * ⚠️ TEK SEFER. Bağımlılık listesi yalnızca oturum kimliği: run'ı
   * listeye koymak her çizimde yeni bir kimlik demek olurdu ve
   * doğrulama sonsuza dek kendini tetiklerdi — aynı tuzağa bu turda bir
   * kez düşüldü (NotificationsScreen).
   */
  useEffect(() => {
    if (!chain) return;
    let live = true;
    setBusy(true);
    setError("");
    api
      .verifyRecording(sessionId)
      .then((r) => {
        if (live) setResult(r);
      })
      .catch((e: unknown) => {
        if (live) setError(toMessage(e));
      })
      .finally(() => {
        if (live) setBusy(false);
      });

    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, chain]);

  return (
    <div className="chain-status">
      {error && (
        <p className="msg msg-error" role="alert">
          {error}
        </p>
      )}

      {busy && result === null && <p className="state">Checking…</p>}

      {!busy && result === null && !error ? (
        /*
          ⚠️ MÜHÜRSÜZ OTURUMDA KOŞACAK BİR ŞEY YOK. Kontrolü çalıştırmak
          "doğrulandı" diyemeyeceği bir sonuç üretirdi; cümle nötr.
        */
        <p className="state">
          No chain was stored for this session — it ended before chains existed,
          or it has only just closed.
        </p>
      ) : result === null ? null : (
        <>
          <p className="chain-line">
            <span className={`badge ${LOCAL[result.local].badge}`}>
              {LOCAL[result.local].label}
            </span>
            <span>{result.detail || LOCAL[result.local].text}</span>
          </p>

          {/*
              ⚠️ KUTU DIŞI SONUÇ AYRI SATIRDA VE HER ZAMAN YAZILIYOR.
              Yerel sonuçla tek rozette birleştirmek, "yerel tuttu ama
              arşiv çelişiyor" durumunu gizlerdi; sessizlik ise
              bakılmadığını bakılmış gibi okutur.
            */}
          <p className="chain-line">
            <span className={`badge ${OFFBOX[result.off_box.state].badge}`}>
              {OFFBOX[result.off_box.state].label}
            </span>
            <span>
              {result.off_box.state === "match" && result.off_box.object
                ? `The copy in ${result.off_box.object} carries the same head.`
                : result.off_box.state === "mismatch"
                  ? `The archived copy carries ${result.off_box.chain} — treat ` +
                    `the archived head as the one to trust, and this host as ` +
                    `compromised.`
                  : result.off_box.detail}
            </span>
          </p>

          {result.local === "verified" && result.off_box.state !== "match" && (
            /*
                  ⚠️ YEREL "GEÇTİ" TEK BAŞINA DAR BİR İDDİA ve bunu
                  yazmazsak yeşil rozet fazla okunur: bu makinede root
                  olan biri dosyayı ve veritabanındaki başı BİRLİKTE
                  yeniden yazabilir.
                */
            <p className="state chain-note">
              This only shows the file was not changed after postern wrote it.
              Whoever holds root here could rewrite the file and the stored
              chain together; the copy in the archive is what closes that, and
              it was not consulted.
            </p>
          )}

          <ActionButton onClick={run} disabled={busy}>
            {busy ? "Checking…" : "Check again"}
          </ActionButton>
        </>
      )}
    </div>
  );
}
