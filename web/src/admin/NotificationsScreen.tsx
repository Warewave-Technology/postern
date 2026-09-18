import { useCallback, useEffect, useRef, useState } from "react";
import { Notification, api, toMessage } from "../api";
import { ErrorLine, ListState, Timestamp } from "./common";

/**
 * NotificationsScreen — bekleyen işlerin kendi sayfası.
 *
 * ⚠️ AÇILIR PANELDEN SAYFAYA TAŞINDI. Üst çubuktaki panel dar ve
 * geçiciydi: satırın tamamı sığmıyor, kapanınca hiçbir iz kalmıyordu.
 * Bir kararı okumak için açılan bir liste, kapandığında o kararı da
 * götürüyordu (kullanıcı söyledi).
 *
 * ⚠️ LİSTE HÂLÂ TÜRETİLİYOR, SAKLANMIYOR. İşi yapılan satır kayboluyor;
 * saklanan tek şey kişinin son bakış anı. Kalıcı bir bildirim tablosu,
 * iş çoktan bitmiş olsa bile satırı "okundu" denene kadar tutardı — ve
 * kendi kendine bayatlayan bir uyarı listesi, bir süre sonra hiç
 * okunmayan bir listedir.
 *
 * ⚠️ AÇILINCA OKUNMUŞ SAYILIYOR, TIKLAYINCA DEĞİL. Yönetici sayfayı
 * açtıysa listeyi görmüştür; her satıra ayrı ayrı tıklamasını beklemek,
 * rozeti hiç sıfırlanmayan bir sayaca çevirirdi.
 */
export default function NotificationsScreen({
  onGo,
  onRead,
}: {
  onGo: (section: string) => void;
  /** Damga ileri alındıktan sonra çağrılır; çan sayısını tazeliyor. */
  onRead?: () => void;
}) {
  const [items, setItems] = useState<Notification[]>([]);
  const [readAt, setReadAt] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback((alive: () => boolean) => {
    api
      .notifications()
      .then((r) => {
        if (!alive()) return;
        setItems(r.items);
        /*
         * Damga LİSTEYLE BİRLİKTE gelen değer: sayfa açıldıktan sonra
         * ileri alınıyor, dolayısıyla "yeni" işareti bu ziyarette hâlâ
         * görünüyor. Önce damgalayıp sonra okumak, yöneticinin tam da
         * bakmaya geldiği şeyi işaretsiz gösterirdi.
         */
        setReadAt(r.read_at);
        setError("");
      })
      .catch((e) => {
        if (!alive()) return;
        setError(toMessage(e));
      })
      .finally(() => {
        if (alive()) setLoading(false);
      });
  }, []);

  /*
   * ⚠️ onRead REF'TE TUTULUYOR, DEPS'TE DEĞİL — ÖLÇÜLDÜ.
   *
   * Çağıran onu satır içi bir ok fonksiyonu olarak veriyor, yani her
   * render'da YENİ bir kimlik. Deps'e koyunca: effect koşuyor →
   * markNotificationsRead → onRead → üst bileşen render oluyor → yeni
   * onRead → effect yeniden koşuyor. Görsel tarama testi 30 saniyede
   * zaman aşımına uğradı; üretimde bu, sayfa açık kaldığı sürece
   * sunucuya kesintisiz istek demekti.
   */
  const read = useRef(onRead);
  read.current = onRead;

  useEffect(() => {
    let live = true;
    const alive = () => live;
    load(alive);
    // Açılış okunmuş sayılıyor; hata yutuluyor çünkü rozetin
    // güncellenmemesi, sayfanın gösterilmemesinden iyidir.
    void api
      .markNotificationsRead()
      .catch(() => {})
      .then(() => {
        if (alive()) read.current?.();
      });

    return () => {
      live = false;
    };
  }, [load]);

  const readStamp = readAt ? Date.parse(readAt) : 0;
  const isNew = (n: Notification) => Date.parse(n.at) > readStamp;
  const fresh = items.filter(isNew).length;

  return (
    <section>
      <div className="page-bar">
        <div className="page-head">
          <h2>Notifications</h2>
          <p className="page-sub">
            Everything waiting for an admin, oldest first — the one that has
            been sitting longest is the one most likely to have been forgotten.
            Nothing here is a record of something that happened: a line
            disappears when its work is done, so this list never needs clearing.
          </p>
        </div>
      </div>

      <ErrorLine msg={error} />
      <ListState
        loading={loading}
        denied={false}
        failed={error !== ""}
        empty={!loading && error === "" && items.length === 0}
        emptyText="Nothing is waiting. New machines, identities to approve and locked accounts appear here."
      />

      {items.length > 0 && (
        <>
          <p className="muted small">
            {fresh > 0
              ? `${fresh} new since you last looked, of ${items.length} waiting.`
              : `${items.length} waiting, none new since you last looked.`}
          </p>
          <ul className="notify-list">
            {items.map((n, i) => (
              <li
                key={`${n.kind}-${n.at}-${i}`}
                className={isNew(n) ? "is-new" : undefined}
              >
                <div className="notify-line">
                  <span className="notify-summary">
                    {isNew(n) && (
                      <span
                        className="badge badge-info"
                        aria-label="new since you last looked"
                      >
                        new
                      </span>
                    )}
                    {n.summary}
                  </span>
                  <span className="notify-at">
                    {/* Damga kısa biçimde ve başlığında tam hâliyle:
                        denetim ekranlarındaki aynı bileşen. */}
                    waiting since <Timestamp value={n.at} />
                  </span>
                </div>
                <p className="notify-detail">{n.detail}</p>
                {/*
                  ⚠️ SATIR KENDİSİ TIKLANMIYOR, DÜĞMESİ TIKLANIYOR. Tıklanabilir
                  bir <li>, klavyeyle gezene hiçbir şey söylemiyor ve
                  metni seçmeyi de zorlaştırıyor.
                */}
                <button className="btn-quiet" onClick={() => onGo(n.section)}>
                  Go where this is handled →
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
