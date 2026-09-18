import { useCallback, useEffect, useState } from "react";
import { api } from "./api";

/**
 * Notifications — üst çubuktaki çan.
 *
 * ⚠️ ÇAN ARTIK BİR KAPI, AÇILIR BİR LİSTE DEĞİL. Önceki hâli üst çubukta
 * bir açılır panel çiziyordu: liste orada okunuyor, kapanınca hiçbir iz
 * kalmıyordu — yani "bunu görmüştüm" diye bir şey yoktu ve aynı satırlar
 * her açılışta aynı aciliyetle duruyordu. Şimdi çan bildirim SAYFASINA
 * götürüyor, ve götürdüğü anda bakış damgası ileri alınıyor.
 *
 * ⚠️ ROZET YALNIZCA YENİLERİ SAYIYOR, VE SAYIYI SUNUCU VERİYOR. Rozetin
 * sayısı ile sayfanın içeriği aynı kuraldan çıkmak zorunda; istemcide
 * ikinci bir kural yazmak, "rozet üç diyor ama sayfada iki satır var"
 * hâlini üretirdi ve o noktadan sonra rozete kimse güvenmez.
 *
 * ⚠️ BEKLEYEN HİÇ YOKKEN ÇAN YİNE DURUYOR, ROZET DURMUYOR. Çanın
 * kaybolması, okunmuş bildirimlere dönmenin yolunu da kapatırdı. Sıfır
 * yazan bir rozet ise bakılacak bir şey olmadığında da göz çeker ve bir
 * süre sonra dolu hâli de fark edilmez.
 *
 * ⚠️ HATA SESSİZ. Sayı alınamıyorsa rozet çizilmiyor: üst çubuk hiçbir
 * şey yapamayacağın bir yer ve oraya konan kırmızı bir satır, her
 * sayfada duran bir alarm olurdu. Sunucu, okunamayan bir kaynağı zaten
 * listenin İÇİNDE bir satır olarak söylüyor.
 */
export default function Notifications({
  onGo,
  refresh = 0,
}: {
  onGo: (section: string) => void;
  /** Değiştiğinde sayı yeniden okunur (sayfa bildirimleri okunmuş yapınca). */
  refresh?: number;
}) {
  const [unread, setUnread] = useState(0);
  const [total, setTotal] = useState(0);

  const read = useCallback(
    (alive: () => boolean) =>
      api
        .notifications()
        .then((r) => {
          if (!alive()) return;
          setUnread(r.unread);
          setTotal(r.count);
        })
        .catch(() => {
          if (!alive()) return;
          setUnread(0);
          setTotal(0);
        }),
    [],
  );

  useEffect(() => {
    let live = true;
    const alive = () => live;
    read(alive);
    // Dakikada bir: keşfin en sık koşusu beş dakikada bir, daha sık
    // sormanın söyleyeceği yeni bir şey yok.
    const t = setInterval(() => read(alive), 60_000);

    return () => {
      live = false;
      clearInterval(t);
    };
  }, [read, refresh]);

  const label =
    unread > 0
      ? `${unread} new notification${unread === 1 ? "" : "s"}`
      : total > 0
        ? `Notifications — ${total} waiting, none new`
        : "Notifications";

  return (
    <button
      className="bell"
      title={label}
      aria-label={label}
      onClick={() => {
        /*
         * Damga ÖNCE ileri alınıyor, sonra sayfaya gidiliyor: sayfanın
         * kendisi de damgayı alıyor ama ağ yavaşsa rozet birkaç saniye
         * dolu kalırdı ve kullanıcı tıklamanın işe yaramadığını sanırdı.
         */
        void api
          .markNotificationsRead()
          .catch(() => {})
          .finally(() => setUnread(0));
        onGo("notifications");
      }}
    >
      <svg
        width="16"
        height="16"
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
      >
        <path
          d="M8 1.6a3.6 3.6 0 0 0-3.6 3.6v2.2L3.2 10.2h9.6l-1.2-2.8V5.2A3.6 3.6 0 0 0 8 1.6Z"
          stroke="currentColor"
          strokeWidth="1.3"
          strokeLinejoin="round"
        />
        <path
          d="M6.4 12.1a1.7 1.7 0 0 0 3.2 0"
          stroke="currentColor"
          strokeWidth="1.3"
        />
      </svg>
      {unread > 0 && (
        <span className="bell-count">{unread > 99 ? "99+" : unread}</span>
      )}
    </button>
  );
}
