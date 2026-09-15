import { useEffect, useRef, useState } from "react";
import { Notification, api } from "./api";
import { Timestamp } from "./admin/common";

/**
 * Notifications — üst çubuktaki çan ve bekleyen işlerin listesi.
 *
 * ⚠️ ÇAN BİR YERE ATMIYOR, AÇIYOR. İlk hâli doğrudan keşif ekranına
 * gidiyordu: sayı üç kaynaktan besleniyorsa (bekleyen makine, onay
 * bekleyen kimlik, geri alınamamış hak) tek bir ekrana atmak, üçte
 * ikisini görünmez yapar — ve tıklayan kişi beklediği şeyi bulamayınca
 * rozete bir daha bakmaz (kullanıcı söyledi). Liste burada açılıyor,
 * satır işin yapılacağı yere götürüyor.
 *
 * ⚠️ HER SATIR NE ZAMANDAN BERİ BEKLEDİĞİNİ SÖYLÜYOR. "Bir şey var"
 * ile "bu üç gündür duruyor" aynı cümle değil; ikincisi bir karar
 * gerektiriyor.
 *
 * ⚠️ HATA SESSİZ. Sayı alınamıyorsa çan hiç çizilmiyor: üst çubuk
 * hiçbir şey yapamayacağın bir yer ve oraya konan kırmızı bir satır,
 * her sayfada duran bir alarm olurdu. Sunucu, okunamayan bir kaynağı
 * zaten listenin İÇİNDE bir satır olarak söylüyor.
 */
export default function Notifications({
  onGo,
}: {
  onGo: (section: string) => void;
}) {
  const [items, setItems] = useState<Notification[]>([]);
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    let alive = true;
    const read = () =>
      api
        .notifications()
        .then((r) => {
          if (alive) setItems(r.items);
        })
        .catch(() => {
          if (alive) setItems([]);
        });
    read();
    // Dakikada bir: keşfin en sık koşusu beş dakikada bir, daha sık
    // sormanın söyleyeceği yeni bir şey yok.
    const t = setInterval(read, 60_000);

    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);

    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  // Bekleyen yokken çan da yok: sıfır yazan bir rozet, bakılacak bir şey
  // olmadığında da göz çeker ve bir süre sonra dolu hâli de fark edilmez.
  if (items.length === 0) return null;

  const label = `${items.length} thing${items.length === 1 ? "" : "s"} waiting for you`;

  return (
    <div
      className="notifications"
      ref={root}
      onKeyDown={(e) => {
        if (e.key === "Escape" && open) {
          e.stopPropagation();
          setOpen(false);
          button.current?.focus();
        }
      }}
    >
      <button
        ref={button}
        className="bell"
        aria-haspopup="menu"
        aria-expanded={open}
        title={label}
        aria-label={label}
        onClick={() => setOpen((v) => !v)}
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
        <span className="bell-count">
          {items.length > 99 ? "99+" : items.length}
        </span>
      </button>

      {open && (
        <div className="notify-panel" role="menu">
          <p className="notify-head">Waiting for you</p>
          {items.map((n, i) => (
            <button
              key={`${n.kind}-${n.at}-${i}`}
              role="menuitem"
              onClick={() => {
                setOpen(false);
                onGo(n.section);
              }}
            >
              <span className="notify-summary">{n.summary}</span>
              <span className="notify-detail">{n.detail}</span>
              <span className="notify-at">
                {/* Damga kısa biçimde ve başlığında tam hâliyle: denetim
                    ekranlarındaki aynı bileşen. */}
                since <Timestamp value={n.at} />
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
