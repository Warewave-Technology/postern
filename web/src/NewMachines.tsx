import { useEffect, useState } from "react";
import { api } from "./api";

/**
 * NewMachines — üst çubuktaki çan: kaydedilmeyi bekleyen makine sayısı.
 *
 * ⚠️ KEŞİF ZAMANLAYICIYLA ÇALIŞIYOR, YANİ OKURU YOK. Bir kaynak on beş
 * dakikada bir koşuyor ve bulduğu makineyi kimse istemeden listeye
 * koyuyor; o listeye bakmak için Settings → Discovery'ye gitmek gerekiyordu.
 * Çan, "platformda kaydedilmemiş makineler var" cümlesini yöneticinin
 * bulunduğu her ekrana taşıyor.
 *
 * ⚠️ ROZET "yeni" DURUMUYLA AYNI ŞEYİ SAYIYOR (sunucuda tek sorgu):
 * hedef değil, yok sayılmamış, kaynakta duruyor, sorunsuz ve anahtarı
 * okunmuş. Başka bir şey sayan bir rozet, tıklayanı listede o kadar satır
 * bulamayınca bir daha bakmamaya iter.
 *
 * ⚠️ HATA SESSİZ. Sayı alınamıyorsa çan hiç çizilmiyor: üst çubukta
 * kırmızı bir hata satırı, hiçbir şey yapamayacağın bir yerde duran bir
 * alarm olurdu. Asıl ekran (Discovery) hatayı zaten söylüyor.
 */
export default function NewMachines({ onOpen }: { onOpen: () => void }) {
  const [count, setCount] = useState(0);

  useEffect(() => {
    let alive = true;
    const read = () =>
      api
        .discoveryNewCount()
        .then((r) => {
          if (alive) setCount(r.new);
        })
        .catch(() => {
          if (alive) setCount(0);
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

  if (count === 0) return null;

  return (
    <button
      className="bell"
      onClick={onOpen}
      title={`${count} discovered machine${count === 1 ? "" : "s"} waiting to be registered`}
      aria-label={`${count} discovered machine${count === 1 ? "" : "s"} waiting to be registered`}
    >
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <path
          d="M8 1.6a3.6 3.6 0 0 0-3.6 3.6v2.2L3.2 10.2h9.6l-1.2-2.8V5.2A3.6 3.6 0 0 0 8 1.6Z"
          stroke="currentColor"
          strokeWidth="1.3"
          strokeLinejoin="round"
        />
        <path d="M6.4 12.1a1.7 1.7 0 0 0 3.2 0" stroke="currentColor" strokeWidth="1.3" />
      </svg>
      <span className="bell-count">{count > 99 ? "99+" : count}</span>
    </button>
  );
}
