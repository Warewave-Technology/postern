import { useEffect, useRef, useState } from "react";

/**
 * UserMenu — üst çubuğun sağ ucundaki tek düğme ve menüsü.
 *
 * ⚠️ BEŞ AYRI ÖĞE BİR KÜME DEĞİL, YIĞINDI. Sağ uçta çan, tema anahtarı,
 * isim, admin rozeti ve "Sign out" yan yana duruyordu; hiçbiri öbürüyle
 * aynı türden bir şey değil ve hepsi aynı ağırlıkta çizildiği için göz
 * hangisinin bir düğme hangisinin bir etiket olduğunu ayırmıyordu
 * (kullanıcı ekrana bakıp "çok ayrık ve dağınık" dedi). Kimlik ve ona
 * bağlı eylemler tek bir düğmede toplandı.
 *
 * ⚠️ ÇAN VE TEMA MENÜYE GİRMİYOR. İkisi de tek tıklık kontrol: çan bir
 * sayı taşıyor (menünün içinde görünmez olurdu, oysa varlık sebebi
 * görünmek) ve tema anahtarı üç durumlu bir seçici — menüye gömmek her
 * ikisine de bir tık ekler ve durumlarını gizler.
 *
 * ⚠️ ÇIKIŞ HÂLÂ BİR FORM POST'U. Menüye girerken bağlantıya
 * dönüştürülmedi: oturumu kapatmak durum değiştiren bir istek, GET ile
 * yapılan bir çıkış yolu ise önceden getirilen bir bağlantıyla ya da
 * başka bir sitenin <img>'iyle tetiklenebilir.
 */
export type MenuSection = {
  /** Başlık; tek bölümlü menüde boş bırakılabilir. */
  title?: string;
  items: { label: string; onClick: () => void; icon?: React.ReactNode }[];
};

export default function UserMenu({
  name,
  admin,
  sections,
}: {
  name: string;
  admin: boolean;
  sections: MenuSection[];
}) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  // Dışarı tıklayınca kapan — MultiSelect'teki gerekçenin aynısı.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);

    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  /*
   * ⚠️ ESC KAPATIYOR VE ODAK DÜĞMEYE DÖNÜYOR. Kapanan bir menüden sonra
   * odak belgenin başına düşerse, klavyeyle gezen kişi sayfanın en
   * üstünden yeniden başlamak zorunda kalır.
   */
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape" && open) {
      e.stopPropagation();
      setOpen(false);
      button.current?.focus();
    }
  };

  const run = (fn: () => void) => () => {
    setOpen(false);
    fn();
  };

  return (
    <div className="usermenu" ref={root} onKeyDown={onKeyDown}>
      <button
        ref={button}
        className="usermenu-button"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <svg
          width="15"
          height="15"
          viewBox="0 0 16 16"
          fill="none"
          aria-hidden="true"
        >
          <circle
            cx="8"
            cy="5.2"
            r="2.6"
            stroke="currentColor"
            strokeWidth="1.3"
          />
          <path
            d="M2.9 13.4c0-2.5 2.3-4 5.1-4s5.1 1.5 5.1 4"
            stroke="currentColor"
            strokeWidth="1.3"
            strokeLinecap="round"
          />
        </svg>
        <span className="who">{name}</span>
        {admin && <span className="badge badge-accent">admin</span>}
        <svg
          className={open ? "caret open" : "caret"}
          width="10"
          height="10"
          viewBox="0 0 10 10"
          fill="none"
          aria-hidden="true"
        >
          <path
            d="M2 4l3 3 3-3"
            stroke="currentColor"
            strokeWidth="1.4"
            strokeLinecap="round"
          />
        </svg>
      </button>

      {open && (
        <div className="usermenu-panel" role="menu">
          {/*
            ⚠️ İSİM MENÜNÜN BAŞINDA DA YAZIYOR. Dar ekranda düğme yalnızca
            ikon ve oka düşüyor (aksi hâlde 390 pikselde üst çubuk sayfayı
            yatay kaydırıyordu — ölçüldü), yani kimin oturumu olduğu
            yalnızca burada okunabiliyor. Geniş ekranda tekrar ediyor:
            "hangi hesapla bakıyorum" sorusunun cevabı, çıkış düğmesinin
            hemen üstünde durmalı.
          */}
          <p className="usermenu-who">
            Signed in as <strong>{name}</strong>
            {admin && <span className="badge badge-accent">admin</span>}
          </p>
          {sections.map((s, i) => (
            <div className="usermenu-group" key={s.title ?? i}>
              {s.title && <p className="usermenu-title">{s.title}</p>}
              {s.items.map((it) => (
                <button
                  key={it.label}
                  role="menuitem"
                  onClick={run(it.onClick)}
                >
                  {it.icon}
                  {it.label}
                </button>
              ))}
            </div>
          ))}
          <div className="usermenu-group">
            <form method="post" action="/auth/logout">
              <button role="menuitem">
                <svg
                  width="15"
                  height="15"
                  viewBox="0 0 16 16"
                  fill="none"
                  aria-hidden="true"
                >
                  <path
                    d="M6.2 2.6H3.4v10.8h2.8M9.4 5.2L12.6 8l-3.2 2.8M12.2 8H6.6"
                    stroke="currentColor"
                    strokeWidth="1.3"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
                Sign out
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
