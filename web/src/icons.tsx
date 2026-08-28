/**
 * Satır içi simgeler.
 *
 * Dosya değil satır içi SVG: harici bir varlık CSP altında ayrı bir
 * kaynak demek, ve currentColor sayesinde her simge bulunduğu yerin
 * rengini — dolayısıyla temayı — kendiliğinden alıyor.
 *
 * Hepsi 16x16 ızgarada, 1.5 kalınlıkta ve yuvarlak uçlu. Tek tek "güzel"
 * olmaları değil, YAN YANA aynı ailedenmiş gibi durmaları önemli:
 * kalınlığı ya da ızgarası kayan tek bir simge, sıradaki bütün satırı
 * dağıtıyor.
 */

type P = { size?: number };

const base = (size: number) => ({
  width: size,
  height: size,
  viewBox: "0 0 16 16",
  fill: "none" as const,
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
});

/**
 * GateMark, ürünün işareti.
 *
 * Bir postern, kale duvarındaki küçük yan kapıdır — ve buradaki mesele
 * o kapıdan yalnızca anahtarı olanın geçmesi. İşaret tam olarak bu:
 * DOLU bir kemer (duvardaki geçit) ve içinden OYULMUŞ bir anahtar
 * deliği. Çizgi değil kütle olması kasıtlı; 16px'te çizgiler eriyor,
 * dolu bir siluet erimiyor.
 *
 * Anahtar deliği TEK kapalı alt yol: daire ile sapı ayrı yollar olsaydı
 * evenodd kuralı kesişimlerini geri doldurur ve delik "kapanırdı".
 */
export function GateMark({ size = 20 }: P) {
  return (
    <svg width={size} height={size} viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M3.6 18.4V8.6a6.4 6.4 0 0 1 12.8 0v9.8H3.6Z
           M9.15 10.63a2.2 2.2 0 1 1 1.7 0l.65 3.97h-3l.65-3.97Z"
        fill="currentColor"
      />
    </svg>
  );
}

export function HostIcon({ size = 14 }: P) {
  return (
    <svg {...base(size)}>
      <rect x="2.2" y="2.8" width="11.6" height="4.4" rx="1.2" />
      <rect x="2.2" y="8.8" width="11.6" height="4.4" rx="1.2" />
      <path d="M4.8 5h.01M4.8 11h.01" />
    </svg>
  );
}

export function PulseIcon({ size = 15 }: P) {
  return (
    <svg {...base(size)}>
      <path d="M1.5 8h3l1.6-4 2.6 8 1.7-4h4.1" />
    </svg>
  );
}

export function UsersIcon({ size = 15 }: P) {
  return (
    <svg {...base(size)}>
      <circle cx="6.2" cy="5.4" r="2.5" />
      <path d="M1.8 13.6c0-2.3 2-3.9 4.4-3.9s4.4 1.6 4.4 3.9" />
      <path d="M11.2 3.4a2.4 2.4 0 0 1 0 4.5M12.4 9.9c1.2.5 2 1.6 2 3.1" />
    </svg>
  );
}

export function RolesIcon({ size = 15 }: P) {
  return (
    <svg {...base(size)}>
      <path d="M8 1.8 3 3.8v3.9c0 3 2.1 5.3 5 6.5 2.9-1.2 5-3.5 5-6.5V3.8L8 1.8Z" />
      <path d="m6.1 7.9 1.4 1.5 2.5-2.8" />
    </svg>
  );
}

export function MapIcon({ size = 15 }: P) {
  return (
    <svg {...base(size)}>
      <circle cx="4" cy="4" r="2.1" />
      <circle cx="12" cy="12" r="2.1" />
      <path d="M6.1 4h3.4a2.4 2.4 0 0 1 2.4 2.4v3.5" />
    </svg>
  );
}

export function TargetIcon({ size = 15 }: P) {
  return (
    <svg {...base(size)}>
      <circle cx="8" cy="8" r="6.2" />
      <circle cx="8" cy="8" r="2.6" />
    </svg>
  );
}

export function DirectoryIcon({ size = 15 }: P) {
  return (
    <svg {...base(size)}>
      <path d="M1.8 5.2 8 2.1l6.2 3.1L8 8.3 1.8 5.2Z" />
      <path d="m1.8 8 6.2 3.1L14.2 8M1.8 10.8 8 13.9l6.2-3.1" />
    </svg>
  );
}

export function PlayIcon({ size = 15 }: P) {
  return (
    <svg {...base(size)}>
      <circle cx="8" cy="8" r="6.2" />
      <path d="M6.6 5.6 10.6 8l-4 2.4V5.6Z" fill="currentColor" />
    </svg>
  );
}

export function LogIcon({ size = 15 }: P) {
  return (
    <svg {...base(size)}>
      <path d="M3.4 2.2h9.2v11.6H3.4z" />
      <path d="M5.8 5.4h4.4M5.8 8h4.4M5.8 10.6h2.6" />
    </svg>
  );
}

export function SearchIcon({ size = 14 }: P) {
  return (
    <svg {...base(size)}>
      <circle cx="7" cy="7" r="4.6" />
      <path d="m10.5 10.5 3 3" />
    </svg>
  );
}

/**
 * SortArrow, sıralanan sütunun yönü.
 *
 * Yön tek başına renkten değil ŞEKİLDEN okunuyor; ayrıca yeri her zaman
 * ayrılmış (bkz. .sort-arrow), yoksa sıralayınca sütun genişliği
 * zıplıyordu.
 */
export function SortArrow({ dir }: { dir: "asc" | "desc" | null }) {
  return (
    <svg
      className="sort-arrow"
      width="10"
      height="10"
      viewBox="0 0 10 10"
      fill="none"
      aria-hidden="true"
    >
      <path
        d={dir === "desc" ? "M2.2 4 5 7l2.8-3" : "M2.2 6 5 3l2.8 3"}
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
