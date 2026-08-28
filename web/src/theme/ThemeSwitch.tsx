import { AutoIcon, MoonIcon, SunIcon } from "../icons";
import type { ThemeMode } from "./mode";

/**
 * ThemeSwitch — üç durumlu tema anahtarı.
 *
 * NEDEN ÜÇ DÜĞME, TEK "toggle" DEĞİL: iki durumlu bir anahtar "sistemi
 * izle" seçeneğini yok eder ve gün içinde otomatik geçen bir masaüstünde
 * panel tek başına yanlış temada kalır. Üçü de görünür duruyor çünkü
 * hangi hâlde olduğunu göstermek, tıklayıp öğrenmekten iyi.
 *
 * radiogroup: bu bir eylem kümesi değil, birbirini dışlayan bir SEÇİM.
 * Ekran okuyucuya "3'ün 2'si seçili" diye okunması gereken şey bu.
 */
const OPTIONS: [ThemeMode, string, React.ReactNode][] = [
  ["light", "Light", <SunIcon key="i" />],
  ["dark", "Dark", <MoonIcon key="i" />],
  ["system", "System", <AutoIcon key="i" />],
];

export default function ThemeSwitch({
  mode,
  onChange,
}: {
  mode: ThemeMode;
  onChange: (m: ThemeMode) => void;
}) {
  return (
    <div className="theme-switch" role="radiogroup" aria-label="Colour theme">
      {OPTIONS.map(([m, label, icon]) => (
        <button
          key={m}
          role="radio"
          aria-checked={mode === m}
          // ⚠️ title DEĞİL aria-label: simge tek başına adsız ve title
          // dokunmatik cihazda hiç görünmüyor.
          aria-label={`${label} theme`}
          onClick={() => onChange(m)}
        >
          {icon}
        </button>
      ))}
    </div>
  );
}
