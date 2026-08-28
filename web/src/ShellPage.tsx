import Terminal from "./Terminal";
import ThemeSwitch from "./theme/ThemeSwitch";
import { GateMark } from "./icons";
import type { Resolved, ThemeMode } from "./theme/mode";

/**
 * ShellPage — tam ekran kabuk, kendi sekmesinde.
 *
 * NEDEN AYRI SEKME: panelin içindeki terminal, çevresindeki kabuk
 * yüzünden ekranın yarısını kullanıyordu ve sekme değiştirmek çalışan
 * oturumu gizliyordu. Kendi sekmesinde açılan bir kabuk, kullanıcının
 * zaten alışkın olduğu şey: bir terminal penceresi.
 *
 * ⚠️ Sekme KAPATILINCA oturum biter — WebSocket kapanır, sunucu
 * tarafındaki proxy oturumu onunla birlikte düşer. Bu bir kayıp değil,
 * beklenen davranış: terminal penceresini kapatmak oturumu bitirir.
 * Sayfa bunu yazıyor ki kimse "arkada çalışmaya devam ediyor" sanmasın.
 */
export default function ShellPage({
  target,
  mode,
  onMode,
  resolved,
}: {
  target: string;
  mode: ThemeMode;
  onMode: (m: ThemeMode) => void;
  resolved: Resolved;
}) {
  return (
    <div className="shell-page">
      <header className="shell-bar">
        <span className="brand">
          <GateMark size={17} />
          <span className="brand-word">postern</span>
        </span>
        <span className="shell-target">{target}</span>
        <span className="badge badge-ok">recording</span>
        <span className="shell-spacer" />
        <span className="shell-hint">closing this tab ends the session</span>
        <ThemeSwitch mode={mode} onChange={onMode} />
      </header>

      <Terminal target={target} theme={resolved} fullScreen />
    </div>
  );
}

/**
 * shellTargetFromPath, /shell/<target> yolundan hedefi çıkarır.
 *
 * Rota kütüphanesi yok: tek bir yol için yüz kilobayt bağımlılık
 * getirmenin gerekçesi yok. Sunucu zaten bilinmeyen yollara index.html
 * dönüyor (bkz. httpapi/spa.go), yani bu sayfa doğrudan adres çubuğuna
 * yazılarak da açılabiliyor.
 */
export function shellTargetFromPath(pathname: string): string | null {
  const m = /^\/shell\/([^/]+)\/?$/.exec(pathname);
  if (!m) return null;
  try {
    const name = decodeURIComponent(m[1]);
    return name.trim() === "" ? null : name;
  } catch {
    // Bozuk yüzde kaçışı: adres uydurulmuş demektir, kabuk açma.
    return null;
  }
}
