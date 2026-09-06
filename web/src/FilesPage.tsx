import FileBrowser from "./FileBrowser";
import ThemeSwitch from "./theme/ThemeSwitch";
import { GateMark } from "./icons";
import type { ThemeMode } from "./theme/mode";

/**
 * FilesPage — tam ekran dosya tarayıcısı, kendi sekmesinde.
 *
 * Kabukla AYNI kalıp (ShellPage.tsx) ve aynı gerekçe: uzun bir dizin
 * listesi panelin içindeki bir kutuda okunmuyor, ve sekme değiştirmek
 * çalışan oturumu gizliyor.
 *
 * ⚠️ SEKME KAPATILINCA OTURUM BİTER. Bu bir dosya yöneticisi değil,
 * hedefe açılmış CANLI BİR SSH OTURUMU: denetim defterinde satırı var,
 * kaydı yazılıyor ve kapatıldığında kapanıyor. Sayfa bunu yazıyor ki
 * kimse sekmeyi açık bırakmanın bedelsiz olduğunu sanmasın.
 */
export default function FilesPage({
  target,
  mode,
  onMode,
}: {
  target: string;
  mode: ThemeMode;
  onMode: (m: ThemeMode) => void;
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
        {/*
          ⚠️ "read-only" BİR VAAT, SÜS DEĞİL. Kısıt sunucuda
          (proxy.SetSFTPReadOnly) ve panelden yazma isteği hiç
          kodlanmıyor. Rozeti buraya koymak, kullanıcının dosyaları
          değiştirmeye çalışıp reddedilmesini beklemeden bilmesini
          sağlıyor.
        */}
        <span className="badge badge-info">read-only</span>
        <span className="shell-spacer" />
        <span className="shell-hint">closing this tab ends the session</span>
        <ThemeSwitch mode={mode} onChange={onMode} />
      </header>

      <FileBrowser target={target} />
    </div>
  );
}

/** filesTargetFromPath, /files/<target> yolundan hedefi çıkarır. */
export function filesTargetFromPath(pathname: string): string | null {
  const m = /^\/files\/([^/]+)\/?$/.exec(pathname);
  if (!m) return null;
  try {
    const name = decodeURIComponent(m[1]);
    return name.trim() === "" ? null : name;
  } catch {
    // Bozuk yüzde kaçışı: adres uydurulmuş demektir.
    return null;
  }
}
