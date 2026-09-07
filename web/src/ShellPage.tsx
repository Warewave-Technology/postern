import { useState } from "react";
import Terminal from "./Terminal";
import ThemeSwitch from "./theme/ThemeSwitch";
import Modal from "./admin/Modal";
import FileBrowser from "./FileBrowser";
import { GateMark, FolderIcon } from "./icons";
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
  filesEnabled,
  filesWriteEnabled,
}: {
  target: string;
  mode: ThemeMode;
  onMode: (m: ThemeMode) => void;
  resolved: Resolved;
  /** Dosya tarayıcısı açık mı (session.sftp_panel). */
  filesEnabled?: boolean;
  /** Yükleme açık mı (session.sftp_panel_write). */
  filesWriteEnabled?: boolean;
}) {
  /*
   * ⚠️ DOSYALAR KABUĞUN İÇİNDE, AYRI BİR SEKMEDE DEĞİL.
   *
   * Önce kendi sayfası vardı (/files/<hedef>) ve hedef kartında ayrı bir
   * düğmesi. Yanlış yerdi: dosyalara bakmak, bağlandığın makinede
   * yaptığın bir şey — bağlanmadan önce verilen bir karar değil. Ayrıca
   * ayrı sekme, AYRI BİR OTURUM açıyordu: aynı makineye iki kayıt, iki
   * denetim satırı, ve kullanıcının tek iş sandığı şey için iki giriş.
   *
   * ⚠️ MODAL AÇILINCA KANAL AÇILIYOR, kapanınca kapanıyor: bileşen
   * yalnızca açıkken çiziliyor. Arka planda açık duran bir SFTP kanalı,
   * kullanıcının kapattığını sandığı bir şeyin canlı kalması olurdu.
   */
  const [files, setFiles] = useState(false);

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
        {filesEnabled && (
          <button
            type="button"
            className="btn btn-ghost btn-sm shell-files"
            onClick={() => setFiles(true)}
          >
            <FolderIcon />
            Files
          </button>
        )}
        <span className="shell-hint">closing this tab ends the session</span>
        <ThemeSwitch mode={mode} onChange={onMode} />
      </header>

      <Terminal target={target} theme={resolved} fullScreen />

      <Modal
        open={files}
        onClose={() => setFiles(false)}
        title={`Files — ${target}`}
        description={
          filesWriteEnabled
            ? "Your computer on the left, the host on the right. Drag between them, or select and use the buttons."
            : "Read-only: this bastion allows browsing and downloading, not uploading."
        }
        wide
      >
        {/* key: kapanınca bileşen SÖKÜLÜYOR, yani kanal da kapanıyor. */}
        {files && (
          <FileBrowser target={target} canWrite={Boolean(filesWriteEnabled)} />
        )}
      </Modal>
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
