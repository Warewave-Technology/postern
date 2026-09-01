import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { ExternalIcon, ShellIcon } from "./icons";

/*
 * ShellMenu — hedef kartındaki "Shell" düğmesi, iki seçenekli.
 *
 *   Connect : tarayıcıda terminal açar (eski davranış)
 *   Copy    : "ssh kullanıcı:hedef@bastion" komutunu panoya kopyalar
 *
 * ⚠️ KOPYALANAN KOMUT YAPIŞTIRILDIĞINDA ÇALIŞMALI. Adres sunucudan
 * geliyor (config.SSHEndpoint): dinleme adresi dışarıda anlamsız
 * olabiliyor (":2222", "0.0.0.0") ve <bastion> gibi bir yer tutucu
 * komutu yapıştırıldığı anda bozardı. Sunucu adresi bilmiyorsa bu
 * seçenek HİÇ çizilmiyor.
 */

// sshCommand, postern'in kullanıcı kalıbını kurar: "kullanıcı:hedef".
//
// ⚠️ Port yalnızca 22 DEĞİLSE yazılıyor: gereksiz bir -p, komutu
// okuyan kişiye özel bir şey yapıldığını düşündürür.
export function sshCommand(
  user: string,
  target: string,
  host: string,
  port: number,
): string {
  const p = port && port !== 22 ? `-p ${port} ` : "";
  return `ssh ${p}${user}:${target}@${host}`;
}

/*
 * menuPlacement, menünün nereye açılacağına karar verir.
 *
 * ⚠️ SAF FONKSİYON ve bilerek: karar tarayıcıda ölçülemeyecek kadar
 * duruma bağlı (ızgaranın son satırı, kısa pencere) ve bir arayüz
 * testinde jsdom'un yerleşimi yok. Buradan test edilebiliyor.
 *
 * Aşağıda yer yoksa YUKARI açılıyor: ekranın dışına taşan bir menü,
 * olmayan bir menüdür.
 */
export function menuPlacement(
  btn: { top: number; bottom: number; right: number },
  viewportHeight: number,
  viewportWidth: number,
): { top: number; right: number; above: boolean } {
  const room = viewportHeight - btn.bottom;
  const above = room < MENU_HEIGHT && btn.top > room;
  return {
    top: above ? btn.top - 4 : btn.bottom + 4,
    // Sağ kenardan taşmasın: 8px'lik pay, dar pencerede menüyü
    // ekranın dışına iten bir hizalamayı engelliyor.
    right: Math.max(8, viewportWidth - btn.right),
    above,
  };
}

// MENU_HEIGHT, "aşağıda yer var mı" kararının eşiği. Menü iki satır
// ve ipuçları taşıyor; ölçülen yüksekliği 130px civarı, eşik ondan
// biraz yukarıda.
const MENU_HEIGHT = 160;

export default function ShellMenu({
  target,
  user,
  sshHost,
  sshPort,
  connectHref,
}: {
  target: string;
  user: string;
  /** Boşsa kopyalama seçeneği çizilmiyor (adres bilinmiyor). */
  sshHost?: string;
  sshPort?: number;
  /** Boşsa web terminali kapalı; bağlanma seçeneği çizilmiyor. */
  connectHref?: string;
}) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState("");
  const boxRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ top: 0, right: 0, above: false });

  /*
   * ⚠️ MENÜ KARTIN İÇİNDE ÇİZİLEMİYOR.
   *
   * ÖLÇÜLEN ARIZA: .tcard'da `overflow: hidden` var — alttaki şeridin
   * yuvarlak köşeleri ondan geliyor — ve mutlak konumlu menüyü kırpıyor.
   * Ekranda "Connect" yazısının solu kesilmiş, "Copy" satırı hiç
   * görünmemiş hâlde çıkıyordu.
   *
   * Kartın kırpmasını kaldırmak alttaki şeridin köşelerini bozardı, o
   * yüzden menü body'ye taşınıyor ve sabit konumlanıyor. Bu ayrıca iki
   * gizli sorunu da kapatıyor: ızgaranın son satırındaki kartta menü
   * sayfanın altına takılıyordu, ve komşu kartlarla z-index yarışı
   * vardı.
   */
  useLayoutEffect(() => {
    if (!open) return;
    const btn = boxRef.current?.querySelector("button");
    if (!btn) return;
    const r = btn.getBoundingClientRect();
    setPos(menuPlacement(r, window.innerHeight, window.innerWidth));
  }, [open]);

  /*
   * ⚠️ DIŞARI TIKLAMA VE Escape MENÜYÜ KAPATIR. Açık kalan bir menü,
   * kartların üstünü örtüp altındaki hedeflere tıklanmasını engelliyor
   * — ve kullanıcı bunu arayüzün donması sanıyor.
   */
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      // Menü artık body'de: iki kapsayıcıyı da sormak gerekiyor.
      if (boxRef.current?.contains(t) || listRef.current?.contains(t)) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    const close = () => setOpen(false);
    /*
     * ⚠️ KAYDIRMADA KAPANIYOR. Sabit konumlu menü sayfa kaydıkça
     * düğmesinden KOPUYOR ve ekranın ortasında sahipsiz bir kutu
     * olarak kalıyor. Konumu sürekli izlemek yerine kapatmak hem
     * doğru hem ucuz.
     */
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open]);

  const canCopy = Boolean(sshHost);
  const canConnect = Boolean(connectHref);
  if (!canCopy && !canConnect) return null;

  const cmd = sshCommand(user, target, sshHost ?? "", sshPort ?? 22);

  const copy = () => {
    setOpen(false);
    /*
     * ⚠️ BAŞARISIZLIK SESSİZ GEÇMİYOR. navigator.clipboard yalnızca
     * güvenli bağlamda (https ya da localhost) var; düz http üzerinden
     * açılmış bir panelde hiç tanımlı değil. Sessizce hiçbir şey
     * yapmak, kullanıcıya yapıştıracak bir şey olduğunu sandırırdı —
     * o yüzden komutu ekranda gösteriyoruz ki elle alabilsin.
     */
    if (!navigator.clipboard?.writeText) {
      setCopied(cmd);
      return;
    }
    navigator.clipboard.writeText(cmd).then(
      () => {
        setCopied("copied");
        window.setTimeout(() => setCopied(""), 2000);
      },
      () => setCopied(cmd),
    );
  };

  return (
    <div className="shell-menu" ref={boxRef}>
      <button
        type="button"
        className="btn btn-primary btn-shell"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        aria-label={`shell options for ${target}`}
      >
        <ShellIcon />
        Shell
        <span className="caret" aria-hidden="true">
          ▾
        </span>
      </button>

      {open &&
        createPortal(
          <div
            className="shell-menu-list"
            role="menu"
            ref={listRef}
            style={{
              top: pos.top,
              right: pos.right,
              transform: pos.above ? "translateY(-100%)" : undefined,
            }}
          >
            {canConnect && (
              <a
                role="menuitem"
                href={connectHref}
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => setOpen(false)}
              >
                Connect
                <span className="hint">open a shell in this browser</span>
                <ExternalIcon />
              </a>
            )}
            {canCopy && (
              <button type="button" role="menuitem" onClick={copy}>
                Copy ssh command
                {/*
                  Komut ipucu olarak GÖSTERİLİYOR: kullanıcı neyi
                  kopyaladığını görmeden yapıştırmak zorunda kalmasın.
                */}
                <span className="hint">
                  <code>{cmd}</code>
                </span>
              </button>
            )}
          </div>,
          document.body,
        )}

      {copied === "copied" && (
        <span className="shell-copied" role="status">
          Copied
        </span>
      )}
      {copied && copied !== "copied" && (
        /*
         * Pano kullanılamadı: komut elle alınabilsin diye ekranda.
         * "Kopyalandı" demek yalan olurdu.
         */
        <span className="shell-copied manual" role="status">
          Copy this: <code>{copied}</code>
        </span>
      )}
    </div>
  );
}
