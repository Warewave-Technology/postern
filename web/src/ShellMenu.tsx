import { useEffect, useRef, useState } from "react";
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

  /*
   * ⚠️ DIŞARI TIKLAMA VE Escape MENÜYÜ KAPATIR. Açık kalan bir menü,
   * kartların üstünü örtüp altındaki hedeflere tıklanmasını engelliyor
   * — ve kullanıcı bunu arayüzün donması sanıyor.
   */
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!boxRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
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

      {open && (
        <div className="shell-menu-list" role="menu">
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
        </div>
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
