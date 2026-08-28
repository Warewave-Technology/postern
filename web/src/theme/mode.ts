import { useCallback, useEffect, useState } from "react";

/**
 * Tema modu.
 *
 * ÜÇ HÂL, iki değil: "system" işletim sistemini izler, "light"/"dark"
 * onu ezer. İki hâlli bir anahtar (sadece açık/koyu) kullanıcının
 * sistemini izleme seçeneğini yok eder — ve gün içinde otomatik geçen
 * bir masaüstünde bu, panelin tek başına yanlış temada kalması demek.
 */
export type ThemeMode = "system" | "light" | "dark";

/** Çözülmüş tema: gerçekte hangisi çiziliyor. */
export type Resolved = "light" | "dark";

const KEY = "postern.theme";

const media = () =>
  typeof window !== "undefined" && window.matchMedia
    ? window.matchMedia("(prefers-color-scheme: dark)")
    : null;

export function readMode(): ThemeMode {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    // Depolama kapalı olabilir (gizli pencere, sıkı politika). Tema
    // tercihi uğruna paneli açmamak saçma olurdu.
  }
  return "system";
}

export function systemPrefersDark(): boolean {
  return media()?.matches ?? false;
}

export function resolve(mode: ThemeMode): Resolved {
  if (mode === "system") return systemPrefersDark() ? "dark" : "light";
  return mode;
}

/**
 * apply, seçimi köke yazar.
 *
 * ⚠️ "system" hâlinde ÖZNİTELİK SİLİNİYOR, "light" yazılmıyor. Sebebi
 * CSS tarafında: koyu blok `@media (prefers-color-scheme: dark)` içinde
 * `:root:not([data-theme="light"])` ile duruyor, yani JS hiç çalışmasa
 * bile sistem teması doğru çiziliyor. Bunu JS'e bağlasaydık — kökü her
 * zaman damgalayarak — sayfa ilk boyandığında bir kare açık tema
 * yanıp sönerdi, ve CSP script-src 'self' satır içi bir önyükleme
 * betiğine izin vermiyor.
 */
export function apply(mode: ThemeMode) {
  const root = document.documentElement;
  if (mode === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", mode);
}

/**
 * useThemeMode, modu okur/yazar ve ÇÖZÜLMÜŞ temayı verir.
 *
 * Çözülmüş değer terminal için gerekli: xterm'in paleti CSS
 * değişkenlerinden gelmiyor, JS nesnesi olarak veriliyor — hangi
 * gruvbox varyantının yükleneceğini birinin bilmesi lazım.
 */
export function useThemeMode(): [ThemeMode, (m: ThemeMode) => void, Resolved] {
  const [mode, setModeState] = useState<ThemeMode>(readMode);
  const [resolved, setResolved] = useState<Resolved>(() => resolve(readMode()));

  const setMode = useCallback((m: ThemeMode) => {
    setModeState(m);
    apply(m);
    setResolved(resolve(m));
    try {
      localStorage.setItem(KEY, m);
    } catch {
      // Kaydedilemedi: bu oturumda çalışır, sonrakinde sisteme döner.
      // Sessizce çalışmamaktan iyi.
    }
  }, []);

  // İlk boyamada köke yaz: depolamadaki seçim ile DOM'un hâli
  // ayrışmasın.
  useEffect(() => {
    apply(mode);
    // Yalnızca ilk montajda; sonrası setMode'un işi.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sistem teması değişince — mod "system" ise — çözülmüş değeri
  // güncelle. Bu olmadan gece moduna geçen bir masaüstünde terminal
  // eski paletle kalırdı; CSS kendi kendine geçiyor, xterm geçmiyor.
  useEffect(() => {
    const m = media();
    if (!m) return;
    const onChange = () => {
      if (readMode() === "system") setResolved(systemPrefersDark() ? "dark" : "light");
    };
    m.addEventListener("change", onChange);
    return () => m.removeEventListener("change", onChange);
  }, []);

  return [mode, setMode, resolved];
}
