import { useEffect, useState } from "react";

/*
 * Geçici bildirimler ("Copied" gibi).
 *
 * NEDEN VAR: bu onaylar kartın ya da menünün yanında satır olarak
 * çiziliyordu ve iki sorunu vardı — açıldığı yerde yerleşimi itiyor,
 * ve kullanıcı başka bir yere bakıyorsa hiç görülmüyordu. Ekranın
 * köşesinde beliren ve kendiliğinden kaybolan bir kutu, ikisini de
 * çözüyor.
 *
 * ⚠️ YALNIZCA GEÇİCİ ONAYLAR İÇİN. Hata mesajları ve form sonuçları
 * satır içinde kalıyor: kaybolan bir hata, okunmamış bir hatadır ve
 * kullanıcı neyin yanlış gittiğini bir daha göremez.
 */

export type Toast = { id: number; text: string };

type Listener = (t: Toast[]) => void;

let items: Toast[] = [];
let nextID = 1;
const listeners = new Set<Listener>();

function emit() {
  // Dinleyicilere KOPYA gidiyor: aynı diziyi paylaşmak, React'in
  // değişikliği görmemesine yol açardı.
  const snapshot = [...items];
  listeners.forEach((l) => l(snapshot));
}

/*
 * toast, bir bildirim gösterir.
 *
 * Modül düzeyinde: bileşen ağacının herhangi bir yerinden context
 * kurmadan çağrılabiliyor. Bildirim tek yönlü ve durumsuz olduğu için
 * bu fazladan bir bağlam katmanını hak etmiyor.
 */
export function toast(text: string, ms = 2200) {
  const t = { id: nextID++, text };
  items = [...items, t];
  emit();
  window.setTimeout(() => {
    items = items.filter((x) => x.id !== t.id);
    emit();
  }, ms);
}

// dismissAllToasts, testler için: modül durumu koşumlar arasında
// sızmasın.
export function dismissAllToasts() {
  items = [];
  emit();
}

export function ToastHost() {
  const [list, setList] = useState<Toast[]>(items);

  useEffect(() => {
    listeners.add(setList);
    return () => {
      listeners.delete(setList);
    };
  }, []);

  if (list.length === 0) return null;

  return (
    /*
     * ⚠️ aria-live="polite": ekran okuyucu bildirimi okusun ama
     * kullanıcının o anda yaptığı işi kesmesin. assertive olsaydı
     * "Copied" her seferinde okumayı bölerdi.
     *
     * pointer-events yok (CSS'te): kutu ekranın üstünde duruyor ve
     * altındaki düğmelere tıklamayı engellememeli.
     */
    <div className="toasts" role="status" aria-live="polite">
      {list.map((t) => (
        <div className="toast" key={t.id}>
          {t.text}
        </div>
      ))}
    </div>
  );
}
