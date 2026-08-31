import { useCallback, useEffect, useState } from "react";
import { ApiError, toMessage } from "../api";

/**
 * useList, "listeyi çek + hata + yenile" üçlüsü.
 *
 * loading DÖNMESİ önemli: eskiden yoktu ve her sayfa henüz veri
 * gelmemişken boş-durum metnini gösteriyordu — "No mappings — nobody can
 * sign in through the IdP yet." yazısı, eşlemeler yükleniyorken de
 * çıkıyordu. Bir yetkilendirme panelinde "hiç kural yok" ile "henüz
 * gelmedi" aynı ekranı göstermek yanlış bilgi vermektir.
 */
export function useList<T>(load: () => Promise<T[]>) {
  const [items, setItems] = useState<T[]>([]);
  const [error, setError] = useState("");
  const [denied, setDenied] = useState(false);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(() => {
    setLoading(true);
    return load()
      .then((v) => {
        setItems(v);
        // Başarıda hatayı TEMİZLE: eskiden temizlenmiyordu ve bir kez
        // düşen istekten sonra ekranda kalan kırmızı satır, sonraki
        // başarılı yüklemelerde de duruyordu.
        setError("");
        setDenied(false);
      })
      .catch((e: unknown) => {
        // ⚠️ Burada window.location.reload() VARDI ve sonsuz döngü
        // riskiydi: sameOrigin katmanı da 403 döndürüyor, dolayısıyla
        // yanlış yapılandırılmış bir vekil arkasında sayfa yenilenip
        // aynı 403'ü alıp yeniden yenileniyordu — kullanıcının
        // çıkamayacağı bir kısır döngü.
        //
        // Yerine durumu söylüyoruz; ne olduğunu anlatmak, tahmin edip
        // yeniden yüklemekten iyi.
        if (e instanceof ApiError && e.status === 403) {
          setDenied(true);
          setItems([]);
          return;
        }
        setError(toMessage(e));
      })
      .finally(() => setLoading(false));
  }, [load]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { items, error, denied, loading, refresh, setError };
}

/** ErrorLine, hata satırı. role="alert" ile ekran okuyucuya duyurulur. */
export function ErrorLine({ msg }: { msg: string }) {
  if (!msg) return null;
  return (
    <p className="msg msg-error" role="alert">
      {msg}
    </p>
  );
}

export function OkLine({ msg }: { msg: string }) {
  if (!msg) return null;
  return (
    <p className="msg msg-ok" role="status">
      {msg}
    </p>
  );
}

export function WarnLine({ msg }: { msg: string }) {
  if (!msg) return null;
  return (
    <p className="msg msg-warn" role="status">
      {msg}
    </p>
  );
}

/**
 * ListState, yükleniyor / yetki yok / boş durumlarını tek yerde çizer.
 *
 * Üçü de FARKLI şeyler ve üçünü birleştirmek operatörü yanıltır.
 * Dönen null, "listeyi çiz" demek.
 */
export function ListState({
  loading,
  denied,
  empty,
  emptyText,
}: {
  loading: boolean;
  denied: boolean;
  empty: boolean;
  emptyText: string;
}) {
  if (loading) return <p className="state">Loading…</p>;
  if (denied)
    return (
      <p className="msg msg-warn" role="alert">
        Your admin access was refused for this request. If it was just revoked,
        signing out and back in will show you the correct view.
      </p>
    );
  if (empty) return <p className="state">{emptyText}</p>;
  return null;
}

/**
 * ActionButton, yıkıcı işlemler için onay + uçuş sırasında kilit.
 *
 * İki ayrı hatayı birden kapatıyor:
 *
 *  1. Onay yoktu — yanlış satırdaki "delete" tek tıkla bir kullanıcıyı
 *     siliyordu.
 *  2. Uçuş sırasında kilit yoktu — iki kez tıklanan "Create" 409
 *     alıyor, storeErr onu "already exists" diye gösteriyor ve kullanıcı
 *     BAŞARILI olmuş bir işlem için hata görüyordu. Panelin hata
 *     mesajlarına güvenmemeyi böyle öğreniyor.
 */
/**
 * Görsel varyantlar.
 *
 * Panelde her düğme aynı kutuydu: "Create" ile satır içindeki "delete"
 * ve "revoke" aynı ağırlıkta duruyordu, yani ekranda hangisinin asıl iş
 * hangisinin yıkıcı işlem olduğu okunmuyordu. Ayrım GÖRSEL: erişilebilir
 * ad ve onay metni değişmiyor.
 */
const VARIANT_CLASS = {
  default: "",
  primary: "btn-primary",
  quiet: "btn-quiet",
  // ⚠️ btn-quiet DEĞİL: gerekçesi styles.css'teki .btn-danger notunda.
  // Yıkıcı bir eylem düğme gibi görünmek zorunda.
  danger: "btn-danger",
} as const;

export function ActionButton({
  onClick,
  children,
  confirm,
  label,
  disabled,
  variant = "default",
}: {
  onClick: () => Promise<unknown> | void;
  children: React.ReactNode;
  /** Doluysa tıklamadan önce bu metinle onay istenir. */
  confirm?: string;
  /** Ekran okuyucu için: "delete" tek başına hangi satır olduğunu söylemez. */
  label?: string;
  disabled?: boolean;
  variant?: keyof typeof VARIANT_CLASS;
}) {
  const [busy, setBusy] = useState(false);

  const run = async () => {
    if (confirm && !window.confirm(confirm)) return;
    setBusy(true);
    try {
      await onClick();
    } finally {
      setBusy(false);
    }
  };

  return (
    <button
      onClick={run}
      disabled={busy || disabled}
      aria-label={label}
      className={VARIANT_CLASS[variant] || undefined}
    >
      {busy ? "…" : children}
    </button>
  );
}
