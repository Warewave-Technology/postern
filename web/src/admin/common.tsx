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
  /*
   * ⚠️ "ÇEKİLEMEDİ", "BOŞ" DEĞİLDİR.
   *
   * Hata dalında yalnızca setError çağrılıyordu; `items` boş kalıyor ve
   * ListState onu `empty` sanıp OLUMLU bir cümle yazıyordu — kırmızı
   * hata satırının hemen altında "No mappings — nobody can sign in
   * through the IdP yet." İkisinden hangisinin okunacağı belli:
   * olumlu cümle bir olgu gibi durur, hata satırı bir aksaklık gibi.
   *
   * Bu, dosyanın kendi gerekçesinin aynısı — yukarıdaki not `loading`
   * için tam bunu söylüyor ("hiç kural yok" ile "henüz gelmedi" aynı
   * ekranı gösteremez) — ve dördüncü hâl eksikti.
   */
  const [failed, setFailed] = useState(false);

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
        setFailed(false);
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
        setFailed(true);
      })
      .finally(() => setLoading(false));
  }, [load]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { items, error, denied, loading, failed, refresh, setError };
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
  failed,
  empty,
  emptyText,
}: {
  loading: boolean;
  denied: boolean;
  /*
   * ⚠️ ZORUNLU, İSTEĞE BAĞLI DEĞİL. Eksik bırakılabilseydi, eklenen
   * her yeni liste ekranı sessizce eski davranışa düşerdi: sorgu
   * çöktüğünde "burada bir şey yok" yazan bir ekran. Zorunlu olması,
   * derleyicinin her liste ekranına "peki sorgu başarısız olursa?"
   * sorusunu sorması demek.
   */
  failed: boolean;
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
  /*
   * ⚠️ BOŞTAN ÖNCE. Sıra tersine olsaydı çekilemeyen bir liste yine
   * "hiçbir şey yok" diye çıkardı — düzeltmenin tamamı bu sırada.
   */
  if (failed)
    return (
      /*
       * ⚠️ role="alert" DEĞİL — ErrorLine zaten duyuruyor. İkinci bir
       * alert, tek bir olay için ekran okuyucuya iki kez sözünü
       * kestirmek olurdu; buradaki cümle uyarı değil, o uyarının ne
       * ANLAMA GELMEDİĞİNİ söyleyen bağlam.
       */
      <p className="msg msg-warn">
        This list could not be loaded, so what you see is not a statement that
        there is nothing here. The error above says why; refresh once the cause
        is gone.
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

/*
 * ⚠️ BURADA, Audit.tsx'te DEĞİL. Üç denetim ekranı da (oturumlar,
 * defter, dosya geçmişi) aynı damgayı ve aynı bayt biçimini
 * kullanıyor; ikinci ekran için kopyalansalardı, biri düzeltilip
 * öbürü unutulduğunda aynı olay iki ekranda iki farklı zaman
 * gösterirdi.
 */
/*
 * Damgalar KISA biçimde yazılıyor ("28 Aug 09:31:56").
 *
 * toLocaleString() "8/28/2026, 9:31:56 AM" üretiyordu; iki damgalı bir
 * satır tabloyu ~200px genişletiyor ve sağdaki EYLEM sütununu yatay
 * kaydırmanın ardına itiyordu.
 */
const stampFmt = new Intl.DateTimeFormat(undefined, {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

/**
 * Timestamp renders an RFC3339 stamp compactly and keeps the exact
 * original in the title, for copying into a report or a log query.
 */
export function Timestamp({ value }: { value: string }) {
  const d = new Date(value);
  // Ayrıştıramadığımız damgayı "Invalid Date" diye göstermek kaydın
  // kendisini gizlemek olurdu: ham değer hiç yoktan iyidir.
  if (Number.isNaN(d.getTime())) return <>{value}</>;
  return (
    <time dateTime={value} title={value}>
      {stampFmt.format(d)}
    </time>
  );
}

/**
 * sortableTime, sıralama için sayısal damga.
 *
 * ⚠️ METİN SIRALAMASI YANLIŞ OLURDU: gösterilen biçimde yıl yok ve
 * "28 Aug" ile "3 Sep" alfabetik sıralandığında Ağustos, Eylül'den
 * sonra gelir. Sıralama ham değerin zamanına bakıyor.
 */
export function sortableTime(v: string | null): number {
  if (!v) return 0;
  const t = new Date(v).getTime();
  return Number.isNaN(t) ? 0 : t;
}

/*
 * Bayt sayısını okunur hâle getirir.
 *
 * Denetçinin sorusu "4823905 bayt mı" değil "4,6 MB mı". Ham sayı, iki
 * transferi gözle karşılaştırmayı imkânsız kılıyordu.
 */
export function bytes(n: number): string {
  if (n === 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}
