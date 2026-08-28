import { useEffect, useRef } from "react";

/**
 * Modal — ekleme formlarının kabı.
 *
 * NEDEN MODAL: "Add user", "Register target", "Add mapping" formları
 * listelerin ALTINDA kalıcı olarak duruyordu. Sayfanın işi listeyi
 * göstermek; ekleme ara sıra yapılan bir eylem ve sürekli ekranda
 * durması hem listeyi aşağı itiyor hem "bu sayfa ne için" sorusunu
 * bulanıklaştırıyordu.
 *
 * ⚠️ NATIVE <dialog> KULLANILIYOR, div + z-index DEĞİL. showModal()
 * bedavaya üç şey veriyor ve üçü de elle yazıldığında genelde eksik
 * kalıyor:
 *   - odak tuzağı (Tab, modalın dışına çıkmıyor)
 *   - Esc ile kapanma
 *   - arka planın inert olması (ekran okuyucu ve fare için)
 * Kütüphane getirmemenin gerekçesi de bu: tarayıcı zaten yapıyor.
 */
export default function Modal({
  open,
  title,
  description,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);

  /*
   * ⚠️ BAĞIMLILIK LİSTESİ YOK — her render'da eşitleniyor, ve bu kasıtlı.
   *
   * Ölçülen kusur: liste [open] iken eşitleme yalnızca `open` DEĞİŞTİĞİNDE
   * koşuyordu. DOM ile durum bir kez ayrıştığında (dialog dışarıdan
   * kapandı ama `open` hâlâ true kaldı) bir daha buluşamıyorlardı:
   * düğmeye basmak `open`ı zaten olduğu değere ayarlıyor, değişiklik
   * olmadığı için effect koşmuyor ve modal BİR DAHA AÇILMIYOR.
   *
   * İki koşul da idempotent (`!d.open` / `d.open`), yani her render'da
   * koşmasının bedeli iki karşılaştırma.
   */
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  });

  /*
   * ⚠️ KAPANMANIN HER YOLU DURUMDAN GEÇMELİ.
   *
   * `open` tek gerçek kaynağı; DOM kendi başına kapanırsa ikisi ayrışır
   * ve modal bir daha açılmaz. Üç yol var ve üçü de aşağıda duruma
   * yazıyor: × düğmesi, backdrop tıklaması, ve Esc (onCancel).
   *
   * `close` olayını da dinliyoruz — spesifikasyona göre doğru yol bu.
   * Ama TEK BAŞINA yeterli sayılmıyor: ölçüldü, bu panelin çalıştığı
   * tarayıcıda React'siz bir <dialog> bile close() çağrısında `close`
   * olayını uçurmuyor. Tek bir olaya bağlı kalan bir bileşen, o olayın
   * gelmediği her yerde kalıcı olarak bozulur.
   */
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    const onCloseEvent = () => onClose();
    d.addEventListener("close", onCloseEvent);
    return () => d.removeEventListener("close", onCloseEvent);
  }, [onClose]);

  return (
    <dialog
      ref={ref}
      className="modal"
      aria-labelledby="modal-title"
      // Boşluğa tıklayınca kapansın: <dialog> bunu kendiliğinden
      // yapmıyor. Hedef kontrolü ŞART — form içindeki bir tıklama da
      // dialog'a kadar kabarıyor ve kontrolsüz bırakılırsa kullanıcı
      // yazarken modal kapanırdı.
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
      // Esc: React'in sentetik olayı. Varsayılan davranış (tarayıcının
      // dialog'u kendi kapatması) ENGELLENİYOR ki kapanma yalnızca
      // durum üzerinden olsun — yoksa DOM kapanır, `open` true kalır.
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <div className="modal-head">
        <h3 id="modal-title">{title}</h3>
        <button className="btn-quiet" onClick={onClose} aria-label="close this dialog">
          ×
        </button>
      </div>
      {description && <p className="modal-sub">{description}</p>}
      <div className="modal-body">{children}</div>
    </dialog>
  );
}
