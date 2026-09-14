import { ActionButton } from "./common";

/**
 * GrowingTable — satırları doldukça büyüyen küçük bir giriş tablosu.
 *
 * ⚠️ "EKLE" DÜĞMESİ YOK, VE SEBEBİ ÖLÇÜLDÜ. Etiketler serbest metin
 * kutusundayken operatör son satırı yazıp onu listeye almayı unutuyor,
 * yazdığını sanarak ilerliyordu (kullanıcı söyledi). Düğmeli bir tablo
 * aynı unutmayı bir tık ileri taşır. Son satır dolar dolmaz boş satır
 * kendiliğinden beliriyor: yazılan şey zaten tabloda.
 *
 * ⚠️ TEK KOPYA. Büyüme kuralı hem etiketlerde hem sudo komutlarında
 * lazım; iki yere yazılsaydı biri düzeltilip öbürü unutulduğunda aynı
 * ekranın iki yarısı farklı davranırdı.
 */
export type GrowColumn<T> = {
  /** Satır nesnesindeki alan. */
  key: keyof T & string;
  header: string;
  placeholder?: string;
  /** Ekran okuyucu için: "label key 2" gibi, satır numarasıyla. */
  label: (row: number) => string;
  /** Sütun genişliği için sınıf (ör. dar "runs as" sütunu). */
  className?: string;
};

export default function GrowingTable<T extends Record<string, string>>({
  rows,
  onChange,
  columns,
  empty,
  removeLabel,
  className,
}: {
  rows: T[];
  onChange: (rows: T[]) => void;
  columns: GrowColumn<T>[];
  /** Boş satırın kendisi — hangi alanların olduğunu bu söylüyor. */
  empty: T;
  removeLabel: (row: number) => string;
  className?: string;
}) {
  const blank = (r: T) => columns.every((c) => (r[c.key] ?? "").trim() === "");

  const edit = (i: number, key: keyof T & string, value: string) => {
    const next = rows.map((r, n) => (n === i ? { ...r, [key]: value } : r));
    if (!blank(next[next.length - 1])) next.push({ ...empty });
    onChange(next);
  };

  /*
   * ⚠️ SON SATIR SİLİNİNCE TABLO BOŞ KALMIYOR. Hiç satırı olmayan bir
   * tablo, yazılacak yeri olmayan bir tablo: operatörün elinde yalnızca
   * bir başlık satırı kalırdı.
   */
  const remove = (i: number) => {
    const next = rows.filter((_, n) => n !== i);
    onChange(next.length > 0 ? next : [{ ...empty }]);
  };

  return (
    <div className="table-wrap">
      <table className={className ? `growing ${className}` : "growing"}>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} className={c.className}>
                {c.header}
              </th>
            ))}
            <th className="actions">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              {columns.map((c) => (
                <td key={c.key} className={c.className}>
                  {/*
                    ⚠️ ÖRNEK YALNIZCA İLK SATIRDA. Her boş satırda tekrar
                    eden uzun bir yer tutucu ("/usr/bin/systemctl restart
                    nginx") yazılmış bir satır gibi okunuyor — tablonun
                    nerede bittiği kayboluyor. Örnek okumanın başladığı
                    yerde duruyor.
                  */}
                  <input
                    value={r[c.key] ?? ""}
                    aria-label={c.label(i + 1)}
                    placeholder={i === 0 ? c.placeholder : undefined}
                    onChange={(e) => edit(i, c.key, e.target.value)}
                  />
                </td>
              ))}
              <td className="actions">
                {/*
                  Boş satırda silme yok: silinecek bir şey olmadığı gibi,
                  her satırda duran bir düğme tablonun sonunu da bulanık
                  gösteriyor.
                */}
                {!blank(r) && (
                  <ActionButton variant="quiet" onClick={() => remove(i)} label={removeLabel(i + 1)}>
                    Remove
                  </ActionButton>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
