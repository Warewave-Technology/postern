import { ReactNode, useMemo, useState } from "react";
import { SearchIcon, SortArrow } from "../icons";

/**
 * DataTable — sıralanabilir, aranabilir tablo.
 *
 * NEDEN VAR: her yönetim sayfası kendi <table>'ını elle çiziyordu ve
 * hiçbirinde sıralama ya da arama yoktu. Yüz kullanıcılı bir kurulumda
 * "kim admin", "hangi hedefe kim erişiyor", "bu oturum kimindi" gibi
 * soruların cevabı gözle satır taramaktı; denetim ekranında bu, bakmayı
 * bırakmakla sonuçlanır.
 *
 * Sıralama ve süzme İSTEMCİDE: sunucu zaten en fazla 200/500 satır
 * dönüyor (bkz. Audit.tsx SESSION_CAP / LOG_CAP) ve o kadarını sıralamak
 * için sunucuya gitmek, kapsam sınırını da sayfalamayı da yeniden
 * tasarlamak demekti. Sınır aşıldığında kart eteğindeki uyarı hâlâ
 * yerinde duruyor: elde OLMAYAN satır sıralanamaz, ve bunu söylemek
 * sessizce kırpmaktan iyi.
 */

export type Column<T> = {
  key: string;
  header: string;
  /**
   * Sıralama ve aramanın kullandığı DÜZ metin/sayı. Verilmezse sütun
   * sıralanmaz ve aramaya girmez — çünkü render'ın döndürdüğü React
   * ağacından güvenilir bir metin çıkarmanın yolu yok.
   */
  value?: (row: T) => string | number;
  render?: (row: T) => ReactNode;
  className?: string;
  /** value varsa varsayılan true; eylem sütunları için false. */
  sortable?: boolean;
  /** Görsel olarak boş başlık (eylem sütunu) — ama adsız değil. */
  srHeader?: boolean;
};

type Dir = "asc" | "desc";

/**
 * compare, iki hücre değerini sıralar.
 *
 * ⚠️ SAYILAR İÇİN AYRI YOL. Sayıyı metne çevirip harmanlamak, ölçüldü:
 * "0.5" ile "0.25" ve "-1" ile "-2" YANLIŞ sıralanıyor (numeric
 * harmanlama ondalık noktayı ve eksiyi sayı olarak okumuyor). Tam
 * sayılarda fark yok, ama sütunun bir gün kesirli ya da negatif değer
 * taşımayacağını varsaymak için bir sebep yok.
 *
 * Metinlerde numeric:true ŞART: onsuz "web-10", "web-2"den önce gelir
 * ve adları sayıyla biten hedeflerde liste gözle yanlış görünür.
 *
 * Dışa açık, çünkü asıl mantık burada: bileşenin içinden test etmek
 * kesirli değerleri uydurma bir sütuna sıkıştırmayı gerektirirdi.
 */
export function compare(a: string | number, b: string | number): number {
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b), undefined, {
    numeric: true,
    sensitivity: "base",
  });
}

export default function DataTable<T>({
  rows,
  columns,
  rowKey,
  initialSort,
  searchLabel,
  searchPlaceholder,
  extraSearch,
  foot,
  toolbarExtra,
  noun,
  match,
  onRowClick,
}: {
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T) => string;
  initialSort?: { key: string; dir: Dir };
  searchLabel: string;
  searchPlaceholder?: string;
  /** Sütunlarda görünmeyen ama aranabilir olması gereken metin. */
  extraSearch?: (row: T) => string;
  /**
   * Aramayı DEVRALIR. Verilmezse sütun değerleri üzerinde alt dize
   * araması yapılır; verilirse (hedefler için sorgu dili) süzme buna
   * bırakılır.
   */
  match?: (row: T, query: string) => boolean;
  foot?: ReactNode;
  toolbarExtra?: ReactNode;
  /** "user" / "target" — sayaç ve boş sonuç metni için. */
  noun: string;
  /**
   * Satıra tıklanınca çalışır — özet tablodan detaya geçiş.
   *
   * ⚠️ TEK ERİŞİM YOLU DEĞİL. Tıklanabilir bir <tr> klavyeyle
   * ulaşılamaz ve `role="button"` vermek tablo semantiğini bozar.
   * Bu yüzden çağıran, gerçek bir <button> taşıyan bir sütun da
   * ekliyor; buradaki tıklama yalnızca fare için kısayol.
   */
  onRowClick?: (row: T) => void;
}) {
  const [sort, setSort] = useState<{ key: string; dir: Dir } | null>(
    initialSort ?? null,
  );
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    if (match) return rows.filter((r) => match(r, query.trim()));
    // Her terim AYRI aranıyor: "yigit web" yazan kişi iki alanda birden
    // eşleşme bekliyor, tek bir bitişik dize değil.
    const terms = q.split(/\s+/);
    return rows.filter((r) => {
      const hay = (
        columns.map((c) => (c.value ? String(c.value(r)) : "")).join(" ") +
        " " +
        (extraSearch ? extraSearch(r) : "")
      ).toLowerCase();
      return terms.every((t) => hay.includes(t));
    });
  }, [rows, columns, query, extraSearch, match]);

  const sorted = useMemo(() => {
    if (!sort) return filtered;
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.value) return filtered;
    // Kopya üzerinde: sort yerinde çalışıyor ve prop dizisini
    // değiştirmek çağıranın state'ini sessizce bozardı.
    const out = [...filtered];
    out.sort((a, b) => compare(col.value!(a), col.value!(b)));
    if (sort.dir === "desc") out.reverse();
    return out;
  }, [filtered, sort, columns]);

  const toggle = (key: string) => {
    setSort((cur) =>
      cur?.key === key
        ? { key, dir: cur.dir === "asc" ? "desc" : "asc" }
        : { key, dir: "asc" },
    );
  };

  const searching = query.trim() !== "";

  return (
    <div className="card">
      <div className="table-tools">
        <div className="search">
          <SearchIcon />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label={searchLabel}
            placeholder={searchPlaceholder ?? "Search…"}
          />
          {searching && (
            <button
              type="button"
              className="search-clear"
              onClick={() => setQuery("")}
              aria-label="clear the search"
            >
              ×
            </button>
          )}
        </div>
        {toolbarExtra}
        <span className="tools-spacer" />
        {/* Sayaç süsleme değil: süzülmüş bir listeye bakarken kaç satırın
            gizlendiğini bilmek, "hepsi bu kadar" yanılgısını önlüyor. */}
        <span className="count" role="status">
          {searching
            ? `${sorted.length} of ${rows.length} ${noun}${rows.length === 1 ? "" : "s"}`
            : `${rows.length} ${noun}${rows.length === 1 ? "" : "s"}`}
        </span>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              {columns.map((c) => {
                const sortable = c.sortable ?? Boolean(c.value);
                const active = sort?.key === c.key;
                return (
                  <th
                    key={c.key}
                    className={c.className}
                    // aria-sort YALNIZCA sıralı sütunda: her sütuna
                    // "none" koymak ekran okuyucuya her başlıkta
                    // sıralama durumu okutuyor ve gürültü yapıyor.
                    aria-sort={
                      active
                        ? sort!.dir === "asc"
                          ? "ascending"
                          : "descending"
                        : undefined
                    }
                  >
                    {c.srHeader ? (
                      <span className="th-pad">
                        <span className="sr-only">{c.header}</span>
                      </span>
                    ) : sortable ? (
                      <button
                        type="button"
                        className="sort"
                        onClick={() => toggle(c.key)}
                        aria-label={`sort by ${c.header}`}
                      >
                        {c.header}
                        <SortArrow dir={active ? sort!.dir : null} />
                      </button>
                    ) : (
                      <span className="th-pad">{c.header}</span>
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {sorted.map((r) => (
              <tr
                key={rowKey(r)}
                className={onRowClick ? "row-click" : undefined}
                onClick={
                  onRowClick
                    ? (e) => {
                        /*
                         * ⚠️ METİN SEÇİLDİYSE AÇMIYORUZ. Denetçi bir
                         * yolu ya da oturum kimliğini raporuna
                         * kopyalamak için sürükleyerek seçiyor; her
                         * seçim bir modal açsaydı kopyalamak imkânsız
                         * hâle gelirdi.
                         */
                        if (window.getSelection()?.toString()) return;
                        // Hücre içindeki gerçek bir düğme kendi işini
                        // yapsın; iki kez tetiklenmesin.
                        if ((e.target as HTMLElement).closest("button")) return;
                        onRowClick(r);
                      }
                    : undefined
                }
              >
                {columns.map((c) => (
                  <td key={c.key} className={c.className}>
                    {c.render
                      ? c.render(r)
                      : c.value
                        ? String(c.value(r))
                        : null}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>

        {/* "Aramanla eşleşen yok" ile "hiç kayıt yok" AYRI ekranlar:
            ikincisini çağıran ListState çiziyor, bu tablo hiç
            gösterilmiyor. */}
        {sorted.length === 0 && searching && (
          <p className="no-match" role="status">
            No {noun} matches “{query.trim()}”.
          </p>
        )}
      </div>

      {foot && <div className="card-foot">{foot}</div>}
    </div>
  );
}
