import { KeyboardEvent, useEffect, useId, useMemo, useRef, useState } from "react";

/**
 * MultiSelect — aranabilir çoklu seçim: seçilenler etiket (chip), altında
 * onay kutulu liste, tümünü seç / temizle, öbekler, klavye.
 *
 * ⚠️ NEDEN KENDİMİZ YAZDIK: kullanıcı CoreUI'nin Multi Select'ini istedi;
 * o bileşen CoreUI PRO (ticari lisans) ve Bootstrap 5 üstüne kurulu.
 * Panelde bilerek çerçeve yok — CSP `script-src 'self'`, ve
 * gosec/govulncheck'in taramadığı bir bağımlılık ağacı istenmiyor
 * (styles.css başındaki not). Aynı davranış ~300 satır ve panelin kendi
 * paletiyle; bedeli, tarayıcının yerleşik <select multiple>'ının
 * verdiği ücretsiz klavye/kaydırma davranışını burada yeniden kurmak.
 *
 * ⚠️ NEDEN <select multiple> DEĞİL: yüz hedefli bir envanterde Ctrl ile
 * çoklu seçim ve süzgeçsiz bir liste kullanılmıyor (kullanıcı söyledi);
 * seçilenlerin bir etiket olarak görünmesi, listede kaybolmalarından iyi.
 *
 * Erişilebilirlik: arama kutusu group=combobox ve başlıkla etiketli
 * (aria-labelledby); liste group=listbox, seçenekler group=option ve
 * aria-selected; öbekler group=group. Testler bu rollerle konuşuyor.
 */

export type MultiSelectOption = {
  value: string;
  label: string;
  /** Sağda, sönük: hedefin adresi gibi. Aramaya dahil. */
  hint?: string;
  disabled?: boolean;
  /** Öbek başlığı; boş/undefined öbeksiz. */
  group?: string;
};

function Check({ state }: { state: "on" | "off" | "mixed" }) {
  return <span className={"ms-check " + state} aria-hidden="true" />;
}

export default function MultiSelect({
  label,
  options,
  value,
  onChange,
  placeholder = "Search…",
  emptyText = "Nothing matches.",
  note,
}: {
  label: string;
  options: MultiSelectOption[];
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  emptyText?: string;
  /** Kutunun altındaki açıklama satırı. */
  note?: string;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const root = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);

  const q = query.trim().toLowerCase();
  const shown = useMemo(
    () =>
      options.filter(
        (o) =>
          !q ||
          o.label.toLowerCase().includes(q) ||
          (o.hint ?? "").toLowerCase().includes(q),
      ),
    [options, q],
  );
  // Öbekler ilk görüldükleri sırayla; öbeksiz seçenekler "" altında.
  const groups = useMemo(() => {
    const order: string[] = [];
    const by = new Map<string, MultiSelectOption[]>();
    for (const o of shown) {
      const g = o.group ?? "";
      if (!by.has(g)) {
        by.set(g, []);
        order.push(g);
      }
      by.get(g)!.push(o);
    }
    return order.map((name) => ({ name, options: by.get(name)! }));
  }, [shown]);
  const byValue = useMemo(() => new Map(options.map((o) => [o.value, o])), [options]);

  const selectable = shown.filter((o) => !o.disabled);
  const allOn = selectable.length > 0 && selectable.every((o) => value.includes(o.value));
  const someOn = selectable.some((o) => value.includes(o.value));

  /*
   * Dışarı tıklayınca kapan. mousedown, click DEĞİL: seçenekler kendi
   * mousedown'larını yutuyor (odak arama kutusunda kalsın diye) ve
   * click'e bağlansaydı bir seçeneğe basmak listeyi kapatırdı.
   */
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  useEffect(() => {
    setActive(0);
  }, [q, open]);

  const toggle = (v: string) => {
    const o = byValue.get(v);
    if (!o || o.disabled) return;
    onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v]);
  };

  /*
   * "Tümünü seç" SÜZÜLMÜŞ listeye uygulanıyor: kutuya "web" yazıp tümünü
   * seçmek web sunucularını seçer, envanterin tamamını değil. Düğme metni
   * de bunu söylüyor.
   */
  const toggleAll = () => {
    const vals = selectable.map((o) => o.value);
    onChange(
      allOn ? value.filter((v) => !vals.includes(v)) : Array.from(new Set([...value, ...vals])),
    );
  };

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        if (!open) setOpen(true);
        else setActive((i) => Math.min(i + 1, Math.max(shown.length - 1, 0)));
        break;
      case "ArrowUp":
        e.preventDefault();
        setActive((i) => Math.max(i - 1, 0));
        break;
      case "Enter":
        e.preventDefault();
        if (open && shown[active]) toggle(shown[active].value);
        else setOpen(true);
        break;
      case " ":
        // Boşluk yalnızca kutu boşken seçer; arama yazarken kelime ayırır.
        if (query === "" && open && shown[active]) {
          e.preventDefault();
          toggle(shown[active].value);
        }
        break;
      case "Escape":
        setOpen(false);
        break;
      case "Backspace":
        if (query === "" && value.length > 0) onChange(value.slice(0, -1));
        break;
    }
  };

  const renderOption = (o: MultiSelectOption) => {
    const idx = shown.indexOf(o);
    const on = value.includes(o.value);
    return (
      <div
        key={o.value}
        id={`${id}-opt-${idx}`}
        role="option"
        aria-selected={on}
        aria-disabled={o.disabled || undefined}
        className={"ms-option" + (idx === active ? " active" : "")}
        onMouseDown={(e) => e.preventDefault()}
        onMouseEnter={() => setActive(idx)}
        onClick={() => toggle(o.value)}
      >
        <Check state={on ? "on" : "off"} />
        <span className="ms-label">{o.label}</span>
        {o.hint && <span className="ms-hint">{o.hint}</span>}
      </div>
    );
  };

  return (
    <div className="ms-field" ref={root}>
      <span className="wfield-label" id={`${id}-label`}>
        {label}
      </span>
      <div className="ms-wrap">
        <div
          className={"ms" + (open ? " open" : "")}
          onMouseDown={(e) => {
            // Kutunun boş yerine basmak arama kutusunu odaklar; odak
            // zaten oradaysa listeyi aç/kapa.
            if (e.target === e.currentTarget || (e.target as HTMLElement).classList.contains("ms-tags")) {
              e.preventDefault();
              input.current?.focus();
              setOpen(true);
            }
          }}
        >
          <div className="ms-tags">
            {value.map((v) => {
              const text = byValue.get(v)?.label ?? v;
              return (
                <span key={v} className="ms-tag">
                  {text}
                  <button
                    type="button"
                    aria-label={`remove ${text}`}
                    onClick={() => onChange(value.filter((x) => x !== v))}
                  >
                    ×
                  </button>
                </span>
              );
            })}
            <input
              ref={input}
              role="combobox"
              aria-labelledby={`${id}-label`}
              aria-expanded={open}
              aria-controls={`${id}-list`}
              aria-autocomplete="list"
              aria-activedescendant={open && shown[active] ? `${id}-opt-${active}` : undefined}
              value={query}
              placeholder={value.length ? "" : placeholder}
              onChange={(e) => {
                setQuery(e.target.value);
                setOpen(true);
              }}
              onFocus={() => setOpen(true)}
              onKeyDown={onKey}
            />
          </div>
          {value.length > 0 && (
            <button
              type="button"
              className="ms-clear"
              aria-label={`clear ${label}`}
              onClick={() => onChange([])}
            >
              ×
            </button>
          )}
          <span className="ms-caret" aria-hidden="true">
            ▾
          </span>
        </div>

        {open && (
          <div
            className="ms-list"
            id={`${id}-list`}
            role="listbox"
            aria-multiselectable="true"
            aria-labelledby={`${id}-label`}
          >
            {selectable.length > 0 && (
              <button type="button" className="ms-all" onClick={toggleAll} aria-pressed={allOn}>
                <Check state={allOn ? "on" : someOn ? "mixed" : "off"} />
                {q ? `Select all ${selectable.length} matching` : "Select all"}
              </button>
            )}
            {shown.length === 0 && <p className="ms-empty">{emptyText}</p>}
            {groups.map((g) =>
              g.name ? (
                <div key={g.name} role="group" aria-label={g.name} className="ms-group">
                  <div className="ms-group-name">{g.name}</div>
                  {g.options.map(renderOption)}
                </div>
              ) : (
                <div key="" className="ms-group">
                  {g.options.map(renderOption)}
                </div>
              ),
            )}
          </div>
        )}
      </div>
      {note && <span className="muted small">{note}</span>}
    </div>
  );
}
