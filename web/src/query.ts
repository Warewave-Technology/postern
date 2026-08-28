/**
 * Hedef araması için küçük bir sorgu dili.
 *
 * NEDEN DİL, DÜZ ALT DİZE DEĞİL: "prod" yazan operatör adında prod
 * geçen hedefi mi, env=prod etiketlisini mi arıyor belli değil — ve
 * ikisini birden döndürmek, elli makineli bir kurulumda listeyi
 * daraltmıyor. Alan adı vererek sorulan soru kesin oluyor.
 *
 * DİL:
 *   web                     her yerde "web" geçen
 *   name: web-server        adında geçen
 *   env: prod               env etiketi prod olan
 *   env:                    env etiketi OLAN (değeri ne olursa olsun)
 *   -env: prod              env etiketi prod OLMAYAN
 *   name: web and env: prod ikisi birden
 *   env: prod or env: stage biri ya da diğeri
 *
 * Boşlukla ayrılmış terimler zaten VE ile bağlanıyor; `and` yazmak
 * serbest çünkü insan öyle yazıyor. `and`, `or`dan daha sıkı bağlar —
 * "a and b or c" = "(a ve b) veya c", matematikteki alışkanlıkla aynı.
 */

export type Fields = {
  name: string;
  labels: Record<string, string>;
  /** Ada ve etikete girmeyen ama aranabilir olması gereken metin. */
  extra?: Record<string, string>;
};

type Term = { negate: boolean; field: string | null; value: string };

/** Bir VEYA öbeği: içindeki terimler VE ile bağlı. */
type Group = Term[];

export type Query = Group[];

/**
 * parse, sorgu metnini öbeklere çevirir.
 *
 * Ayrıştırma HİÇBİR ZAMAN hata atmıyor: yazarken her tuşta çalışan bir
 * kutuda yarım kalmış sorgu normaldir ("env:" henüz değeri yazılmamış).
 * Anlaşılmayan parça terim olarak alınıyor; kullanıcı yazmaya devam
 * ediyor.
 */
export function parse(input: string): Query {
  // "name : web" ve "name: web" → "name:web". Kullanıcı iki nokta
  // etrafında boşluk bırakıyor ve bunu bir sözdizimi hatası saymak
  // dili kullanılmaz yapardı.
  const normalized = input.replace(/\s*:\s*/g, ":").trim();
  if (!normalized) return [];

  const tokens = normalized.split(/\s+/).filter(Boolean);

  const groups: Group[] = [];
  let current: Group = [];

  for (const tok of tokens) {
    const lower = tok.toLowerCase();
    if (lower === "or" || lower === "||") {
      // Boş öbek eklemiyoruz: "a or" yazarken araya boş bir öbek
      // girseydi sorgu her satırla eşleşirdi.
      if (current.length > 0) groups.push(current);
      current = [];
      continue;
    }
    if (lower === "and" || lower === "&&") continue;

    current.push(toTerm(tok));
  }
  if (current.length > 0) groups.push(current);
  return groups;
}

function toTerm(tok: string): Term {
  let negate = false;
  let t = tok;
  if (t.startsWith("-") && t.length > 1) {
    negate = true;
    t = t.slice(1);
  }
  const i = t.indexOf(":");
  if (i > 0) {
    return { negate, field: t.slice(0, i).toLowerCase(), value: t.slice(i + 1).toLowerCase() };
  }
  return { negate, field: null, value: t.toLowerCase() };
}

/** matches, tek bir kaydın sorguyu karşılayıp karşılamadığı. */
export function matches(q: Query, f: Fields): boolean {
  if (q.length === 0) return true;
  // Öbekler VEYA ile bağlı.
  return q.some((group) => group.every((term) => matchTerm(term, f)));
}

function matchTerm(t: Term, f: Fields): boolean {
  const hit = termHit(t, f);
  return t.negate ? !hit : hit;
}

function termHit(t: Term, f: Fields): boolean {
  if (t.field === null) {
    // Alansız terim: her yerde ara.
    return haystack(f).includes(t.value);
  }

  if (t.field === "name") return f.name.toLowerCase().includes(t.value);

  // Bilinen ek alanlar (server_version gibi).
  const extra = f.extra?.[t.field];
  if (extra !== undefined) return extra.toLowerCase().includes(t.value);

  // Geri kalan her alan adı bir ETİKET ANAHTARI sayılıyor. Bilinmeyen
  // bir alanı hata saymak yerine etiket olarak denemek, kullanıcının
  // kendi etiket şemasını öğrenmek zorunda olmayan bir dil veriyor.
  const key = Object.keys(f.labels).find((k) => k.toLowerCase() === t.field);
  if (key === undefined) return false;

  // "env:" → değeri ne olursa olsun etiketin VARLIĞI.
  if (t.value === "") return true;
  return f.labels[key].toLowerCase().includes(t.value);
}

function haystack(f: Fields): string {
  const parts = [f.name];
  for (const [k, v] of Object.entries(f.labels)) parts.push(k, v, `${k}=${v}`);
  if (f.extra) for (const v of Object.values(f.extra)) parts.push(v);
  return parts.join(" ").toLowerCase();
}

/**
 * describe, sorgunun ne aradığını insan diline çevirir.
 *
 * Sonuç boş çıktığında "hiçbir şey eşleşmedi" demek yetmiyor: kullanıcı
 * sorgusunu mu yanlış yazdı, gerçekten mi yok bilemiyor. Ekranda ne
 * anlaşıldığını göstermek bu ikisini ayırıyor.
 */
export function describe(q: Query): string {
  if (q.length === 0) return "";
  return q
    .map((group) =>
      group
        .map((t) => {
          const what =
            t.field === null
              ? `anything matching “${t.value}”`
              : t.value === ""
                ? `has a ${t.field} label`
                : `${t.field} contains “${t.value}”`;
          return t.negate ? `not ${what}` : what;
        })
        .join(" and "),
    )
    .join(" — or — ");
}
