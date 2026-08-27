// asciicast v2 ayrıştırma ve zamanlama.
//
// Saf fonksiyonlar: DOM yok, xterm yok. Oynatıcının kendisi
// CastPlayer.tsx'te; buradaki mantık ondan ayrı durduğu için testi de
// tarayıcı olmadan yazılabiliyor.
//
// NEDEN asciinema-player DEĞİL: paket 3.x sürümlerinde VT emülasyonunu
// base64 gömülü bir WASM modülü olarak taşıyor ve
// WebAssembly.instantiate çağırıyor. postern'in CSP'si script-src
// 'self' — ölçüldü, tarayıcı modülü derlemeyi reddediyor. Çalıştırmak
// için CSP'yi gevşetmek gerekirdi; bir bastion panelinde WASM'a izin
// vermek, oynatıcı rahatlığı için ödenecek bir bedel değil. xterm.js
// zaten web terminali için bağımlılığımız ve aynı VT'yi yorumluyor.

export type CastHeader = {
  version: number;
  width: number;
  height: number;
  timestamp?: number;
};

export type CastEvent = {
  /** Kayıt başından itibaren saniye. */
  time: number;
  /** "o" çıktı, "i" girdi, "r" yeniden boyutlandırma. */
  kind: "o" | "i" | "r";
  data: string;
};

export type Cast = {
  header: CastHeader;
  events: CastEvent[];
  /** Son satır yarım kaldıysa true: oturum sürüyor olabilir. */
  truncated: boolean;
};

export class CastError extends Error {}

/**
 * parseCast, asciicast v2 metnini ayrıştırır.
 *
 * Yarım kalan SON satır hata değil: süren bir oturumun dosyası
 * büyümeye devam ediyor ve sunucu son satır sonuna kadar kesiyor —
 * ama ağ ya da disk yine de yarım bir satır bırakabilir. Orada durup
 * `truncated` işaretliyoruz; atmak, izlenebilir olanı da atmak olurdu.
 */
export function parseCast(text: string): Cast {
  const lines = text.split("\n");
  if (lines.length === 0 || lines[0].trim() === "") {
    throw new CastError("recording is empty");
  }

  let header: CastHeader;
  try {
    header = JSON.parse(lines[0]);
  } catch {
    throw new CastError("recording header is not valid JSON");
  }
  if (header.version !== 2) {
    throw new CastError(`unsupported asciicast version ${header.version}`);
  }

  const events: CastEvent[] = [];
  let truncated = false;

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (line === "") continue;

    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      // Yalnız SON satırın yarım olması beklenir; ortada bozuk bir
      // satır varsa dosya gerçekten bozuk demektir ve bunu söylemek
      // sessizce yutmaktan iyidir.
      if (i === lines.length - 1) {
        truncated = true;
        break;
      }
      throw new CastError(`recording is corrupt at line ${i + 1}`);
    }

    if (!Array.isArray(parsed) || parsed.length < 3) continue;
    const [time, kind, data] = parsed;
    if (typeof time !== "number" || typeof data !== "string") continue;
    if (kind !== "o" && kind !== "i" && kind !== "r") continue;

    events.push({ time, kind, data });
  }

  return { header, events, truncated };
}

/**
 * compress, uzun sessizlikleri kısaltır.
 *
 * Bir oturumda kullanıcının düşündüğü, kahve içtiği, toplantıya gittiği
 * boşluklar var. Gerçek zamanlı oynatmak, üç saatlik bir kaydı üç saatte
 * izlemek demek — kimse yapmaz, dolayısıyla kayıt de facto izlenmez
 * olur. Sınırdan uzun her boşluk sınıra indiriliyor.
 *
 * Zaman damgaları DEĞİŞTİRİLMİYOR: dönen her olay kendi ORİJİNAL
 * zamanını da taşıyor, çünkü denetimde "ne zaman oldu" sorusunun cevabı
 * oynatma hızından bağımsız olmalı.
 */
export function compress(
  events: CastEvent[],
  idleLimit = 2,
): Array<CastEvent & { playAt: number }> {
  const out: Array<CastEvent & { playAt: number }> = [];
  let shift = 0;
  let prev = 0;

  for (const e of events) {
    const gap = e.time - prev;
    if (gap > idleLimit) {
      shift += gap - idleLimit;
    }
    out.push({ ...e, playAt: e.time - shift });
    prev = e.time;
  }
  return out;
}

/** duration, kaydın toplam süresi (saniye). */
export function duration(events: CastEvent[]): number {
  return events.length === 0 ? 0 : events[events.length - 1].time;
}

/** formatDuration, saniyeyi m:ss ya da h:mm:ss olarak yazar. */
export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;

  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${m}:${pad(sec)}`;
}
