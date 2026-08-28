import type { Resolved } from "./mode";

/**
 * gruvbox — canlı terminalin ve kayıt oynatıcının ortak teması.
 *
 * NEDEN ORTAK DOSYA: renkler iki ayrı bileşende ayrı ayrı yazılıydı.
 * Aynı oturumu canlı izleyen ile kaydından izleyen operatör FARKLI
 * renkler görebilirdi — bir denetim aracında "gördüğüm şey aynı mı"
 * sorusunun cevabı evet olmak zorunda.
 *
 * ⚠️ TERMINAL TEMAYI İZLİYOR. Daha önce her hâlde koyu kalıyordu, çünkü
 * çoğu terminal paleti yalnızca koyu zemin için tasarlanmış. gruvbox'ın
 * AÇIK varyantı gerçek bir tasarım tercihidir ve okunur; aydınlık
 * temada paneli açıp içinde tek bir siyah dikdörtgen görmek, temanın
 * kendisini yarım bırakmak olurdu.
 *
 * ⚠️ ANSI EŞLEMESİ gruvbox'ın kendi sırası: normal renkler soluk (bg
 * varyantı), parlak renkler doygun. Rastgele bir eşleme `ls --color`
 * çıktısını gruvbox olmayan tek renk yapardı.
 */

const dark = {
  background: "#282828",
  foreground: "#ebdbb2",

  cursor: "#ebdbb2",
  cursorAccent: "#282828",
  // Seçim DÜZ renk: xterm'in katmanında yarı saydam seçim, altındaki
  // metni okunmaz hale getiriyor.
  selectionBackground: "#504945",
  selectionForeground: "#ebdbb2",

  black: "#282828",
  red: "#cc241d",
  green: "#98971a",
  yellow: "#d79921",
  blue: "#458588",
  magenta: "#b16286",
  cyan: "#689d6a",
  white: "#a89984",

  brightBlack: "#928374",
  brightRed: "#fb4934",
  brightGreen: "#b8bb26",
  brightYellow: "#fabd2f",
  brightBlue: "#83a598",
  brightMagenta: "#d3869b",
  brightCyan: "#8ec07c",
  brightWhite: "#ebdbb2",
} as const;

const light = {
  background: "#fbf1c7",
  foreground: "#3c3836",

  cursor: "#3c3836",
  cursorAccent: "#fbf1c7",
  selectionBackground: "#d5c4a1",
  selectionForeground: "#3c3836",

  black: "#fbf1c7",
  red: "#cc241d",
  green: "#98971a",
  yellow: "#d79921",
  blue: "#458588",
  magenta: "#b16286",
  cyan: "#689d6a",
  white: "#7c6f64",

  brightBlack: "#928374",
  // Aydınlık varyantta PARLAK renkler daha KOYU: krem zemin üzerinde
  // gruvbox'ın doygun renkleri okunmuyor, koyu varyantları okunuyor.
  brightRed: "#9d0006",
  brightGreen: "#79740e",
  brightYellow: "#b57614",
  brightBlue: "#076678",
  brightMagenta: "#8f3f71",
  brightCyan: "#427b58",
  brightWhite: "#3c3836",
} as const;

export function gruvbox(resolved: Resolved) {
  return resolved === "dark" ? dark : light;
}

/** Terminal yüzeyinin zemini — kabın da aynı rengi alması için. */
export function terminalBackground(resolved: Resolved): string {
  return gruvbox(resolved).background;
}

/**
 * Terminal yüzeyinin ortak yazı ayarları.
 *
 * fontFamily xterm'e AÇIKÇA veriliyor: verilmezse xterm "courier-new"
 * varsayılanına düşüyor ve panelin geri kalanındaki mono yığınından
 * görünür biçimde ayrılıyordu.
 */
export const terminalFont = {
  fontFamily:
    'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
  fontSize: 13,
  lineHeight: 1.35,
} as const;
