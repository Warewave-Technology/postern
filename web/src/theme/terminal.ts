/**
 * Monokai Material — canlı terminalin ve kayıt oynatıcının ortak teması.
 *
 * NEDEN ORTAK DOSYA: renkler iki ayrı bileşende ayrı ayrı yazılıydı
 * (`{ background: "#111", foreground: "#eee" }`). Aynı oturumu canlı
 * izleyen ile kaydından izleyen operatör FARKLI renkler görebilirdi —
 * bir denetim aracında "gördüğüm şey aynı mı" sorusunun cevabı evet
 * olmak zorunda.
 *
 * ⚠️ ANSI EŞLEMESİ KASITLI: Monokai'de gerçek bir mavi yok. Terminaller
 * mavi (4) isteyince cyan veriliyor; turuncu, ANSI'de yeri olmadığı için
 * parlak sarıya bindirilmiyor — kendi yerinde bırakılıyor. Rastgele bir
 * mavi uydurmak, `ls --color` çıktısını Monokai olmayan tek renk yapardı.
 */
export const monokaiMaterial = {
  background: "#221F22",
  foreground: "#FCFCFA",

  // İmleç ve seçim: seçim yarı saydam değil düz renk — xterm'in canvas
  // katmanında saydam seçim, altındaki metni okunmaz hale getiriyor.
  cursor: "#FCFCFA",
  cursorAccent: "#221F22",
  selectionBackground: "#4A454B",
  selectionForeground: "#FCFCFA",

  black: "#403E41",
  red: "#FF6188",
  green: "#A9DC76",
  yellow: "#FFD866",
  blue: "#78DCE8",
  magenta: "#AB9DF2",
  cyan: "#78DCE8",
  white: "#FCFCFA",

  brightBlack: "#727072",
  brightRed: "#FF6188",
  brightGreen: "#A9DC76",
  brightYellow: "#FC9867",
  brightBlue: "#78DCE8",
  brightMagenta: "#AB9DF2",
  brightCyan: "#78DCE8",
  brightWhite: "#FCFCFA",
} as const;

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
