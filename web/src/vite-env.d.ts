/**
 * Vite'ın `?raw` içe aktarımı için tip bildirimi.
 *
 * @types/node EKLEMEMEK için: styles.test.ts stil dosyasını okuyor ve
 * bunu fs ile yapmak, yalnızca bir testin uğruna bütün Node tip
 * paketini bağımlılığa çevirirdi. `?raw` derleyici tarafından gömülüyor,
 * çalışma zamanında dosya sistemi yok.
 */
declare module "*?raw" {
  const content: string;
  export default content;
}
