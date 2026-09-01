/*
 * QRCode — sunucunun ürettiği modül matrisini çizer.
 *
 * ⚠️ MATRİS SUNUCUDAN GELİYOR, BURADA ÜRETİLMİYOR. Kodlayıcı Go
 * tarafında (internal/qr) ve orada bağımsız bir uygulamayla (Apple
 * CoreImage) bit bit karşılaştırılarak doğrulanıyor. Panelde ikinci bir
 * kodlayıcı bulundurmak, ikinci bir doğrulama yükü ve sessizce
 * ayrışabilecek iki gerçek demek olurdu.
 */

// QUIET, kodun çevresindeki boş kenar (modül cinsinden).
//
// ⚠️ 4 MODÜL, ISO/IEC 18004'ün istediği en az değer. Kenarsız bir kod,
// arkasındaki sayfa desenini kodun parçası sanan tarayıcılarda
// okunmuyor — ve bunu ancak telefonunu tutup deneyen kullanıcı fark
// eder.
const QUIET = 4;

export default function QRCode({
  rows,
  label,
}: {
  // rows: her satır '0'/'1' karakterlerinden; '1' = koyu modül.
  rows: string[];
  label: string;
}) {
  if (rows.length === 0) return null;
  const n = rows.length;
  const span = n + QUIET * 2;

  // Koyu modülleri TEK bir path'te topluyoruz: 53x53'lük bir kodda
  // ~1400 ayrı <rect>, DOM'u gereksiz şişiriyor.
  let d = "";
  for (let y = 0; y < n; y++) {
    const row = rows[y];
    for (let x = 0; x < row.length; x++) {
      if (row[x] === "1") d += `M${x + QUIET} ${y + QUIET}h1v1h-1z`;
    }
  }

  return (
    <svg
      className="qr"
      viewBox={`0 0 ${span} ${span}`}
      role="img"
      aria-label={label}
      shapeRendering="crispEdges"
    >
      {/*
        ⚠️ RENKLER TEMA BELİRTECİ DEĞİL, SABİT.

        Koyu temada gruvbox belirteçleri kodu TERSİNE çevirirdi (açık
        modüller koyu zeminde) ve tarayıcıların çoğu tersine dönmüş bir
        QR'ı okumuyor. Kullanıcı bunu ancak telefonunu tutup denerken
        anlar; o noktada hesabına giremiyor olur. Bu yüzden bu kart
        temaya UYMUYOR — okunabilirlik, tutarlılıktan önce geliyor.
      */}
      <rect width={span} height={span} fill="#ffffff" />
      <path d={d} fill="#000000" />
    </svg>
  );
}
