package sshd

import "errors"

// Route is the parsed form of the "user:target" SSH username convention.
// İstemci `ssh yigit:web01@bastion` yazdığında SSH protokolünde username
// alanı "yigit:web01" olarak gelir; biz onu kişi + hedefe ayırırız.
type Route struct {
	User   string
	Target string
}

// ParseUsername splits raw ("user:target") into a Route.
//
// TODO(yigit) — S1.3: implement et. Kurallar (test tablosu = sözleşme):
//   - İLK ':' ayraçtır, sonrakiler target'ın parçasıdır
//     ("yigit:web:01" → {yigit, web:01}). İpucu: strings.Cut tam bu iş.
//   - Boş girdi / ':' hiç yok / boş user / boş target → hepsi hata.
//   - Üst uzunluk sınırı koy ve sabit (const) olarak tanımla (ör. 255).
//     Bu string, saldırgan kontrolündeki İLK girdi — sınırsız haliyle
//     karşılaştırmalara ve loglara girmemeli (plan Ek B, "Girdi").
//   - Hata mesajına raw string'in kendisini KOYMA (log'a saldırgan verisi
//     enjekte etmenin en kısa yolu); sadece sebebi söyle.
func ParseUsername(raw string) (Route, error) {
	return Route{}, errors.New("sshd.ParseUsername: not implemented")
}
