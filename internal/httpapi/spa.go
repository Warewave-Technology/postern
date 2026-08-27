package httpapi

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/warewave/postern/web"
)

// spaHandler, gömülü frontend'i sunar.
//
// SPA yönlendirme kuralı: dosya varsa dosya, yoksa index.html — istemci
// taraflı rotalar (/sessions gibi) sunucuda dosya DEĞİLDİR; hepsinin
// cevabı index.html'dir, gerisini JS çözer.
func spaHandler() http.Handler {
	dist := web.Dist()
	files := http.FileServerFS(dist)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p != "" {
			// Stat, Open değil: DİZİN de açılabiliyor ve dosya
			// sunucusu ona üretilmiş bir dizin listesiyle cevap
			// veriyordu. "/assets/" isteği ne bir dosya ne index.html
			// döndürüyor, gömülü ağacı sayılabilir kılıyordu — bugün
			// sızan bir şey yok (adlar zaten index.html'de geçiyor)
			// ama yarın web/dist'e giren bir source map ya da artık,
			// adını bilmeye gerek kalmadan bulunabilir olurdu.
			if st, err := fs.Stat(dist, p); err == nil && !st.IsDir() {
				files.ServeHTTP(w, r)
				return
			}
		}
		serveIndex(w, r, dist)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, dist fs.FS) {
	http.ServeFileFS(w, r, dist, "index.html")
}
