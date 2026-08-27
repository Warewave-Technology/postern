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
			if f, err := dist.Open(p); err == nil {
				f.Close()
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
