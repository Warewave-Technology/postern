// Package web embeds the built frontend.
//
// dist/ npm build'in çıktısıdır (bkz. web/README.md). Boş placeholder
// commit'lidir ki go:embed derlemeyi kırmasın; gerçek arayüz için önce
// frontend build edilir.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist, dist/ kökünü dosya sistemi olarak döner.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// go:embed derleme zamanında doğrulanır; buraya düşmek imkânsız.
		panic(err)
	}
	return sub
}
