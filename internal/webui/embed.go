package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed dist/*
var assets embed.FS

func Handler() http.Handler {
	dist, err := fs.Sub(assets, "dist")
	if err != nil {
		panic(err)
	}
	return &spaHandler{files: dist, static: http.FileServer(http.FS(dist))}
}

type spaHandler struct {
	files  fs.FS
	static http.Handler
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	if info, err := fs.Stat(h.files, path); err == nil && !info.IsDir() {
		if strings.HasPrefix(path, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		h.static.ServeHTTP(w, r)
		return
	}
	r.URL.Path = "/"
	w.Header().Set("Cache-Control", "no-cache")
	h.static.ServeHTTP(w, r)
}
