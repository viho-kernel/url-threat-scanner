package main

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed web/dist
var embeddedWebFiles embed.FS

func newUIHandler() (http.Handler, error) {
	dist, err := fs.Sub(embeddedWebFiles, "web/dist")
	if err != nil {
		return nil, err
	}

	fileServer := http.FileServer(http.FS(dist))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath := strings.TrimPrefix(
			path.Clean(r.URL.Path),
			"/",
		)

		if requestedPath != "." && requestedPath != "" {
			if _, err := fs.Stat(dist, requestedPath); err != nil {
				r.URL.Path = "/"
			}
		}

		fileServer.ServeHTTP(w, r)
	}), nil
}
