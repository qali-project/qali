// Package webui embeds the production web bundle built by `make build`.
//
// Vite writes the bundle to dist/app. dist/.keep exists so the package
// compiles before the frontend is built; the server then answers 503 for the
// application shell.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the bundle with index.html at its root.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist/app")
	if err != nil {
		panic(err) // unreachable: "dist/app" is a valid static path
	}
	return sub
}
