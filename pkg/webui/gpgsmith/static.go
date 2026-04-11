// Package gpgsmith hosts the gpgsmith web UI — a thin HTTP frontend
// that calls the daemon over its Unix socket via wire.Client. It does
// no GPG, no vault crypto, and no audit on its own.
package gpgsmith

import (
	"embed"
)

// staticFS carries the CSS + vendored HTMX bundle that the browser
// fetches from /static/*. The bundle is small (~50KB) so we embed it
// directly into the binary instead of shipping a separate asset dir.
//
// templatesFS carries the html/template sources. We opted for the
// stdlib html/template over a-h/templ to avoid adding a code-generation
// step and an extra devbox package; the page count is small enough
// that the ergonomics cost is minimal.
var (
	//go:embed static/style.css static/htmx.min.js
	staticFS embed.FS

	//go:embed templates/*.html
	templatesFS embed.FS
)
