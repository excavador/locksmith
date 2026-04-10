package wire

import (
	"net/http"

	"github.com/excavador/locksmith/pkg/gen/gpgsmith/v1/gpgsmithv1connect"
)

// Server bundles the gpgsmith ConnectRPC service handlers into a single
// http.Handler ready to be served over a Unix socket (by the daemon) or a
// localhost TCP listener (by the web UI shim, if it ever wants to expose
// the same surface to the browser via Connect-Web).
//
// Construct via NewServer(backend); call Handler() to get the
// http.Handler suitable for http.Server.
type (
	Server struct {
		backend Backend
		mux     *http.ServeMux
	}
)

// NewServer wires every gpgsmith Connect service handler into a single
// http.ServeMux. Each handler delegates to the supplied Backend.
func NewServer(backend Backend) *Server {
	mux := http.NewServeMux()

	type registration struct {
		path    string
		handler http.Handler
	}

	regs := []registration{}

	{
		path, handler := gpgsmithv1connect.NewDaemonServiceHandler(newDaemonHandler(backend))
		regs = append(regs, registration{path, handler})
	}
	{
		path, handler := gpgsmithv1connect.NewVaultServiceHandler(newVaultHandler(backend))
		regs = append(regs, registration{path, handler})
	}
	{
		path, handler := gpgsmithv1connect.NewKeyServiceHandler(newKeyHandler(backend))
		regs = append(regs, registration{path, handler})
	}
	{
		path, handler := gpgsmithv1connect.NewIdentityServiceHandler(newIdentityHandler(backend))
		regs = append(regs, registration{path, handler})
	}
	{
		path, handler := gpgsmithv1connect.NewCardServiceHandler(newCardHandler(backend))
		regs = append(regs, registration{path, handler})
	}
	{
		path, handler := gpgsmithv1connect.NewServerServiceHandler(newServerHandler(backend))
		regs = append(regs, registration{path, handler})
	}
	{
		path, handler := gpgsmithv1connect.NewAuditServiceHandler(newAuditHandler(backend))
		regs = append(regs, registration{path, handler})
	}
	{
		path, handler := gpgsmithv1connect.NewEventServiceHandler(newEventHandler(backend))
		regs = append(regs, registration{path, handler})
	}

	for _, r := range regs {
		mux.Handle(r.path, r.handler)
	}

	return &Server{
		backend: backend,
		mux:     mux,
	}
}

// Handler returns the http.Handler that serves all gpgsmith Connect
// services. The daemon mounts this on its Unix socket; tests can mount it
// on an httptest.Server for round-trip integration tests.
func (s *Server) Handler() http.Handler {
	return s.mux
}
