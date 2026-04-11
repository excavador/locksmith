package gpgsmith

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
)

type (
	// DaemonClient is the narrow subset of wire.Client that the web UI
	// actually uses. Defining it here (rather than taking *wire.Client
	// directly) lets tests inject a fake without dialing a real Unix
	// socket.
	//
	// The concrete adapter lives in wire_adapter.go.
	DaemonClient interface {
		VaultList(ctx context.Context) (*v1.ListResponse, error)
		VaultStatus(ctx context.Context) (*v1.StatusVaultResponse, error)
		VaultOpen(ctx context.Context, vaultName, passphrase string) (*v1.OpenResponse, error)
		VaultDiscard(ctx context.Context, sessionToken string) error

		KeyList(ctx context.Context, sessionToken string) (*v1.ListKeysResponse, error)
		KeyStatus(ctx context.Context, sessionToken string) (*v1.KeyStatusResponse, error)
		IdentityList(ctx context.Context, sessionToken string) (*v1.ListIdentitiesResponse, error)
		CardInventory(ctx context.Context, sessionToken string) (*v1.InventoryResponse, error)
		ServerList(ctx context.Context, sessionToken string) (*v1.ListServersResponse, error)
		ServerLookup(ctx context.Context, sessionToken string) (*v1.LookupResponse, error)
		AuditShow(ctx context.Context, sessionToken string, last int32) (*v1.ShowResponse, error)
	}

	// Config holds Server construction parameters.
	Config struct {
		// Client is the daemon-facing client. Required.
		Client DaemonClient

		// Logger is the slog logger for the server. If nil, a
		// discarding logger is used (tests).
		Logger *slog.Logger
	}

	// Server is the HTTP web UI. Construct via NewServer and install
	// Handler() on an http.Server to start serving.
	Server struct {
		client       DaemonClient
		logger       *slog.Logger
		tabs         *tabStore
		startupToken string
		templates    *template.Template
		mux          *http.ServeMux
	}

	tabCtxKey struct{}

	// discardWriter is a zero-alloc io.Writer for the default "no
	// logger" path. slog needs something to write to; we pick a value
	// that throws everything away rather than hitting stderr
	// unexpectedly from tests.
	discardWriter struct{}
)

func contextWithTab(ctx context.Context, t *tabState) context.Context {
	return context.WithValue(ctx, tabCtxKey{}, t)
}

func tabFromContext(ctx context.Context) (*tabState, bool) {
	t, ok := ctx.Value(tabCtxKey{}).(*tabState)
	return t, ok && t != nil
}

// NewServer assembles the HTTP handler graph. It does not start
// listening; install Handler() on an http.Server yourself.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Client == nil {
		return nil, errors.New("webui: Config.Client is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}

	tpl, err := template.New("webui").Funcs(templateFuncs()).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("webui: parse templates: %w", err)
	}

	s := &Server{
		client:       cfg.Client,
		logger:       logger,
		tabs:         newTabStore(),
		startupToken: newRandomToken(),
		templates:    tpl,
		mux:          http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

// StartupToken returns the one-shot token the server requires on the
// initial URL (?t=<token>). Callers print this to stderr at startup.
func (s *Server) StartupToken() string {
	return s.startupToken
}

// Handler returns the fully-wired HTTP handler: auth middleware +
// routed mux. Callers install it on an http.Server and call Serve.
func (s *Server) Handler() http.Handler {
	return s.authMiddleware(s.mux)
}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
