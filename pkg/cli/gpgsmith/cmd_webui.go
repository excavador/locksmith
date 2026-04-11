package gpgsmith

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/urfave/cli/v3"

	webui "github.com/excavador/locksmith/pkg/webui/gpgsmith"
)

func webuiCmd() *cli.Command {
	return &cli.Command{
		Name:  "webui",
		Usage: "start a local web UI for gpgsmith (loopback-only)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "bind",
				Usage: "bind address (must be a loopback host; port 0 picks automatically)",
				Value: "127.0.0.1:0",
			},
			&cli.BoolFlag{
				Name:  "open",
				Usage: "open the access URL in the default browser after startup",
				Value: true,
			},
			&cli.BoolFlag{
				Name:  "no-open",
				Usage: "do not open a browser (overrides --open)",
			},
		},
		Action: webuiStart,
	}
}

func webuiStart(ctx context.Context, cmd *cli.Command) error {
	logger := loggerFrom(ctx)

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("webui: %w", err)
	}
	defer client.Close()

	srv, err := webui.NewServer(webui.Config{
		Client: webui.NewWireAdapter(client),
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("webui: %w", err)
	}

	// Bind up-front so we can log the effective port before blocking.
	// The server loops Serve internally; we start a listener here to
	// get the final address with port 0 → OS-assigned.
	ln, err := startWebuiListener(ctx, cmd.String("bind"))
	if err != nil {
		return fmt.Errorf("webui: %w", err)
	}

	uiURL := fmt.Sprintf("http://%s/?t=%s", ln.Addr().String(), srv.StartupToken())
	logger.InfoContext(ctx, "webui: ready",
		slog.String("url", uiURL),
	)
	_, _ = fmt.Fprintf(cmd.Writer, "gpgsmith web UI: %s\n", uiURL)

	// Browser auto-open. Disabled via --no-open or when --open was
	// explicitly set to false.
	if !cmd.Bool("no-open") && cmd.Bool("open") {
		if oerr := openBrowser(ctx, uiURL); oerr != nil {
			logger.WarnContext(ctx, "webui: open browser",
				slog.String("error", oerr.Error()),
			)
		}
	}

	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

func startWebuiListener(ctx context.Context, bindAddr string) (net.Listener, error) {
	if err := assertLoopbackAddr(ctx, bindAddr); err != nil {
		return nil, err
	}
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", bindAddr)
}

// assertLoopbackAddr fails fast if the operator tries to bind a
// non-loopback host. The web UI's security perimeter is "local user
// only"; binding 0.0.0.0 would expose a token-protected but still
// network-reachable HTTP server, which is not what we want.
func assertLoopbackAddr(ctx context.Context, bindAddr string) error {
	host, _, err := net.SplitHostPort(bindAddr)
	if err != nil {
		return fmt.Errorf("invalid bind address %q: %w", bindAddr, err)
	}
	if host == "" {
		return fmt.Errorf("bind address %q has no host; use 127.0.0.1 or ::1", bindAddr)
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if !ip.IsLoopback() {
			return fmt.Errorf("bind address %q is not loopback; refusing", bindAddr)
		}
		return nil
	}
	var resolver net.Resolver
	addrs, lookupErr := resolver.LookupIPAddr(ctx, host)
	if lookupErr != nil || len(addrs) == 0 {
		return fmt.Errorf("cannot resolve bind host %q: %w", host, lookupErr)
	}
	for _, a := range addrs {
		if !a.IP.IsLoopback() {
			return fmt.Errorf("bind host %q resolves to non-loopback address %s; refusing", host, a.IP)
		}
	}
	return nil
}

func openBrowser(ctx context.Context, url string) error {
	var bin string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		bin = "open"
		args = []string{url}
	case "linux":
		bin = "xdg-open"
		args = []string{url}
	default:
		return fmt.Errorf("unsupported OS %q for browser auto-open", runtime.GOOS)
	}
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // url is our own generated string
	return cmd.Start()
}
