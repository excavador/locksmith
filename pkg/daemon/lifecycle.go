package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/excavador/locksmith/pkg/gpgsmith"
	"github.com/excavador/locksmith/pkg/wire"
)

// Run is the daemon main loop: hardens the process, binds the Unix
// socket, serves the wire ConnectRPC API over h2c (so server-streaming
// RPCs like EventService.Subscribe work over cleartext HTTP/2), and
// handles SIGINT / SIGTERM / SIGHUP with a graceful shutdown.
//
// Run blocks until the listener is closed (shutdown) or an error
// occurs. It returns nil on normal shutdown.
func (d *Daemon) Run(ctx context.Context) error {
	if err := gpgsmith.HardenProcess(); err != nil {
		d.logger.WarnContext(ctx, "process hardening failed",
			slog.String("error", err.Error()),
		)
	}

	if d.socketPath == "" {
		sp, err := SocketPath()
		if err != nil {
			return err
		}
		d.socketPath = sp
	}

	ln, err := BindSocket(d.socketPath)
	if err != nil {
		return err
	}

	d.logger.InfoContext(ctx, "daemon listening",
		slog.String("socket", d.socketPath),
	)

	handler := wire.NewServer(d).Handler()
	h2s := &http2.Server{}
	httpSrv := &http.Server{
		Handler: h2c.NewHandler(handler, h2s),
		// Disable read/write timeouts: EventService.Subscribe is a
		// long-running server-stream. Per-call deadlines are supplied
		// by the client via the Connect context.
		ReadHeaderTimeout: 10 * time.Second,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	serveErr := make(chan error, 1)
	go func() {
		err := httpSrv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	var shutdownOnce sync.Once
	shutdown := func(reason string) {
		shutdownOnce.Do(func() {
			d.logger.InfoContext(ctx, "daemon shutdown initiated",
				slog.String("reason", reason),
			)
			shutCtx, cancel := context.WithTimeout(context.Background(), d.gracefulTimeout)
			defer cancel()
			if err := d.DaemonShutdown(shutCtx, int(d.gracefulTimeout/time.Second)); err != nil {
				d.logger.WarnContext(shutCtx, "daemon shutdown returned error",
					slog.String("error", err.Error()),
				)
			}
			closeCtx, closeCancel := context.WithTimeout(context.Background(), d.gracefulTimeout)
			defer closeCancel()
			_ = httpSrv.Shutdown(closeCtx)
			_ = ln.Close()
			_ = os.Remove(d.socketPath)
		})
	}

	select {
	case sig := <-sigCh:
		shutdown(fmt.Sprintf("signal %s", sig))
	case <-ctx.Done():
		shutdown("context canceled")
	case <-d.ShutdownCh():
		shutdown("rpc shutdown")
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("daemon serve: %w", err)
		}
	}

	// Drain the serve goroutine.
	if err := <-serveErr; err != nil {
		return fmt.Errorf("daemon serve: %w", err)
	}
	return nil
}
