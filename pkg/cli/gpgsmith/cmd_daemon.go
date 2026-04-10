package gpgsmith

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	"github.com/excavador/locksmith/pkg/daemon"
	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/wire"
)

const (
	// daemonStartupTimeout caps how long the parent process waits for a
	// detached child daemon to bind its socket before giving up.
	daemonStartupTimeout = 5 * time.Second

	// daemonPollInterval is the interval at which we poll the socket path
	// while waiting for the daemon to come up or go down.
	daemonPollInterval = 50 * time.Millisecond

	// daemonDefaultGraceful is the default graceful-shutdown timeout
	// passed to Shutdown RPCs from the CLI.
	daemonDefaultGraceful = 30

	// exitDaemonNotRunning follows the systemctl --user "inactive" exit
	// code: `status` on a stopped unit exits 3.
	exitDaemonNotRunning = 3
)

// daemonCmd builds the `gpgsmith daemon` subcommand group. The
// version/commit/date triple flows in from Main so that the foreground
// runner can embed them in daemon.Options just like the rest of the CLI
// does for the `version` subcommand.
func daemonCmd(version, commit, date string) *cli.Command {
	_ = date // reserved for a future `daemon status` build-date field
	return &cli.Command{
		Name:  "daemon",
		Usage: "manage the gpgsmith background daemon",
		Commands: []*cli.Command{
			{
				Name:  "start",
				Usage: "start the gpgsmith daemon",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "foreground",
						Usage: "run the daemon in the current process instead of spawning a detached child",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return daemonStart(ctx, cmd, version, commit)
				},
			},
			{
				Name:  "stop",
				Usage: "stop the running gpgsmith daemon",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "timeout",
						Usage: "graceful shutdown timeout in seconds",
						Value: daemonDefaultGraceful,
					},
				},
				Action: daemonStop,
			},
			{
				Name:   "status",
				Usage:  "report whether the gpgsmith daemon is running",
				Action: daemonStatus,
			},
			{
				Name:  "restart",
				Usage: "stop and then start the gpgsmith daemon",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return daemonRestart(ctx, cmd, version, commit)
				},
			},
		},
	}
}

// daemonStart implements `gpgsmith daemon start [--foreground]`. In
// foreground mode it constructs a *daemon.Daemon in-process and blocks
// on Run until signal or error. In background mode (the default) it
// re-execs itself with --foreground and detaches, then polls for socket
// readiness.
func daemonStart(ctx context.Context, cmd *cli.Command, version, commit string) error {
	logger := loggerFrom(ctx)

	if cmd.Bool("foreground") {
		return runForegroundDaemon(ctx, logger, version, commit)
	}

	sockPath, err := daemon.SocketPath()
	if err != nil {
		return fmt.Errorf("daemon start: resolve socket path: %w", err)
	}

	// Already running? systemctl start on an active unit is a no-op
	// success.
	if daemonReachable(ctx, sockPath) {
		fmt.Fprintln(os.Stderr, "daemon already running")
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("daemon start: locate self: %w", err)
	}

	child := exec.CommandContext(context.Background(), exe, "daemon", "start", "--foreground") //nolint:gosec // exe comes from os.Executable, not user input
	child.Stdin = nil
	child.Stdout = nil
	child.Stderr = nil
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := child.Start(); err != nil {
		return fmt.Errorf("daemon start: spawn child: %w", err)
	}

	// Do not Wait: the child is a long-lived daemon. Release the
	// process handle so Go doesn't keep an internal reference.
	if err := child.Process.Release(); err != nil {
		logger.WarnContext(ctx, "daemon start: release child handle",
			slog.String("error", err.Error()),
		)
	}

	if err := waitForDaemon(ctx, sockPath, daemonStartupTimeout); err != nil {
		return fmt.Errorf("daemon start: %w", err)
	}

	fmt.Fprintln(os.Stderr, "daemon started")
	return nil
}

// runForegroundDaemon is the foreground-mode entry point: build a
// *daemon.Daemon and call Run until signal or error.
func runForegroundDaemon(ctx context.Context, logger *slog.Logger, version, commit string) error {
	d := daemon.New(daemon.Options{
		Version: version,
		Commit:  commit,
		Logger:  logger,
	})
	if err := d.Run(ctx); err != nil {
		return fmt.Errorf("daemon run: %w", err)
	}
	return nil
}

// daemonStop implements `gpgsmith daemon stop`. A not-running daemon is
// a silent success (matches systemctl).
func daemonStop(ctx context.Context, cmd *cli.Command) error {
	sockPath, err := daemon.SocketPath()
	if err != nil {
		return fmt.Errorf("daemon stop: resolve socket path: %w", err)
	}

	if !daemonReachable(ctx, sockPath) {
		fmt.Fprintln(os.Stderr, "daemon is not running")
		return nil
	}

	timeout := cmd.Int("timeout")
	if timeout <= 0 {
		timeout = daemonDefaultGraceful
	}

	client := wire.NewUnixSocketClient(sockPath)
	defer client.Close()

	callCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout+5)*time.Second)
	defer cancel()

	_, err = client.Daemon.Shutdown(callCtx, connect.NewRequest(&v1.ShutdownRequest{
		GracefulTimeoutSeconds: int32(timeout),
	}))
	if err != nil {
		// If the daemon drops the connection mid-shutdown that's still
		// a success — it stopped.
		if isConnRefused(err) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "daemon stopped")
			return nil
		}
		return fmt.Errorf("daemon stop: %w", err)
	}

	fmt.Fprintln(os.Stderr, "daemon stopped")
	return nil
}

// daemonStatus implements `gpgsmith daemon status`.
func daemonStatus(ctx context.Context, _ *cli.Command) error {
	sockPath, err := daemon.SocketPath()
	if err != nil {
		return fmt.Errorf("daemon status: resolve socket path: %w", err)
	}

	if !daemonReachable(ctx, sockPath) {
		fmt.Println("daemon: not running")
		return cli.Exit("", exitDaemonNotRunning)
	}

	client := wire.NewUnixSocketClient(sockPath)
	defer client.Close()

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := client.Daemon.Status(callCtx, connect.NewRequest(&v1.StatusRequest{}))
	if err != nil {
		return fmt.Errorf("daemon status: %w", err)
	}

	st := resp.Msg
	started := st.GetStartedAt().AsTime()
	uptime := time.Since(started).Round(time.Second)

	fmt.Println("daemon: running")
	fmt.Printf("  pid:      %d\n", st.GetPid())
	fmt.Printf("  version:  %s\n", st.GetVersion())
	fmt.Printf("  commit:   %s\n", st.GetCommit())
	fmt.Printf("  socket:   %s\n", st.GetSocketPath())
	fmt.Printf("  started:  %s (%s ago)\n", started.UTC().Format(time.RFC3339), uptime)
	fmt.Printf("  sessions: %d\n", st.GetActiveSessions())
	return nil
}

// daemonRestart implements `gpgsmith daemon restart`.
func daemonRestart(ctx context.Context, cmd *cli.Command, version, commit string) error {
	// Best-effort stop; ignore errors because the daemon may already be
	// stopped (which is fine) and any other error will resurface on
	// start if the socket is still held.
	_ = daemonStop(ctx, cmd)

	sockPath, err := daemon.SocketPath()
	if err != nil {
		return fmt.Errorf("daemon restart: resolve socket path: %w", err)
	}

	// Wait for the socket file to disappear (lifecycle.go removes it on
	// clean shutdown).
	deadline := time.Now().Add(daemonStartupTimeout)
	for time.Now().Before(deadline) {
		if _, statErr := os.Stat(sockPath); errors.Is(statErr, os.ErrNotExist) {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("daemon restart: %w", ctx.Err())
		case <-time.After(daemonPollInterval):
		}
	}

	return daemonStart(ctx, cmd, version, commit)
}

// daemonReachable reports whether a gpgsmith daemon is currently
// listening on the given Unix socket path. A successful connect is the
// definition of "running".
func daemonReachable(ctx context.Context, sockPath string) bool {
	if _, err := os.Stat(sockPath); errors.Is(err, os.ErrNotExist) {
		return false
	}
	dialCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", sockPath)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// waitForDaemon polls the socket path until it becomes reachable or
// the timeout expires.
func waitForDaemon(ctx context.Context, sockPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if daemonReachable(ctx, sockPath) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(daemonPollInterval):
		}
	}
	return fmt.Errorf("daemon did not become ready within %s", timeout)
}

// isConnRefused reports whether err is a connection-refused-style
// error, which indicates the daemon closed its socket (expected during
// shutdown) rather than a genuine RPC failure.
func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	// Connect wraps transport errors under its own Error type; pull the
	// code out rather than string-matching.
	var connErr *connect.Error
	if errors.As(err, &connErr) {
		code := connErr.Code()
		if code == connect.CodeUnavailable || code == connect.CodeCanceled {
			return true
		}
	}
	return false
}
