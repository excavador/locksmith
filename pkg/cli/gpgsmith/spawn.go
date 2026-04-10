package gpgsmith

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/excavador/locksmith/pkg/daemon"
)

// EnsureDaemon checks whether a gpgsmith daemon is reachable on its
// canonical socket. If it is, EnsureDaemon returns nil immediately.
// Otherwise it spawns one as a detached child process by exec'ing
// `gpgsmith daemon start --foreground` and waits up to `timeout` for
// the socket to become ready.
//
// Used by CLI commands so that a user-facing command like
// `gpgsmith keys list` transparently spins up the daemon if it isn't
// already running. The user opts out by running `gpgsmith daemon stop`
// and avoiding commands that need the daemon thereafter.
func EnsureDaemon(ctx context.Context, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = daemonStartupTimeout
	}

	sockPath, err := daemon.SocketPath()
	if err != nil {
		return fmt.Errorf("ensure daemon: resolve socket path: %w", err)
	}

	if daemonReachable(ctx, sockPath) {
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("ensure daemon: locate self: %w", err)
	}

	if err := spawnDetachedDaemon(ctx, exe); err != nil {
		return fmt.Errorf("ensure daemon: %w", err)
	}

	if err := waitForDaemon(ctx, sockPath, timeout); err != nil {
		return fmt.Errorf("ensure daemon: %w", err)
	}
	return nil
}

// spawnDetachedDaemon execs the given binary with `daemon start
// --foreground` and detaches from the child. The child survives the
// parent process; Release is called so Go's runtime does not retain
// an internal reference to it.
func spawnDetachedDaemon(ctx context.Context, exe string) error {
	logger := loggerFrom(ctx)

	cmd := exec.CommandContext(context.Background(), exe, "daemon", "start", "--foreground")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn: %w", err)
	}

	if err := cmd.Process.Release(); err != nil {
		logger.WarnContext(ctx, "ensure daemon: release child handle",
			slog.String("error", err.Error()),
		)
	}
	return nil
}
