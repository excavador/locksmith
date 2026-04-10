package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

type (
	// AlreadyRunningError is returned by BindSocket when another daemon
	// process is already listening on the requested socket path.
	AlreadyRunningError struct {
		Path string
	}
)

// Error implements the error interface.
func (e *AlreadyRunningError) Error() string {
	return fmt.Sprintf("daemon already running at %s", e.Path)
}

// IsAlreadyRunning reports whether err is an AlreadyRunningError.
func IsAlreadyRunning(err error) bool {
	var a *AlreadyRunningError
	return errors.As(err, &a)
}

// SocketPath returns the canonical Unix socket path for the gpgsmith
// daemon. On Linux it lives under XDG_RUNTIME_DIR (which is per-user and
// cleaned up on logout); on macOS it lives under TMPDIR. The parent
// directory is created with mode 0700 if it does not exist.
func SocketPath() (string, error) {
	var base string
	switch runtime.GOOS {
	case "linux":
		base = os.Getenv("XDG_RUNTIME_DIR")
		if base == "" {
			// Last-resort fallback so the daemon still has somewhere to
			// bind on hosts without XDG_RUNTIME_DIR set.
			base = os.TempDir()
		}
	default:
		base = os.Getenv("TMPDIR")
		if base == "" {
			base = os.TempDir()
		}
	}

	dir := filepath.Join(base, "gpgsmith")
	if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // dir derived from XDG_RUNTIME_DIR / TMPDIR, both user-private
		return "", fmt.Errorf("socket path: create dir: %w", err)
	}
	return filepath.Join(dir, "gpgsmith.sock"), nil
}

// BindSocket binds a Unix domain socket listener at the given path,
// recovering from a stale socket file left behind by a crashed daemon.
//
// The standard idiom: try Listen; on EADDRINUSE try Dial; if Dial
// succeeds another daemon is alive (return AlreadyRunningError); if Dial
// fails with ECONNREFUSED the file is stale, remove it and retry the
// bind. The returned listener has its socket file at mode 0600.
func BindSocket(path string) (net.Listener, error) {
	ctx := context.Background()
	var lc net.ListenConfig
	var d net.Dialer

	ln, err := lc.Listen(ctx, "unix", path)
	if err == nil {
		if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("bind socket: chmod %s: %w", path, chmodErr)
		}
		return ln, nil
	}

	if !errors.Is(err, syscall.EADDRINUSE) {
		return nil, fmt.Errorf("bind socket: %w", err)
	}

	// EADDRINUSE: probe whether the existing socket is alive.
	conn, dialErr := d.DialContext(ctx, "unix", path)
	if dialErr == nil {
		_ = conn.Close()
		return nil, &AlreadyRunningError{Path: path}
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, syscall.ENOENT) {
		// Unexpected dial error: surface it instead of silently removing the file.
		return nil, fmt.Errorf("bind socket: probe stale: %w", dialErr)
	}

	// Stale socket: remove and retry once.
	if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
		return nil, fmt.Errorf("bind socket: remove stale %s: %w", path, rmErr)
	}

	ln, err = lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("bind socket: retry: %w", err)
	}
	if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("bind socket: chmod %s: %w", path, chmodErr)
	}
	return ln, nil
}
