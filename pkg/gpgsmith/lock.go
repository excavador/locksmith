// Package gpgsmith is the gpgsmith kernel: orchestration, sessions, and the
// types frontends (CLI, web UI, TUI) build on. It sits above the primitive
// packages (pkg/gpg, pkg/vault, pkg/audit) and below the frontend packages
// (pkg/cli/gpgsmith, pkg/webui/gpgsmith, pkg/tui/gpgsmith).
package gpgsmith

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

type (
	// LockSource identifies which gpgsmith frontend holds a vault lock.
	// Used purely for diagnostic output on lock contention.
	LockSource string

	// Lock represents an acquired vault lock. The underlying flock(2) is
	// released either by an explicit Release() call or automatically by the
	// kernel when the holding process exits (any signal, including SIGKILL).
	// Each Lock also writes a sidecar .info file with human-readable
	// diagnostics; the sidecar is removed on Release.
	Lock struct {
		file     *os.File
		lockPath string
		infoPath string
		released bool
	}

	// LockInfo describes the holder of a vault lock. Marshaled to the
	// sidecar .info file alongside the lock so other gpgsmith processes can
	// produce useful contention errors.
	LockInfo struct {
		PID       int        `yaml:"pid"`
		Source    LockSource `yaml:"source"`
		StartedAt time.Time  `yaml:"started_at"`
		Hostname  string     `yaml:"hostname"`
		VaultDir  string     `yaml:"vault_dir"`
	}

	// LockContentionError is returned by AcquireVaultLock when another
	// gpgsmith process already holds the lock. Holder may be nil if the
	// sidecar .info file could not be read.
	LockContentionError struct {
		VaultDir string
		Holder   *LockInfo
	}
)

const (
	// LockSourceCLI marks a lock acquired by the CLI shell session.
	LockSourceCLI LockSource = "cli"
	// LockSourceUI marks a lock acquired by the local web UI.
	LockSourceUI LockSource = "ui"
	// LockSourceTUI marks a lock acquired by the terminal UI (future).
	LockSourceTUI LockSource = "tui"

	// infoSuffix is the filename extension for the sidecar lock info file.
	infoSuffix = ".info"
)

// AcquireVaultLock attempts to take an exclusive non-blocking flock(2) on a
// host-local lock file derived from the absolute path of vaultDir. The lock
// is held by the calling process until Release() is called or the process
// exits.
//
// Different vaults at different paths get distinct lock files (the absolute
// path is hashed into the lock file name). The lock is per-host: vaults
// shared via Dropbox/Syncthing across multiple machines cannot be coordinated
// by this mechanism — that limitation is inherent to file-sync setups.
//
// On contention, returns a *LockContentionError carrying the existing
// holder's diagnostics where possible.
func AcquireVaultLock(vaultDir string, source LockSource) (*Lock, error) {
	abs, err := filepath.Abs(vaultDir)
	if err != nil {
		return nil, fmt.Errorf("vault lock: resolve abs path: %w", err)
	}

	lockPath := lockPathFor(abs)
	infoPath := lockPath + infoSuffix

	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil { //nolint:gosec // path derived from sha256 of abs vault dir
		return nil, fmt.Errorf("vault lock: create dir: %w", err)
	}

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // path derived from sha256 of abs vault dir
	if err != nil {
		return nil, fmt.Errorf("vault lock: open %s: %w", lockPath, err)
	}

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil { //nolint:gosec // fd from os.OpenFile fits in int
		_ = f.Close()
		holder := readLockInfo(infoPath)
		return nil, &LockContentionError{
			VaultDir: abs,
			Holder:   holder,
		}
	}

	hostname, _ := os.Hostname()
	self := LockInfo{
		PID:       os.Getpid(),
		Source:    source,
		StartedAt: time.Now().UTC(),
		Hostname:  hostname,
		VaultDir:  abs,
	}
	if err := writeLockInfo(infoPath, &self); err != nil {
		// Roll back the flock so we don't leave the file locked but with no
		// info sidecar — that would be the worst possible state.
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN) //nolint:gosec // fd from os.OpenFile fits in int
		_ = f.Close()
		return nil, fmt.Errorf("vault lock: write info sidecar: %w", err)
	}

	return &Lock{
		file:     f,
		lockPath: lockPath,
		infoPath: infoPath,
	}, nil
}

// Release unlocks the vault and removes the sidecar info file. Safe to call
// multiple times. After Release, the Lock is unusable.
func (l *Lock) Release() error {
	if l == nil || l.released {
		return nil
	}
	l.released = true

	// Remove the info sidecar first; if the unlock fails we still want the
	// stale info gone so the next acquirer doesn't see misleading data.
	_ = os.Remove(l.infoPath)

	var firstErr error
	if err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN); err != nil { //nolint:gosec // fd from os.OpenFile fits in int
		firstErr = fmt.Errorf("vault lock: flock un: %w", err)
	}
	if err := l.file.Close(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("vault lock: close: %w", err)
	}
	l.file = nil
	return firstErr
}

// Path returns the lock file path. Useful for diagnostics.
func (l *Lock) Path() string {
	if l == nil {
		return ""
	}
	return l.lockPath
}

// Error implements the error interface.
func (e *LockContentionError) Error() string {
	if e.Holder == nil {
		return fmt.Sprintf(
			"vault %q is already locked by another gpgsmith process (sidecar info missing or unreadable)",
			e.VaultDir,
		)
	}
	return fmt.Sprintf(
		"vault %q is already in use by another gpgsmith process\n"+
			"  pid:      %d\n"+
			"  source:   %s\n"+
			"  started:  %s\n"+
			"  host:     %s\n\n"+
			"Wait for the other session to seal/discard, or terminate PID %d.\n"+
			"If you're sure the other process is dead, run: gpgsmith vault unlock <name>",
		e.VaultDir,
		e.Holder.PID,
		e.Holder.Source,
		e.Holder.StartedAt.Format(time.RFC3339),
		e.Holder.Hostname,
		e.Holder.PID,
	)
}

// IsLockContention reports whether err is a LockContentionError.
func IsLockContention(err error) bool {
	var lce *LockContentionError
	return errors.As(err, &lce)
}

// ReadLockInfoFor returns the holder of the vault lock for vaultDir, or nil
// if no holder is recorded. Used by `gpgsmith vault status` to report on the
// current lock holder without acquiring the lock.
//
// Note: a nil return is not proof the vault is unlocked — only that no
// sidecar info is recorded. Always combine with a non-blocking acquire
// attempt if you need a definitive answer.
func ReadLockInfoFor(vaultDir string) (*LockInfo, error) {
	abs, err := filepath.Abs(vaultDir)
	if err != nil {
		return nil, fmt.Errorf("vault lock: resolve abs path: %w", err)
	}
	lockPath := lockPathFor(abs)
	return readLockInfo(lockPath + infoSuffix), nil
}

// ForceUnlockVault removes the lock file and sidecar info for the given
// vault directory unconditionally. Used by `gpgsmith vault unlock` to break
// stuck locks left behind after a process crash. Caller should warn the user
// before invoking this — there is no safety net.
func ForceUnlockVault(vaultDir string) error {
	abs, err := filepath.Abs(vaultDir)
	if err != nil {
		return fmt.Errorf("vault unlock: resolve abs path: %w", err)
	}
	lockPath := lockPathFor(abs)

	infoErr := os.Remove(lockPath + infoSuffix)
	if infoErr != nil && !os.IsNotExist(infoErr) {
		return fmt.Errorf("vault unlock: remove info: %w", infoErr)
	}
	lockErr := os.Remove(lockPath)
	if lockErr != nil && !os.IsNotExist(lockErr) {
		return fmt.Errorf("vault unlock: remove lock file: %w", lockErr)
	}
	return nil
}

// lockPathFor maps an absolute vault directory to its lock file path. The
// vault path is hashed so different vaults at different paths get distinct
// locks even if their basenames collide.
func lockPathFor(absVaultDir string) string {
	const hashBytes = 8 // 8 bytes -> 16 hex chars
	h := sha256.Sum256([]byte(absVaultDir))
	name := hex.EncodeToString(h[:hashBytes]) + ".lock"
	return filepath.Join(lockBaseDir(), name)
}

// lockBaseDir returns the directory where vault lock files live for the
// current host. Linux: $XDG_RUNTIME_DIR/gpgsmith/locks (per-user, cleaned on
// logout). macOS / fallback: $TMPDIR/gpgsmith/locks.
func lockBaseDir() string {
	if runtime.GOOS == "linux" {
		if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
			return filepath.Join(dir, "gpgsmith", "locks")
		}
	}
	return filepath.Join(os.TempDir(), "gpgsmith", "locks")
}

func writeLockInfo(path string, info *LockInfo) error {
	data, err := yaml.Marshal(info)
	if err != nil {
		return fmt.Errorf("marshal lock info: %w", err)
	}
	return os.WriteFile(path, data, 0o600) //nolint:gosec // path derived from sha256 of abs vault dir
}

func readLockInfo(path string) *LockInfo {
	data, err := os.ReadFile(path) //nolint:gosec // path derived from lock file path
	if err != nil {
		return nil
	}
	var info LockInfo
	if err := yaml.Unmarshal(data, &info); err != nil {
		return nil
	}
	return &info
}
