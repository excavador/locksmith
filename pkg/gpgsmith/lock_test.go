package gpgsmith

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withIsolatedLockDir points the lock subsystem at a fresh temp dir for the
// duration of the test by overriding $XDG_RUNTIME_DIR and $TMPDIR. Returns
// the temp dir for inspection.
func withIsolatedLockDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("TMPDIR", dir)
	return dir
}

func TestAcquireAndReleaseLock(t *testing.T) {
	withIsolatedLockDir(t)
	vault := t.TempDir()

	lock, err := AcquireVaultLock(vault, LockSourceCLI)
	if err != nil {
		t.Fatalf("AcquireVaultLock: %v", err)
	}
	if lock == nil {
		t.Fatal("AcquireVaultLock returned nil lock")
	}
	if lock.Path() == "" {
		t.Error("Lock.Path() empty")
	}

	// The sidecar info file should exist and contain our PID.
	info, err := ReadLockInfoFor(vault)
	if err != nil {
		t.Fatalf("ReadLockInfoFor: %v", err)
	}
	if info == nil {
		t.Fatal("ReadLockInfoFor returned nil")
	}
	if info.PID != os.Getpid() {
		t.Errorf("info.PID = %d, want %d", info.PID, os.Getpid())
	}
	if info.Source != LockSourceCLI {
		t.Errorf("info.Source = %q, want %q", info.Source, LockSourceCLI)
	}
	if info.StartedAt.IsZero() {
		t.Error("info.StartedAt is zero")
	}

	if err := lock.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// Sidecar info should be gone after release.
	if info := readLockInfo(lock.infoPath); info != nil {
		t.Errorf("info sidecar still present after Release: %+v", info)
	}

	// Double-release is a no-op.
	if err := lock.Release(); err != nil {
		t.Errorf("second Release should be no-op, got: %v", err)
	}
}

func TestLockContention(t *testing.T) {
	withIsolatedLockDir(t)
	vault := t.TempDir()

	first, err := AcquireVaultLock(vault, LockSourceCLI)
	if err != nil {
		t.Fatalf("first AcquireVaultLock: %v", err)
	}
	defer first.Release()

	second, err := AcquireVaultLock(vault, LockSourceUI)
	if err == nil {
		_ = second.Release()
		t.Fatal("second AcquireVaultLock should have failed")
	}

	if !IsLockContention(err) {
		t.Errorf("IsLockContention(%v) = false, want true", err)
	}

	var lce *LockContentionError
	if !errors.As(err, &lce) {
		t.Fatalf("errors.As LockContentionError failed: %v", err)
	}
	if lce.Holder == nil {
		t.Fatal("LockContentionError.Holder should be populated")
	}
	if lce.Holder.PID != os.Getpid() {
		t.Errorf("Holder.PID = %d, want %d", lce.Holder.PID, os.Getpid())
	}
	if lce.Holder.Source != LockSourceCLI {
		t.Errorf("Holder.Source = %q, want %q", lce.Holder.Source, LockSourceCLI)
	}

	// The contention error message should mention the PID for diagnostics.
	if !strings.Contains(lce.Error(), "pid:") {
		t.Errorf("error message missing pid info: %s", lce.Error())
	}
}

func TestReleaseAllowsReacquire(t *testing.T) {
	withIsolatedLockDir(t)
	vault := t.TempDir()

	first, err := AcquireVaultLock(vault, LockSourceCLI)
	if err != nil {
		t.Fatalf("first AcquireVaultLock: %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	second, err := AcquireVaultLock(vault, LockSourceUI)
	if err != nil {
		t.Fatalf("re-acquire after Release: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatalf("Release of re-acquired lock: %v", err)
	}
}

func TestDifferentVaultsAreIndependent(t *testing.T) {
	withIsolatedLockDir(t)
	vaultA := t.TempDir()
	vaultB := t.TempDir()

	a, err := AcquireVaultLock(vaultA, LockSourceCLI)
	if err != nil {
		t.Fatalf("acquire A: %v", err)
	}
	defer a.Release()

	b, err := AcquireVaultLock(vaultB, LockSourceCLI)
	if err != nil {
		t.Fatalf("acquire B (should not contend with A): %v", err)
	}
	defer b.Release()

	if a.Path() == b.Path() {
		t.Errorf("two distinct vaults got the same lock file: %s", a.Path())
	}
}

func TestSamePathDifferentRepresentationsLockSameFile(t *testing.T) {
	withIsolatedLockDir(t)
	vault := t.TempDir()

	a, err := AcquireVaultLock(vault, LockSourceCLI)
	if err != nil {
		t.Fatalf("acquire absolute: %v", err)
	}
	defer a.Release()

	// A relative path that resolves to the same absolute path must contend
	// with the existing lock.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(wd, vault)
	if err != nil {
		t.Fatal(err)
	}

	_, err = AcquireVaultLock(rel, LockSourceCLI)
	if err == nil {
		t.Errorf("relative path %q should contend with %q", rel, vault)
	}
	if !IsLockContention(err) {
		t.Errorf("expected LockContentionError, got: %v", err)
	}
}

func TestForceUnlockVault(t *testing.T) {
	withIsolatedLockDir(t)
	vault := t.TempDir()

	first, err := AcquireVaultLock(vault, LockSourceCLI)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// Force unlock should remove the sidecar even though the original handle
	// is still around (the original holder leaks until process death — but
	// the next acquirer can take over because the .info file is gone).
	if err := ForceUnlockVault(vault); err != nil {
		t.Fatalf("ForceUnlockVault: %v", err)
	}
	if info := readLockInfo(first.infoPath); info != nil {
		t.Errorf("info sidecar still present after ForceUnlock: %+v", info)
	}

	// ForceUnlock on already-clean lock is idempotent.
	if err := ForceUnlockVault(vault); err != nil {
		t.Errorf("second ForceUnlockVault should be no-op, got: %v", err)
	}

	// Original lock is still semantically held until released — release it
	// for cleanliness.
	_ = first.Release()
}

func TestForceUnlockMissingVault(t *testing.T) {
	withIsolatedLockDir(t)
	if err := ForceUnlockVault(t.TempDir()); err != nil {
		t.Errorf("ForceUnlockVault on never-locked vault should succeed, got: %v", err)
	}
}

// TestLockReleasedOnSubprocessExit verifies that the OS releases the flock
// when the holding process exits — without the holder calling Release().
// This is the core correctness guarantee of using flock(2) over a manual PID
// file: even SIGKILL can't leave a stuck lock.
func TestLockReleasedOnSubprocessExit(t *testing.T) {
	if os.Getenv("GPGSMITH_LOCK_HELPER") == "1" {
		// Helper subprocess: acquire the lock, signal readiness, then exit
		// without calling Release() so the kernel cleanup is what frees it.
		vault := os.Getenv("GPGSMITH_LOCK_HELPER_VAULT")
		if vault == "" {
			os.Exit(2)
		}
		_, err := AcquireVaultLock(vault, LockSourceCLI)
		if err != nil {
			os.Exit(3)
		}
		// Touch the readiness sentinel and exit immediately. No Release().
		ready := os.Getenv("GPGSMITH_LOCK_HELPER_READY")
		_ = os.WriteFile(ready, []byte("ok"), 0o600)
		os.Exit(0)
	}

	dir := withIsolatedLockDir(t)
	vault := t.TempDir()
	ready := filepath.Join(dir, "ready")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestLockReleasedOnSubprocessExit$")
	cmd.Env = append(os.Environ(),
		"GPGSMITH_LOCK_HELPER=1",
		"GPGSMITH_LOCK_HELPER_VAULT="+vault,
		"GPGSMITH_LOCK_HELPER_READY="+ready,
		"XDG_RUNTIME_DIR="+dir,
		"TMPDIR="+dir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\noutput: %s", err, out)
	}

	if _, err := os.Stat(ready); err != nil {
		t.Fatalf("subprocess did not signal ready: %v", err)
	}

	// The subprocess has exited. The kernel should have released the flock,
	// even though Release() was never called. We should be able to acquire
	// it from this process now.
	deadline := time.Now().Add(2 * time.Second)
	var lock *Lock
	for {
		lock, err = AcquireVaultLock(vault, LockSourceCLI)
		if err == nil {
			break
		}
		if !IsLockContention(err) {
			t.Fatalf("unexpected acquire error: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("kernel did not release flock from dead subprocess within deadline: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer lock.Release()
}
