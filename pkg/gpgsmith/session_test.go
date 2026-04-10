package gpgsmith

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/excavador/locksmith/pkg/vault"
)

const (
	// testPassphrase is the passphrase used by all tests in this file. It is
	// arbitrary and only ever encrypts ephemeral test data.
	testPassphrase = "session-test-pass-please-no"

	// fakeMasterFP is a syntactically valid 40-hex-char fingerprint we plant
	// inside test gpgsmith.yaml files. It does not correspond to any real
	// GPG key — TOFU operates on the string value, not on key validity.
	fakeMasterFP = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
	otherFakeFP  = "FACEFEEDFACEFEEDFACEFEEDFACEFEEDFACEFEED"
)

// quietLogger returns a logger that throws everything away. Tests don't need
// to see info logs from the kernel.
func quietLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// makeTestVault creates a fresh vault directory, populates it with one
// canonical snapshot containing a fake gpgsmith.yaml with the given
// master_fp (or no gpgsmith.yaml if masterFP is empty), and returns the
// vault, the registry entry, and a cleanup function.
//
// The "fake gpgsmith.yaml" sidesteps the need for a real GPG key in tests:
// the kernel's TOFU layer reads master_fp from this file as a string, so a
// hand-crafted YAML works.
func makeTestVault(t *testing.T, masterFP string) (*vault.Vault, *vault.Entry, func()) {
	t.Helper()

	vaultDir := t.TempDir()
	logger := quietLogger()

	cfg := &vault.Config{VaultDir: vaultDir}
	v, err := vault.NewWithPassphrase(cfg, testPassphrase, logger)
	if err != nil {
		t.Fatalf("NewWithPassphrase: %v", err)
	}

	// Stage a fake "GNUPGHOME" with just enough content to be sealable.
	stage := t.TempDir()
	if masterFP != "" {
		yaml := "master_fp: " + masterFP + "\n" +
			"subkey_algo: rsa4096\n" +
			"subkey_expiry: 2y\n"
		if err := os.WriteFile(filepath.Join(stage, "gpgsmith.yaml"), []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Always include at least one file so tar isn't empty.
	if err := os.WriteFile(filepath.Join(stage, "marker"), []byte("staged"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := v.Import(context.Background(), stage); err != nil {
		t.Fatalf("Import: %v", err)
	}

	entry := &vault.Entry{
		Name: "test-vault",
		Path: vaultDir,
	}

	cleanup := func() {
		// t.TempDir() handles dir removal; nothing else to do.
	}

	return v, entry, cleanup
}

func TestOpenSessionAndDiscard(t *testing.T) {
	withIsolatedLockDir(t)
	v, entry, cleanup := makeTestVault(t, fakeMasterFP)
	defer cleanup()

	res, err := OpenSession(context.Background(), v, entry, SessionOpts{
		Source: LockSourceCLI,
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if res.Session == nil {
		t.Fatal("Session is nil")
	}

	s := res.Session

	// TOFU first-use should populate the side channel.
	if res.TOFUFingerprint != fakeMasterFP {
		t.Errorf("TOFUFingerprint = %q, want %q", res.TOFUFingerprint, fakeMasterFP)
	}
	if s.ConfiguredMasterFP != fakeMasterFP {
		t.Errorf("ConfiguredMasterFP = %q, want %q", s.ConfiguredMasterFP, fakeMasterFP)
	}

	// Workdir must exist and contain the staged content.
	if _, err := os.Stat(filepath.Join(s.Workdir, "marker")); err != nil {
		t.Errorf("workdir missing staged marker: %v", err)
	}

	// .info sidecar must exist with our hostname and active status.
	infos, err := ListEphemerals(entry.Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 ephemeral, got %d", len(infos))
	}
	if infos[0].Info.Hostname != s.Hostname {
		t.Errorf("ephemeral hostname = %q, want %q", infos[0].Info.Hostname, s.Hostname)
	}
	if infos[0].Info.Status != EphemeralStatusActive {
		t.Errorf("ephemeral status = %q, want %q", infos[0].Info.Status, EphemeralStatusActive)
	}

	// Discard cleans up the workdir AND the ephemeral files.
	if err := s.Discard(context.Background()); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if !s.IsClosed() {
		t.Error("session should be closed after Discard")
	}
	if _, err := os.Stat(s.Workdir); !os.IsNotExist(err) {
		t.Errorf("workdir should be removed after Discard")
	}
	infos, _ = ListEphemerals(entry.Path)
	if len(infos) != 0 {
		t.Errorf("ephemeral files should be removed after Discard, got %d", len(infos))
	}
}

func TestOpenSessionAndSeal(t *testing.T) {
	withIsolatedLockDir(t)
	v, entry, _ := makeTestVault(t, fakeMasterFP)

	res, err := OpenSession(context.Background(), v, entry, SessionOpts{
		Source: LockSourceCLI,
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	s := res.Session

	// Count canonicals before seal.
	beforeSnaps, _ := v.List(context.Background())

	snap, err := s.Seal(context.Background(), "test-seal")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if snap == nil {
		t.Fatal("Seal returned nil snapshot")
	}
	if !s.IsClosed() {
		t.Error("session should be closed after Seal")
	}

	// A new canonical snapshot should now exist.
	afterSnaps, _ := v.List(context.Background())
	if len(afterSnaps) != len(beforeSnaps)+1 {
		t.Errorf("snapshot count = %d, want %d", len(afterSnaps), len(beforeSnaps)+1)
	}

	// Ephemeral files should be gone.
	infos, _ := ListEphemerals(entry.Path)
	if len(infos) != 0 {
		t.Errorf("ephemeral files should be removed after Seal, got %d", len(infos))
	}
}

func TestOpenSessionTOFUMatch(t *testing.T) {
	withIsolatedLockDir(t)
	v, entry, _ := makeTestVault(t, fakeMasterFP)

	// Pre-populate the trust anchor as if a previous session had run TOFU.
	entry.TrustedMasterFP = fakeMasterFP

	res, err := OpenSession(context.Background(), v, entry, SessionOpts{
		Source: LockSourceCLI,
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatalf("OpenSession (matching trust): %v", err)
	}
	defer func() { _ = res.Session.Discard(context.Background()) }()

	// TOFUFingerprint should be EMPTY because no first-use happened.
	if res.TOFUFingerprint != "" {
		t.Errorf("TOFUFingerprint = %q, want empty (no TOFU on already-trusted vault)", res.TOFUFingerprint)
	}
}

func TestOpenSessionTOFUMismatch(t *testing.T) {
	withIsolatedLockDir(t)
	v, entry, _ := makeTestVault(t, fakeMasterFP)

	// Pre-populate trust anchor with a DIFFERENT fingerprint.
	entry.TrustedMasterFP = otherFakeFP

	_, err := OpenSession(context.Background(), v, entry, SessionOpts{
		Source: LockSourceCLI,
		Logger: quietLogger(),
	})
	if err == nil {
		t.Fatal("OpenSession should have failed on master key mismatch")
	}
	if !IsMasterKeyMismatch(err) {
		t.Fatalf("expected MasterKeyMismatchError, got: %v", err)
	}

	var mismatchErr *MasterKeyMismatchError
	if !errors.As(err, &mismatchErr) {
		t.Fatalf("errors.As failed: %v", err)
	}
	if mismatchErr.Expected != otherFakeFP {
		t.Errorf("Expected = %q", mismatchErr.Expected)
	}
	if mismatchErr.Found != fakeMasterFP {
		t.Errorf("Found = %q", mismatchErr.Found)
	}

	// On error, no ephemeral files should have been left behind.
	infos, _ := ListEphemerals(entry.Path)
	if len(infos) != 0 {
		t.Errorf("ephemeral files should not exist after failed open, got %d", len(infos))
	}
}

func TestOpenSessionNoMasterFPSkipsTOFU(t *testing.T) {
	withIsolatedLockDir(t)
	// Empty masterFP → no gpgsmith.yaml in the staged content → fresh vault
	// with no key generated yet. TOFU should be skipped.
	v, entry, _ := makeTestVault(t, "")

	res, err := OpenSession(context.Background(), v, entry, SessionOpts{
		Source: LockSourceCLI,
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatalf("OpenSession on key-less vault: %v", err)
	}
	defer func() { _ = res.Session.Discard(context.Background()) }()

	if res.TOFUFingerprint != "" {
		t.Errorf("TOFUFingerprint = %q, want empty (no key generated yet)", res.TOFUFingerprint)
	}
	if res.Session.ConfiguredMasterFP != "" {
		t.Errorf("ConfiguredMasterFP = %q, want empty", res.Session.ConfiguredMasterFP)
	}
}

func TestSessionDoubleEndIsError(t *testing.T) {
	withIsolatedLockDir(t)
	v, entry, _ := makeTestVault(t, fakeMasterFP)

	res, err := OpenSession(context.Background(), v, entry, SessionOpts{
		Source: LockSourceCLI,
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := res.Session

	if err := s.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Second Discard must fail cleanly.
	if err := s.Discard(context.Background()); err == nil {
		t.Error("second Discard should error")
	}
	// Seal after Discard must also fail.
	if _, err := s.Seal(context.Background(), "msg"); err == nil {
		t.Error("Seal after Discard should error")
	}
}

func TestSessionMarkChanged(t *testing.T) {
	withIsolatedLockDir(t)
	v, entry, _ := makeTestVault(t, fakeMasterFP)

	res, err := OpenSession(context.Background(), v, entry, SessionOpts{
		Source: LockSourceCLI,
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Session.Discard(context.Background()) }()
	s := res.Session

	if g := s.Generation(); g != 0 {
		t.Errorf("initial Generation = %d, want 0", g)
	}
	s.MarkChanged()
	s.MarkChanged()
	if g := s.Generation(); g != 2 {
		t.Errorf("Generation after 2 marks = %d, want 2", g)
	}
}

// waitFor polls the predicate every 50ms until it returns true or the
// deadline expires. Used to wait for asynchronous heartbeat goroutines to
// flush state without flaky fixed sleeps. The generous default deadline
// covers age's scrypt KDF which takes around a second per encrypt and is
// the slow step in any ephemeral flush.
func waitFor(t *testing.T, deadline time.Duration, pred func() bool) bool {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if pred() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return pred()
}

func TestSessionHeartbeatUpdatesInfo(t *testing.T) {
	withIsolatedLockDir(t)
	v, entry, _ := makeTestVault(t, fakeMasterFP)

	res, err := OpenSession(context.Background(), v, entry, SessionOpts{
		Source:            LockSourceCLI,
		Logger:            quietLogger(),
		HeartbeatInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Session.Discard(context.Background()) }()

	infos, _ := ListEphemerals(entry.Path)
	if len(infos) != 1 {
		t.Fatalf("expected 1 ephemeral, got %d", len(infos))
	}
	initial := infos[0].Info.LastHeartbeat

	// Poll for the heartbeat to advance. With age's scrypt KDF the per-tick
	// cost is dominated by the encrypt step, but a no-mutation tick only
	// rewrites the .info sidecar (cheap), so the heartbeat should advance
	// well within the deadline.
	advanced := waitFor(t, 5*time.Second, func() bool {
		latest, _ := ListEphemerals(entry.Path)
		return len(latest) == 1 && latest[0].Info.LastHeartbeat.After(initial)
	})
	if !advanced {
		t.Errorf("heartbeat did not advance within deadline")
	}
}

func TestSessionHeartbeatFlushesOnGenerationChange(t *testing.T) {
	withIsolatedLockDir(t)
	v, entry, _ := makeTestVault(t, fakeMasterFP)

	res, err := OpenSession(context.Background(), v, entry, SessionOpts{
		Source:            LockSourceCLI,
		Logger:            quietLogger(),
		HeartbeatInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Session.Discard(context.Background()) }()
	s := res.Session

	if _, err := os.Stat(s.ephemeralStatePath); !os.IsNotExist(err) {
		t.Errorf(".session-<host> file should not exist before any mutation")
	}

	s.MarkChanged()

	// Poll for the .session-<host> file to appear. The generous deadline
	// accommodates age's scrypt KDF, which dominates the encrypt step
	// (~1s on typical hardware).
	flushed := waitFor(t, 5*time.Second, func() bool {
		_, err := os.Stat(s.ephemeralStatePath)
		return err == nil
	})
	if !flushed {
		t.Errorf(".session-<host> file did not appear within deadline")
	}
}

func TestAutoSealAndDrop(t *testing.T) {
	withIsolatedLockDir(t)
	v, entry, _ := makeTestVault(t, fakeMasterFP)

	res, err := OpenSession(context.Background(), v, entry, SessionOpts{
		Source: LockSourceCLI,
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := res.Session

	if err := s.AutoSealAndDrop(context.Background()); err != nil {
		t.Fatalf("AutoSealAndDrop: %v", err)
	}
	if !s.IsClosed() {
		t.Error("session should be closed after AutoSealAndDrop")
	}

	// Workdir gone.
	if _, err := os.Stat(s.Workdir); !os.IsNotExist(err) {
		t.Errorf("workdir should be removed after AutoSealAndDrop")
	}

	// Ephemeral files should STILL exist (they're the resume material).
	infos, _ := ListEphemerals(entry.Path)
	if len(infos) != 1 {
		t.Fatalf("expected 1 ephemeral after AutoSealAndDrop, got %d", len(infos))
	}
	if infos[0].Info.Status != EphemeralStatusIdleSealed {
		t.Errorf("ephemeral status = %q, want %q",
			infos[0].Info.Status, EphemeralStatusIdleSealed)
	}
	if infos[0].SessionPath == "" {
		t.Error(".session-<host> state file should exist after AutoSealAndDrop")
	}
}
