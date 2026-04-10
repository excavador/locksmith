package daemon

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/excavador/locksmith/pkg/gpgsmith"
	"github.com/excavador/locksmith/pkg/vault"
	"github.com/excavador/locksmith/pkg/wire"
)

const (
	testPassphrase = "daemon-test-pass-please-no"
	testMasterFP   = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// makeDaemonTestVault plants one canonical snapshot in a fresh vault
// dir, writes a vault registry config pointing at it, and returns the
// config path plus the entry name.
func makeDaemonTestVault(t *testing.T, masterFP string) (cfgPath, vaultName string) {
	t.Helper()

	vaultDir := t.TempDir()
	logger := quietLogger()

	vcfg := &vault.Config{VaultDir: vaultDir}
	v, err := vault.NewWithPassphrase(vcfg, testPassphrase, logger)
	if err != nil {
		t.Fatal(err)
	}

	stage := t.TempDir()
	if masterFP != "" {
		yaml := "master_fp: " + masterFP + "\nsubkey_algo: rsa4096\nsubkey_expiry: 2y\n"
		if err := os.WriteFile(filepath.Join(stage, "gpgsmith.yaml"), []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(stage, "marker"), []byte("staged"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := v.Import(context.Background(), stage); err != nil {
		t.Fatal(err)
	}

	cfgPath = filepath.Join(t.TempDir(), "config.yaml")
	cfg := &vault.Config{
		Default: "test",
		Vaults: []vault.Entry{
			{Name: "test", Path: vaultDir},
		},
	}
	if err := vault.SaveConfig(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	return cfgPath, "test"
}

func newTestDaemon(t *testing.T, cfgPath string) *Daemon {
	t.Helper()
	return New(Options{
		Version:         "test",
		Commit:          "abcdef",
		Logger:          quietLogger(),
		IdleTimeout:     5 * time.Minute,
		GracefulTimeout: 2 * time.Second,
		ConfigPath:      cfgPath,
		SocketPath:      "/dev/null/unused",
	})
}

// waitFor polls until pred() is true or the deadline elapses.
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

func TestDaemonConstruction(t *testing.T) {
	d := New(Options{})
	if d == nil {
		t.Fatal("New returned nil")
	}
	if d.idleTimeout != DefaultIdleTimeout {
		t.Errorf("idleTimeout = %v, want %v", d.idleTimeout, DefaultIdleTimeout)
	}
	if d.gracefulTimeout != DefaultGracefulTimeout {
		t.Errorf("gracefulTimeout = %v", d.gracefulTimeout)
	}
	if d.broker == nil {
		t.Error("broker is nil")
	}
}

func TestDaemonStatus(t *testing.T) {
	d := New(Options{Version: "v1.2.3", Commit: "abc", Logger: quietLogger()})
	status, err := d.DaemonStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Version != "v1.2.3" {
		t.Errorf("Version = %q", status.Version)
	}
	if status.ActiveSessions != 0 {
		t.Errorf("ActiveSessions = %d", status.ActiveSessions)
	}
}

func TestDaemonOpenSealCycle(t *testing.T) {
	cfgPath, name := makeDaemonTestVault(t, testMasterFP)
	d := newTestDaemon(t, cfgPath)

	ctx := context.Background()

	res, err := d.OpenVault(ctx, name, testPassphrase, gpgsmith.LockSourceCLI)
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if res.Session == nil {
		t.Fatalf("Session is nil, result = %+v", res)
	}
	if res.Session.VaultName != name {
		t.Errorf("VaultName = %q", res.Session.VaultName)
	}

	sessions, err := d.ListSessions(ctx)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("ListSessions: %v, %d", err, len(sessions))
	}

	snap, err := d.SealVault(ctx, name, "test-seal")
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}
	if snap.Path == "" {
		t.Error("snap path empty")
	}

	sessions, _ = d.ListSessions(ctx)
	if len(sessions) != 0 {
		t.Errorf("sessions after seal = %d, want 0", len(sessions))
	}
}

func TestDaemonResumeAvailable(t *testing.T) {
	cfgPath, name := makeDaemonTestVault(t, testMasterFP)
	d := newTestDaemon(t, cfgPath)

	ctx := context.Background()

	res1, err := d.OpenVault(ctx, name, testPassphrase, gpgsmith.LockSourceCLI)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if res1.Session == nil {
		t.Fatal("first open: expected session")
	}

	// Mutate something so ephemeral flushes.
	d.mu.RLock()
	se := d.sessions[name]
	d.mu.RUnlock()
	se.session.MarkChanged()

	// Auto-seal-and-drop simulates idle timeout.
	if err := se.session.AutoSealAndDrop(ctx); err != nil {
		t.Fatalf("AutoSealAndDrop: %v", err)
	}
	d.mu.Lock()
	delete(d.sessions, name)
	d.mu.Unlock()

	// Wait for the ephemeral file to exist (scrypt KDF is slow).
	cfg, _ := vault.LoadConfig(cfgPath)
	entry, _ := cfg.Resolve(name)
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	found := waitFor(t, 10*time.Second, func() bool {
		eph, _ := gpgsmith.FindEphemeralFor(entry.Path, hostname)
		return eph != nil
	})
	if !found {
		t.Fatal("ephemeral file did not appear")
	}

	// Now OpenVault should return ResumeAvailable.
	res2, err := d.OpenVault(ctx, name, testPassphrase, gpgsmith.LockSourceCLI)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	if res2.ResumeAvailable == nil {
		t.Fatalf("expected ResumeAvailable, got %+v", res2)
	}
	if res2.Session != nil {
		t.Error("expected no Session when resume is available")
	}
}

func TestDaemonSubscribeEvents(t *testing.T) {
	d := New(Options{Logger: quietLogger()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := d.SubscribeEvents(ctx, "foo")
	if err != nil {
		t.Fatalf("SubscribeEvents: %v", err)
	}

	d.publishEvent("foo", wire.EventKindStateChanged, "hello")

	select {
	case evt := <-ch:
		if evt.Message != "hello" {
			t.Errorf("Message = %q", evt.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestDaemonShutdownClosesSubscribers(t *testing.T) {
	d := New(Options{Logger: quietLogger(), GracefulTimeout: time.Second})
	ctx := context.Background()
	ch, err := d.SubscribeEvents(ctx, "foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.DaemonShutdown(ctx, 1); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-ch:
		if ok {
			// First receive might be a valid event, drain once more.
			select {
			case _, ok := <-ch:
				if ok {
					t.Error("channel did not close")
				}
			case <-time.After(time.Second):
				t.Error("channel did not close in time")
			}
		}
	case <-time.After(2 * time.Second):
		t.Error("channel did not close")
	}
}
