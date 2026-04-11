package gpgsmith

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/excavador/locksmith/pkg/daemon"
	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/vault"
	"github.com/excavador/locksmith/pkg/wire"
)

const (
	e2eTestPassphrase = "e2e-cli-passphrase-please-do-not-reuse"
)

// startE2EDaemon launches an in-process daemon with a custom socket and
// config path, waits for it to become reachable, and returns a cleanup
// func the caller must defer.
func startE2EDaemon(t *testing.T, cfgPath string) (sockPath string, cleanup func()) {
	t.Helper()

	tmp := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", tmp)
	t.Setenv("TMPDIR", tmp)
	sockPath = filepath.Join(tmp, "gpgsmith.sock")

	d := daemon.New(daemon.Options{
		Version:         "e2e",
		Commit:          "test",
		Logger:          slog.New(slog.DiscardHandler),
		GracefulTimeout: time.Second,
		SocketPath:      sockPath,
		ConfigPath:      cfgPath,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	// Poll the socket until it answers.
	ok := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c := wire.NewUnixSocketClient(sockPath)
		_, err := c.Daemon.Status(context.Background(), connect.NewRequest(&v1.StatusRequest{}))
		c.Close()
		if err == nil {
			ok = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ok {
		cancel()
		t.Fatal("daemon never became reachable")
	}

	cleanup = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("daemon Run did not return after cancel")
		}
	}
	return sockPath, cleanup
}

// writeE2EConfig writes a vault registry config file with the supplied
// vault entries and returns the path.
func writeE2EConfig(t *testing.T, entries []vault.Entry) string {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &vault.Config{Vaults: entries}
	if len(entries) > 0 {
		cfg.Default = entries[0].Name
	}
	if err := vault.SaveConfig(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// plantVault seeds a fresh vault directory with one empty snapshot, so
// that OpenVault on it succeeds.
func plantVault(t *testing.T, dir string) {
	t.Helper()
	vcfg := &vault.Config{VaultDir: dir}
	v, err := vault.NewWithPassphrase(vcfg, e2eTestPassphrase, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	if _, err := v.Import(context.Background(), stage); err != nil {
		t.Fatalf("plant vault: %v", err)
	}
}

func TestE2EVaultList(t *testing.T) {
	vdir := t.TempDir()
	plantVault(t, vdir)
	cfgPath := writeE2EConfig(t, []vault.Entry{
		{Name: "work", Path: vdir},
	})

	sockPath, cleanup := startE2EDaemon(t, cfgPath)
	defer cleanup()

	client := wire.NewUnixSocketClient(sockPath)
	defer client.Close()

	resp, err := client.Vault.List(context.Background(), connect.NewRequest(&v1.ListRequest{}))
	if err != nil {
		t.Fatalf("Vault.List: %v", err)
	}
	vs := resp.Msg.GetVaults()
	if len(vs) != 1 {
		t.Fatalf("got %d vaults, want 1", len(vs))
	}
	if vs[0].GetName() != "work" {
		t.Errorf("name = %q, want %q", vs[0].GetName(), "work")
	}
	if resp.Msg.GetDefaultVault() != "work" {
		t.Errorf("default = %q, want %q", resp.Msg.GetDefaultVault(), "work")
	}
}

func TestE2EVaultStatusNoOpen(t *testing.T) {
	vdir := t.TempDir()
	plantVault(t, vdir)
	cfgPath := writeE2EConfig(t, []vault.Entry{
		{Name: "work", Path: vdir},
	})

	sockPath, cleanup := startE2EDaemon(t, cfgPath)
	defer cleanup()

	client := wire.NewUnixSocketClient(sockPath)
	defer client.Close()

	resp, err := client.Vault.Status(context.Background(), connect.NewRequest(&v1.StatusVaultRequest{}))
	if err != nil {
		t.Fatalf("Vault.Status: %v", err)
	}
	if len(resp.Msg.GetOpen()) != 0 {
		t.Errorf("expected no open vaults, got %d", len(resp.Msg.GetOpen()))
	}
}

func TestE2EVaultOpenSealRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("scrypt-heavy")
	}
	vdir := t.TempDir()
	plantVault(t, vdir)
	cfgPath := writeE2EConfig(t, []vault.Entry{
		{Name: "work", Path: vdir},
	})

	sockPath, cleanup := startE2EDaemon(t, cfgPath)
	defer cleanup()

	client := wire.NewUnixSocketClient(sockPath)
	defer client.Close()

	ctx, ctxCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer ctxCancel()

	if _, err := client.Vault.Open(ctx, connect.NewRequest(&v1.OpenRequest{
		VaultName:  "work",
		Passphrase: e2eTestPassphrase,
		Source:     v1.LockSource_LOCK_SOURCE_CLI,
	})); err != nil {
		t.Fatalf("Vault.Open: %v", err)
	}

	// Status should now report one open vault.
	statusResp, err := client.Vault.Status(ctx, connect.NewRequest(&v1.StatusVaultRequest{}))
	if err != nil {
		t.Fatalf("Vault.Status: %v", err)
	}
	if len(statusResp.Msg.GetOpen()) != 1 {
		t.Fatalf("open count = %d, want 1", len(statusResp.Msg.GetOpen()))
	}

	// Seal should close it.
	if _, err := client.Vault.Seal(ctx, connect.NewRequest(&v1.SealRequest{
		VaultName: "work",
		Message:   "e2e-roundtrip",
	})); err != nil {
		t.Fatalf("Vault.Seal: %v", err)
	}

	statusResp2, err := client.Vault.Status(ctx, connect.NewRequest(&v1.StatusVaultRequest{}))
	if err != nil {
		t.Fatalf("Vault.Status #2: %v", err)
	}
	if len(statusResp2.Msg.GetOpen()) != 0 {
		t.Errorf("open after seal = %d, want 0", len(statusResp2.Msg.GetOpen()))
	}
}

func TestE2EVaultCreateRPC(t *testing.T) {
	if testing.Short() {
		t.Skip("scrypt-heavy")
	}
	cfgPath := writeE2EConfig(t, nil)
	sockPath, cleanup := startE2EDaemon(t, cfgPath)
	defer cleanup()

	client := wire.NewUnixSocketClient(sockPath)
	defer client.Close()

	ctx, ctxCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer ctxCancel()

	newDir := filepath.Join(t.TempDir(), "newvault")

	resp, err := client.Vault.Create(ctx, connect.NewRequest(&v1.CreateVaultRequest{
		Name:       "fresh",
		Path:       newDir,
		Passphrase: e2eTestPassphrase,
	}))
	if err != nil {
		t.Fatalf("Vault.Create: %v", err)
	}
	if resp.Msg.GetSnapshot() == nil {
		t.Fatal("Create returned nil snapshot")
	}
	if resp.Msg.GetSession() == nil || resp.Msg.GetSession().GetVaultName() != "fresh" {
		t.Errorf("Create session vault_name = %q, want %q", resp.Msg.GetSession().GetVaultName(), "fresh")
	}

	// List should now include the new vault.
	listResp, err := client.Vault.List(ctx, connect.NewRequest(&v1.ListRequest{}))
	if err != nil {
		t.Fatalf("Vault.List: %v", err)
	}
	found := false
	for _, v := range listResp.Msg.GetVaults() {
		if v.GetName() == "fresh" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("fresh vault not found in list after Create")
	}
}
