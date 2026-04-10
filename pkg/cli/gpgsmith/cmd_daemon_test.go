package gpgsmith

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/excavador/locksmith/pkg/daemon"
)

// withPrivateRuntimeDir points daemon.SocketPath() at a private,
// per-test temp directory by overriding XDG_RUNTIME_DIR (Linux) and
// TMPDIR (macOS / fallback) so parallel tests don't collide on the
// canonical daemon socket path.
func withPrivateRuntimeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("TMPDIR", dir)
	return dir
}

func TestDaemonReachable_NoSocket(t *testing.T) {
	withPrivateRuntimeDir(t)
	sock, err := daemon.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}

	if daemonReachable(context.Background(), sock) {
		t.Errorf("expected daemon unreachable at %s", sock)
	}
}

func TestDaemonReachable_LiveSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "live.sock")

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	if !daemonReachable(context.Background(), sock) {
		t.Errorf("expected daemon reachable at %s", sock)
	}
}

func TestDaemonStatus_NotRunningExitCode(t *testing.T) {
	withPrivateRuntimeDir(t)

	err := daemonStatus(context.Background(), &cli.Command{})
	if err == nil {
		t.Fatal("expected error from daemonStatus when daemon is not running")
	}

	var exitErr cli.ExitCoder
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected cli.ExitCoder, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != exitDaemonNotRunning {
		t.Errorf("expected exit code %d, got %d", exitDaemonNotRunning, exitErr.ExitCode())
	}
}

func TestDaemonStop_NotRunningIsSuccess(t *testing.T) {
	withPrivateRuntimeDir(t)

	cmd := &cli.Command{
		Flags: []cli.Flag{
			&cli.IntFlag{Name: "timeout", Value: daemonDefaultGraceful},
		},
	}
	// Populate flag defaults so cmd.Int("timeout") returns the default.
	if err := cmd.Run(context.Background(), []string{"stop"}); err != nil {
		t.Fatalf("prime cmd: %v", err)
	}

	if err := daemonStop(context.Background(), cmd); err != nil {
		t.Errorf("expected nil error when daemon is not running, got %v", err)
	}
}

func TestWaitForDaemon_TimeoutOnMissingSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "never.sock")

	start := time.Now()
	err := waitForDaemon(context.Background(), sock, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Errorf("returned too fast: %s", elapsed)
	}
}

func TestWaitForDaemon_SucceedsWhenSocketLive(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "live.sock")

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	if err := waitForDaemon(context.Background(), sock, time.Second); err != nil {
		t.Errorf("expected success, got %v", err)
	}
}

func TestDaemonCmd_HasSubcommands(t *testing.T) {
	cmd := daemonCmd("v0.0.0", "abc1234", "2026-04-08")
	want := []string{"start", "stop", "status", "restart"}
	if len(cmd.Commands) != len(want) {
		t.Fatalf("want %d subcommands, got %d", len(want), len(cmd.Commands))
	}
	got := make(map[string]bool, len(cmd.Commands))
	for _, c := range cmd.Commands {
		got[c.Name] = true
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("missing subcommand %q", name)
		}
	}
}

func TestDaemonCmd_StartHasForegroundFlag(t *testing.T) {
	cmd := daemonCmd("v0.0.0", "abc1234", "2026-04-08")
	var start *cli.Command
	for _, c := range cmd.Commands {
		if c.Name == "start" {
			start = c
			break
		}
	}
	if start == nil {
		t.Fatal("no start subcommand")
	}
	found := false
	for _, f := range start.Flags {
		for _, n := range f.Names() {
			if n == "foreground" {
				found = true
			}
		}
	}
	if !found {
		t.Error("start subcommand missing --foreground flag")
	}
}

// ensureRuntimeDirExists is used by tests that stat inside the runtime
// dir; some helpers rely on the directory existing.
func ensureRuntimeDirExists(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "gpgsmith"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
}

func TestDaemonStatus_NotRunningWhenSocketMissing(t *testing.T) {
	dir := withPrivateRuntimeDir(t)
	ensureRuntimeDirExists(t, dir)

	err := daemonStatus(context.Background(), &cli.Command{})
	var exitErr cli.ExitCoder
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitCoder, got %v", err)
	}
	if exitErr.ExitCode() != exitDaemonNotRunning {
		t.Errorf("want exit code %d, got %d", exitDaemonNotRunning, exitErr.ExitCode())
	}
}
