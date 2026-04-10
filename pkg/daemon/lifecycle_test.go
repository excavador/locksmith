package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/wire"
)

func TestDaemonRunStatusShutdown(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", tmp)
	t.Setenv("TMPDIR", tmp)

	socketPath := filepath.Join(tmp, "gpgsmith.sock")

	d := New(Options{
		Version:         "v-lifecycle",
		Commit:          "xyz",
		Logger:          quietLogger(),
		GracefulTimeout: time.Second,
		SocketPath:      socketPath,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- d.Run(ctx)
	}()

	// Wait for the socket to appear.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		client := wire.NewUnixSocketClient(socketPath)
		resp, err := client.Daemon.Status(ctx, connect.NewRequest(&v1.StatusRequest{}))
		client.Close()
		if err == nil {
			if resp.Msg.Version != "v-lifecycle" {
				t.Errorf("Version = %q", resp.Msg.Version)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if time.Now().After(deadline) {
		t.Fatal("daemon never became reachable")
	}

	// Trigger graceful shutdown via DaemonShutdown RPC.
	client := wire.NewUnixSocketClient(socketPath)
	defer client.Close()
	_, err := client.Daemon.Shutdown(ctx, connect.NewRequest(&v1.ShutdownRequest{
		GracefulTimeoutSeconds: 1,
	}))
	if err != nil {
		t.Fatalf("Shutdown RPC: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after shutdown")
	}
}
