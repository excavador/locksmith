package gpgsmith

import (
	"context"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	"github.com/excavador/locksmith/pkg/daemon"
	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/wire"
)

const (
	// defaultEnsureDaemonTimeout is the grace window we give the daemon
	// to come up when a CLI subcommand auto-spawns it.
	defaultEnsureDaemonTimeout = 5 * time.Second
)

// ensureClient spins up the daemon (if needed) and returns a typed wire
// client connected to its Unix socket. Callers must defer client.Close()
// to release idle transport connections.
func ensureClient(ctx context.Context) (*wire.Client, error) {
	if err := EnsureDaemon(ctx, defaultEnsureDaemonTimeout); err != nil {
		return nil, err
	}
	sockPath, err := daemon.SocketPath()
	if err != nil {
		return nil, fmt.Errorf("resolve socket path: %w", err)
	}
	return wire.NewUnixSocketClient(sockPath), nil
}

// resolveVaultName picks the vault name the command should target. It
// consults the root --vault flag first; if unset and the daemon has
// exactly one open session, it uses that session's vault name.
// Otherwise it returns a helpful error listing the open vaults.
func resolveVaultName(ctx context.Context, client *wire.Client, cmd *cli.Command) (string, error) {
	if name := cmd.Root().String("vault"); name != "" {
		return name, nil
	}
	resp, err := client.Vault.Status(ctx, connect.NewRequest(&v1.StatusVaultRequest{}))
	if err != nil {
		return "", fmt.Errorf("resolve vault: %w", err)
	}
	open := resp.Msg.GetOpen()
	switch len(open) {
	case 0:
		return "", fmt.Errorf("no vaults are open; run `gpgsmith vault open <name>` first")
	case 1:
		return open[0].GetVaultName(), nil
	default:
		names := make([]string, 0, len(open))
		for _, s := range open {
			names = append(names, s.GetVaultName())
		}
		return "", fmt.Errorf("multiple vaults open (%s); pass --vault <name>", strings.Join(names, ", "))
	}
}

// dash returns "-" if s is empty, otherwise s. Used for tabular output
// where an empty value should display as a visible placeholder.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
