package gpgsmith

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"

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
//
// The returned client carries the env-var session interceptor, so every
// session-bearing RPC is stamped with the current GPGSMITH_SESSION token
// at request time.
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

// ensureSessionToken makes sure GPGSMITH_SESSION is set in the current
// process before a session-bearing RPC is issued. The outbound
// interceptor reads the env var at request time, so it is sufficient to
// set it here and let the regular command body run afterward.
//
// Resolution order:
//  1. GPGSMITH_SESSION already set — use it verbatim.
//  2. Exactly one session in ListSessions — bind to it automatically
//     via the Gpgsmith-Session-Tokens response header.
//  3. Zero sessions — return a helpful "run vault open" error.
//  4. More than one session — refuse and ask the user to disambiguate.
func ensureSessionToken(ctx context.Context, client *wire.Client) error {
	if tok := os.Getenv(wire.SessionEnvVar); tok != "" {
		return nil
	}
	resp, err := client.Daemon.ListSessions(ctx, connect.NewRequest(&v1.ListSessionsRequest{}))
	if err != nil {
		return fmt.Errorf("resolve session: %w", err)
	}
	tokens := wire.DecodeSessionTokens(resp.Header().Get(wire.SessionTokenListHeader))
	switch len(tokens) {
	case 0:
		return fmt.Errorf("no open sessions; run `gpgsmith vault open <name>` first")
	case 1:
		_ = os.Setenv(wire.SessionEnvVar, tokens[0].Token)
		if tokens[0].VaultName != "" {
			_ = os.Setenv(wire.SessionVaultNameEnvVar, tokens[0].VaultName)
		}
		return nil
	default:
		names := make([]string, 0, len(tokens))
		for _, t := range tokens {
			names = append(names, t.VaultName)
		}
		return fmt.Errorf("multiple open sessions (%s); set GPGSMITH_SESSION to the token you want to target",
			strings.Join(names, ", "))
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
