package gpgsmith

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/excavador/locksmith/pkg/wire"
)

type (
	// sessionRC holds the temporary rc file/dir paths and extra env for
	// a shell-specific prompt override. newSessionRC returns a struct
	// whose cleanup() must be called when the subshell exits.
	sessionRC struct {
		args    []string // extra shell args (e.g. bash --rcfile)
		envs    []string // extra env vars (e.g. zsh ZDOTDIR)
		cleanup func()
	}
)

// runWrappedSubshell spawns the user's preferred shell with
// GPGSMITH_SESSION and GPGSMITH_VAULT_NAME set in its environment and a
// gpgsmith-flavored PS1. Blocks until the child exits. The child's exit
// code is propagated via *exec.ExitError — callers should return the
// error as-is so urfave/cli surfaces it.
func runWrappedSubshell(ctx context.Context, vaultName, token string) error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	fmt.Fprintf(os.Stderr, "Entering gpgsmith shell for %q. Exit to leave.\n", vaultName)

	rc := newSessionRC(shell, vaultName)
	defer rc.cleanup()

	shellCmd := exec.CommandContext(ctx, shell, rc.args...) //nolint:gosec // shell comes from user's own env
	shellCmd.Stdin = os.Stdin
	shellCmd.Stdout = os.Stdout
	shellCmd.Stderr = os.Stderr
	sessionEnv := []string{
		wire.SessionEnvVar + "=" + token,
		wire.SessionVaultNameEnvVar + "=" + vaultName,
	}
	shellCmd.Env = append(os.Environ(), append(sessionEnv, rc.envs...)...)

	if err := shellCmd.Run(); err != nil {
		logger := loggerFrom(ctx)
		logger.DebugContext(ctx, "subshell exited with error",
			slog.String("error", err.Error()),
		)
		// Preserve the child exit code when possible so scripts that
		// wrap `gpgsmith vault open` see a meaningful status.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr
		}
		return err
	}
	return nil
}

// newSessionRC builds shell-specific configuration to prepend a
// gpgsmith marker to the user's prompt after their own rc file has
// loaded. Supported shells: bash, zsh. Anything else falls through to
// the raw shell with no prompt override.
func newSessionRC(shell, vaultName string) *sessionRC {
	base := filepath.Base(shell)
	switch base {
	case "bash":
		return bashSessionRC(vaultName)
	case "zsh":
		return zshSessionRC(vaultName)
	default:
		return &sessionRC{cleanup: func() {}}
	}
}

func bashSessionRC(vaultName string) *sessionRC {
	content := fmt.Sprintf(
		"if [ -f ~/.bashrc ]; then . ~/.bashrc; fi\nPS1=\"[gpgsmith:%s] $PS1\"\n",
		vaultName,
	)
	f, err := os.CreateTemp("", "gpgsmith-rc-*")
	if err != nil {
		return &sessionRC{cleanup: func() {}}
	}
	_, writeErr := f.WriteString(content)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(f.Name()) //nolint:gosec // freshly-created temp file
		return &sessionRC{cleanup: func() {}}
	}
	name := f.Name()
	return &sessionRC{
		args:    []string{"--rcfile", name},
		cleanup: func() { _ = os.Remove(name) },
	}
}

func zshSessionRC(vaultName string) *sessionRC {
	home := os.Getenv("HOME")
	dir, err := os.MkdirTemp("", "gpgsmith-zdotdir-*")
	if err != nil {
		return &sessionRC{cleanup: func() {}}
	}
	escapedHome := shellEscapeSingleQuote(home)
	content := fmt.Sprintf(
		"if [ -f '%s/.zshrc' ]; then . '%s/.zshrc'; fi\nPS1=\"[gpgsmith:%s] $PS1\"\n",
		escapedHome, escapedHome, vaultName,
	)
	if err := os.WriteFile(filepath.Join(dir, ".zshrc"), []byte(content), 0o600); err != nil { //nolint:gosec // dir is our own temp dir
		_ = os.RemoveAll(dir)
		return &sessionRC{cleanup: func() {}}
	}
	return &sessionRC{
		envs:    []string{"ZDOTDIR=" + dir},
		cleanup: func() { _ = os.RemoveAll(dir) },
	}
}

// shellEscapeSingleQuote escapes a string for safe use inside single
// quotes in POSIX-ish shells. Used when we need to embed a path or
// value into a generated rc file without worrying about quote
// injection.
func shellEscapeSingleQuote(s string) string {
	return strings.ReplaceAll(s, "'", `'\''`)
}
