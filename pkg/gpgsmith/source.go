// Package gpgsmith is the gpgsmith kernel: orchestration, sessions, and the
// types frontends (CLI, web UI, TUI) build on. It sits above the primitive
// packages (pkg/gpg, pkg/vault, pkg/audit) and below the frontend packages
// (pkg/cli/gpgsmith, pkg/webui/gpgsmith, pkg/tui/gpgsmith).
package gpgsmith

type (
	// LockSource identifies which gpgsmith frontend is driving an open
	// session. Before the daemon refactor this identifier tagged a flock
	// acquisition; in the daemon era it is recorded in the encrypted
	// ephemeral .info sidecar for diagnostic purposes only.
	LockSource string
)

const (
	// LockSourceCLI marks a session opened by the CLI frontend.
	LockSourceCLI LockSource = "cli"
	// LockSourceUI marks a session opened by the local web UI.
	LockSourceUI LockSource = "ui"
	// LockSourceTUI marks a session opened by the terminal UI (future).
	LockSourceTUI LockSource = "tui"
)
