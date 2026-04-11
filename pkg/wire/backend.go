// Package wire is the hand-written ConnectRPC layer for the gpgsmith
// daemon: the typed client wrapper used by CLI/UI/TUI frontends, the
// per-service handler implementations the daemon mounts on its HTTP
// server, and the proto↔kernel type conversion that keeps protobuf types
// from leaking out of this package into the rest of the codebase.
//
// The package is named "wire" rather than "rpc" because Go's standard
// library already has "net/rpc" and golangci-lint's revive var-naming
// rule flags the shadowed name.
//
// Layering:
//
//	pkg/gen/gpgsmith/v1                       generated message + service stubs (untouched)
//	pkg/gen/gpgsmith/v1/gpgsmithv1connect     generated client/server interfaces (untouched)
//	pkg/wire                                  THIS PACKAGE — handlers, client, mapping
//	pkg/daemon                                implements wire.Backend with real sessions
//	pkg/cli/gpgsmith                          uses wire.Client to talk to the daemon
//
// The wire package depends on the kernel (pkg/gpgsmith, pkg/vault, pkg/gpg,
// pkg/audit) for the value types it converts to/from proto, but does NOT
// depend on the daemon runtime — that direction would create a cycle. The
// daemon imports wire and provides a Backend implementation; wire never
// reaches into the daemon.
package wire

import (
	"context"
	"time"

	"github.com/excavador/locksmith/pkg/audit"
	"github.com/excavador/locksmith/pkg/gpg"
	"github.com/excavador/locksmith/pkg/gpgsmith"
	"github.com/excavador/locksmith/pkg/vault"
)

type (
	// Backend is the contract that the wire handlers call into. It exposes
	// the gpgsmith kernel surface in a session-aware, daemon-style API:
	// every session-bearing method takes an opaque session token to
	// identify which open Session to operate on. The Backend implementation
	// (typically *daemon.Daemon) is responsible for looking up the Session
	// in its in-memory token-keyed map, returning a useful error if no
	// session exists for the token, and routing the call to the appropriate
	// kernel function.
	//
	// Methods are grouped by the protobuf service they back, in the same
	// order services appear in proto/gpgsmith/v1/.
	//
	// All Backend methods are safe to call from multiple goroutines
	// concurrently. Concurrency control of mutating operations on a single
	// vault is the Backend's responsibility (typically a per-Session mutex).
	Backend interface {
		// ===== DaemonService =====

		DaemonStatus(ctx context.Context) (DaemonStatus, error)
		DaemonShutdown(ctx context.Context, gracefulTimeoutSeconds int) error
		ListSessions(ctx context.Context) ([]SessionInfo, error)
		// ListSessionTokens returns the open sessions together with
		// their opaque tokens. It is only used by local CLI callers
		// to auto-bind GPGSMITH_SESSION when exactly one session is
		// open. The tokens are transported via the
		// Gpgsmith-Session-Tokens response header — we intentionally
		// keep them out of SessionInfo/proto so non-local callers
		// (e.g. the web UI shim) never see them by accident.
		ListSessionTokens(ctx context.Context) ([]SessionTokenEntry, error)

		// ===== VaultService =====
		//
		// OpenVault, ResumeVault and CreateVault each mint a fresh opaque
		// session token alongside their SessionInfo. Frontends bind that
		// token to the Gpgsmith-Session header (typically via env var
		// GPGSMITH_SESSION or a cookie) for subsequent session-bearing
		// RPCs.

		ListVaults(ctx context.Context) (entries []vault.Entry, defaultName string, err error)
		StatusVaults(ctx context.Context) (open []SessionInfo, recoverable []ResumeOption, err error)
		OpenVault(ctx context.Context, name, passphrase string, source gpgsmith.LockSource) (result OpenResult, token string, err error)
		ResumeVault(ctx context.Context, name, passphrase string, source gpgsmith.LockSource, resume bool) (info SessionInfo, token string, err error)
		SealVault(ctx context.Context, token, message string) (vault.Snapshot, error)
		DiscardVault(ctx context.Context, token string) error
		Snapshots(ctx context.Context, name string) ([]vault.Snapshot, error)
		ImportVault(ctx context.Context, sourcePath, passphrase, targetName string) (vault.Snapshot, error)
		CreateVault(ctx context.Context, name, path, passphrase string) (snap vault.Snapshot, session SessionInfo, token string, err error)
		ExportVault(ctx context.Context, name, passphrase, targetDir string) (snapshotName string, err error)
		TrustVault(ctx context.Context, name, fingerprint string) error

		// ===== KeyService =====

		CreateMasterKey(ctx context.Context, token string, opts CreateKeyOpts) (masterFP string, subkeys []gpg.SubKey, err error)
		GenerateSubkeys(ctx context.Context, token string) ([]gpg.SubKey, error)
		ListKeys(ctx context.Context, token string) ([]gpg.SubKey, error)
		RevokeSubkey(ctx context.Context, token, keyID string) error
		ExportKey(ctx context.Context, token string) (target string, err error)
		SSHPubKey(ctx context.Context, token string) (path string, err error)
		KeyStatus(ctx context.Context, token string) (keys []gpg.SubKey, card *gpg.CardInfo, err error)

		// ===== IdentityService =====

		ListIdentities(ctx context.Context, token string) ([]gpg.UID, error)
		AddIdentity(ctx context.Context, token, uid string) error
		RevokeIdentity(ctx context.Context, token, uid string) error
		PrimaryIdentity(ctx context.Context, token, uid string) error

		// ===== CardService =====

		ProvisionCard(ctx context.Context, token string, opts ProvisionCardOpts) (card gpg.YubiKeyEntry, sshPubkeyPath string, err error)
		RotateCard(ctx context.Context, token, label string) (gpg.YubiKeyEntry, error)
		RevokeCard(ctx context.Context, token, label string) error
		CardInventory(ctx context.Context, token string) ([]gpg.YubiKeyEntry, error)
		DiscoverCard(ctx context.Context, token, label, description string) (card gpg.YubiKeyEntry, alreadyKnown bool, err error)

		// ===== ServerService =====

		ListPublishServers(ctx context.Context, token string) ([]gpg.ServerEntry, error)
		AddPublishServer(ctx context.Context, token, alias, url string) error
		RemovePublishServer(ctx context.Context, token, alias string) error
		EnablePublishServer(ctx context.Context, token, alias string) error
		DisablePublishServer(ctx context.Context, token, alias string) error
		Publish(ctx context.Context, token string, aliases []string) ([]PublishResult, error)
		LookupPublished(ctx context.Context, token string) ([]LookupResult, error)

		// ===== AuditService =====

		ShowAudit(ctx context.Context, token string, last int) ([]audit.Entry, error)

		// ===== EventService =====
		//
		// SubscribeEvents returns a channel of events. If token is
		// non-empty and matches an open session, only that vault's events
		// are forwarded; if token is empty, the subscriber receives events
		// for all vaults. The channel is closed when the passed context is
		// canceled. The Backend is responsible for fan-out.
		SubscribeEvents(ctx context.Context, token string) (<-chan Event, error)
	}

	// DaemonStatus is the response shape for DaemonService.Status, in
	// kernel-flavored Go form. The mapping layer translates this to/from
	// the proto type.
	DaemonStatus struct {
		PID            int
		Version        string
		Commit         string
		SocketPath     string
		StartedAt      time.Time
		ActiveSessions int
	}

	// SessionTokenEntry pairs an opaque session token with its vault
	// name. Used only by ListSessionTokens for local CLI auto-binding.
	SessionTokenEntry struct {
		Token     string
		VaultName string
	}

	// SessionInfo describes one currently-open session held by the daemon,
	// in kernel-flavored Go form.
	SessionInfo struct {
		VaultName      string
		VaultPath      string
		Source         gpgsmith.LockSource
		Hostname       string
		StartedAt      time.Time
		LastActiveAt   time.Time
		SourceSnapshot string
		MasterFP       string
		Generation     uint64
		Status         string
	}

	// ResumeOption describes a recoverable .session-<host> ephemeral that
	// the daemon discovered when listing a vault.
	ResumeOption struct {
		CanonicalBase string
		Hostname      string
		Source        gpgsmith.LockSource
		StartedAt     time.Time
		LastHeartbeat time.Time
		Status        string
		Divergent     bool
	}

	// OpenResult is the return value from Backend.OpenVault. Either
	// Session is set (open succeeded with no resume question) or
	// ResumeAvailable is set (caller must call ResumeVault to choose).
	OpenResult struct {
		Session         *SessionInfo
		ResumeAvailable *ResumeOption
	}

	// CreateKeyOpts mirrors the kernel master-key generation parameters.
	CreateKeyOpts struct {
		Name         string
		Email        string
		Algo         string
		Expiry       string
		SubkeyAlgo   string
		SubkeyExpiry string
	}

	// ProvisionCardOpts mirrors the card provisioning parameters.
	ProvisionCardOpts struct {
		Label       string
		Description string
		SameKeys    bool
		UniqueKeys  bool
	}

	// PublishResult is the per-target outcome of a publish operation.
	PublishResult struct {
		Alias   string
		Success bool
		Error   string
	}

	// LookupResult is the per-server outcome of a lookup operation.
	LookupResult struct {
		URL    string
		Status string
	}

	// Event is one item in the daemon's pub/sub stream.
	Event struct {
		At        time.Time
		VaultName string
		JobID     string
		Kind      EventKind
		Message   string
		Data      map[string]string
	}

	// EventKind enumerates the daemon's event types. Mirrors the proto
	// EventKind enum.
	EventKind int
)

// EventKind enumeration values. The order matches the proto EventKind
// enum so the mapping layer is a 1:1 switch.
const (
	EventKindUnspecified  EventKind = iota // zero value; proto field was unset
	EventKindJobStarted                    // a job (key gen, card op, ...) started
	EventKindJobProgress                   // job has progressed; check Message/Data
	EventKindJobPrompt                     // job needs user input ("touch your YubiKey")
	EventKindJobCompleted                  // job finished successfully
	EventKindJobFailed                     // job finished with an error
	EventKindStateChanged                  // a session's state changed (open/seal/discard)
	EventKindSessionEnded                  // a session was ended (any reason)
)
