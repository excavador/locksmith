// Package daemon implements the long-running gpgsmith daemon process.
//
// The daemon holds open vaults in memory across many client RPCs, runs
// the per-session heartbeat goroutines that keep encrypted ephemeral
// state files fresh on disk, and serves the wire ConnectRPC API on a
// Unix domain socket. CLI / TUI / web-UI frontends are thin clients of
// this daemon: they speak Connect over the socket and never touch GPG
// or the vault directly.
//
// Layering:
//
//	pkg/gpgsmith            kernel: Session, ephemeral, hardening
//	pkg/vault, pkg/gpg, pkg/audit
//	  ^
//	pkg/wire                hand-written ConnectRPC handlers + Backend interface
//	  ^
//	pkg/daemon              THIS PACKAGE — Backend implementation + lifecycle
//
// The daemon implements wire.Backend; every method on the interface is
// routed to either kernel session-bearing operations (open / mutate /
// seal) or one of the per-vault GPG / audit / publish helpers, with the
// session map providing the bridge between a vault name and the
// in-memory *gpgsmith.Session.
package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/excavador/locksmith/pkg/audit"
	"github.com/excavador/locksmith/pkg/gpg"
	"github.com/excavador/locksmith/pkg/gpgsmith"
	"github.com/excavador/locksmith/pkg/vault"
	"github.com/excavador/locksmith/pkg/wire"
)

type (
	// Daemon implements wire.Backend against the gpgsmith kernel. It owns
	// a map of open sessions keyed by opaque session token, an event
	// broker for pub/sub fan-out, and a cancellation channel that the
	// lifecycle goroutine in lifecycle.go uses to coordinate graceful
	// shutdown.
	//
	// Multiple open sessions for the same vault name are allowed and are
	// fully independent: each has its own token, its own /dev/shm workdir,
	// and its own gpg-agent pair. They do NOT share backing state.
	//
	// All methods on Daemon are safe to call from multiple goroutines
	// concurrently. Per-session state is protected by the per-entry
	// mutex; the sessions map itself is protected by Daemon.mu.
	Daemon struct {
		version    string
		commit     string
		startedAt  time.Time
		socketPath string
		cfgPath    string
		logger     *slog.Logger

		idleTimeout     time.Duration
		gracefulTimeout time.Duration

		mu       sync.RWMutex
		sessions map[string]*sessionEntry // keyed by opaque session token

		broker *Broker

		shuttingDown atomic.Bool
		shutdownOnce sync.Once
		shutdownCh   chan struct{}
	}

	// Options configures a new Daemon.
	Options struct {
		Version         string
		Commit          string
		Logger          *slog.Logger
		IdleTimeout     time.Duration
		GracefulTimeout time.Duration
		// ConfigPath overrides the vault registry config file path. If
		// empty, vault.LoadConfig("") is used (which resolves to the
		// default per-user location).
		ConfigPath string
		// SocketPath overrides the Unix socket path. If empty, the
		// daemon will compute it via SocketPath() in Run.
		SocketPath string
	}

	// sessionEntry is the daemon's per-session book-keeping around a
	// kernel gpgsmith.Session. The mu serializes mutating Backend methods
	// on a single session while leaving cross-session calls free to run
	// in parallel. Each entry carries its own opaque token — the key
	// under which it lives in Daemon.sessions — so that auto-seal
	// callbacks (idle timeout, shutdown) can find and delete themselves.
	sessionEntry struct {
		mu           sync.Mutex
		token        string
		session      *gpgsmith.Session
		entry        *vault.Entry
		startedAt    time.Time
		lastActiveAt time.Time

		idleTimer *time.Timer
	}
)

const (
	// DefaultIdleTimeout is the default per-session idle window after
	// which the daemon auto-seals to the encrypted ephemeral file and
	// drops the in-memory workdir.
	DefaultIdleTimeout = 5 * time.Minute

	// DefaultGracefulTimeout caps how long DaemonShutdown will spend
	// auto-sealing open sessions before falling back to discarding the
	// rest.
	DefaultGracefulTimeout = 30 * time.Second

	// unknownHostname is the placeholder used when os.Hostname returns
	// an empty string. Kept as a constant so lint doesn't complain
	// about repeated string literals.
	unknownHostname = "unknown"
)

var (
	// ErrSessionNotOpen is returned by methods that require an open
	// session when no session exists for the requested token.
	ErrSessionNotOpen = errors.New("daemon: no open session for token")

	// ErrShuttingDown is returned by OpenVault / ResumeVault while the
	// daemon is in the process of shutting down.
	ErrShuttingDown = errors.New("daemon: shutting down")
)

// newSessionToken returns a fresh opaque 64-hex-char session handle,
// generated from crypto/rand. 32 bytes of entropy is ample for tying
// an RPC to a single live daemon process.
func newSessionToken() string {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand.Read on all supported platforms never fails in
		// practice; if it does, panic is the only honest response —
		// we would otherwise mint a zero-entropy token.
		panic(fmt.Sprintf("daemon: crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(buf[:])
}

// New constructs a Daemon with the given options. The returned Daemon is
// not yet listening on a socket; call Run to start the lifecycle.
func New(opts Options) *Daemon {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	idle := opts.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	graceful := opts.GracefulTimeout
	if graceful <= 0 {
		graceful = DefaultGracefulTimeout
	}
	return &Daemon{
		version:         opts.Version,
		commit:          opts.Commit,
		startedAt:       time.Now().UTC(),
		socketPath:      opts.SocketPath,
		cfgPath:         opts.ConfigPath,
		logger:          logger,
		idleTimeout:     idle,
		gracefulTimeout: graceful,
		sessions:        make(map[string]*sessionEntry),
		broker:          NewBroker(logger),
		shutdownCh:      make(chan struct{}),
	}
}

// Broker returns the daemon's event broker. Exposed for tests; production
// callers should use SubscribeEvents.
func (d *Daemon) Broker() *Broker {
	return d.broker
}

// SocketPath returns the configured Unix socket path or "" if Run has not
// yet computed one.
func (d *Daemon) SocketPath() string {
	return d.socketPath
}

// ===== helpers =====

func (d *Daemon) lookupSession(token string) (*sessionEntry, error) {
	if token == "" {
		return nil, ErrSessionNotOpen
	}
	d.mu.RLock()
	se, ok := d.sessions[token]
	d.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w", ErrSessionNotOpen)
	}
	return se, nil
}

// vaultNameFromToken is a convenience for wire-level filtering (e.g. the
// event subscriber) that wants the vault name for a given token. Returns
// "" if the token is unknown.
func (d *Daemon) vaultNameFromToken(token string) string {
	if token == "" {
		return ""
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if se, ok := d.sessions[token]; ok && se.entry != nil {
		return se.entry.Name
	}
	return ""
}

func (d *Daemon) sessionInfoLocked(se *sessionEntry) wire.SessionInfo {
	s := se.session
	info := wire.SessionInfo{
		VaultName:    se.entry.Name,
		VaultPath:    se.entry.Path,
		Source:       s.Source,
		Hostname:     s.Hostname,
		StartedAt:    se.startedAt,
		LastActiveAt: se.lastActiveAt,
		MasterFP:     s.ConfiguredMasterFP,
		Generation:   s.Generation(),
		Status:       string(gpgsmith.EphemeralStatusActive),
	}
	if s.SourceSnap != nil {
		info.SourceSnapshot = filepath.Base(s.SourceSnap.Path)
	}
	return info
}

func (d *Daemon) startIdleTimer(se *sessionEntry) {
	se.mu.Lock()
	defer se.mu.Unlock()
	token := se.token
	se.idleTimer = time.AfterFunc(d.idleTimeout, func() {
		d.handleIdleTimeout(token)
	})
}

func (d *Daemon) handleIdleTimeout(token string) {
	d.mu.Lock()
	se, ok := d.sessions[token]
	if !ok {
		d.mu.Unlock()
		return
	}
	delete(d.sessions, token)
	d.mu.Unlock()

	ctx := context.Background()
	se.mu.Lock()
	s := se.session
	name := ""
	if se.entry != nil {
		name = se.entry.Name
	}
	se.mu.Unlock()

	if s != nil && !s.IsClosed() {
		if err := s.AutoSealAndDrop(ctx); err != nil {
			d.logger.WarnContext(ctx, "idle auto-seal failed",
				slog.String("vault", name),
				slog.String("error", err.Error()),
			)
		}
	}

	d.publishEvent(name, wire.EventKindSessionEnded, "idle auto-seal")
}

func (d *Daemon) publishEvent(vaultName string, kind wire.EventKind, message string) {
	evt := &wire.Event{
		At:        time.Now().UTC(),
		VaultName: vaultName,
		Kind:      kind,
		Message:   message,
	}
	d.broker.Publish("vault:"+vaultName, evt)
	d.broker.Publish("*", evt)
}

// loadConfig loads the vault registry config from the daemon's
// configured path.
func (d *Daemon) loadConfig() (*vault.Config, error) {
	cfg, err := vault.LoadConfig(d.cfgPath)
	if err != nil {
		return nil, fmt.Errorf("load vault config: %w", err)
	}
	return cfg, nil
}

func (d *Daemon) saveConfig(cfg *vault.Config) error {
	if err := vault.SaveConfig(d.cfgPath, cfg); err != nil {
		return fmt.Errorf("save vault config: %w", err)
	}
	return nil
}

// ===== DaemonService =====

// DaemonStatus implements wire.Backend.
func (d *Daemon) DaemonStatus(_ context.Context) (wire.DaemonStatus, error) {
	d.mu.RLock()
	active := len(d.sessions)
	d.mu.RUnlock()
	return wire.DaemonStatus{
		PID:            os.Getpid(),
		Version:        d.version,
		Commit:         d.commit,
		SocketPath:     d.socketPath,
		StartedAt:      d.startedAt,
		ActiveSessions: active,
	}, nil
}

// DaemonShutdown implements wire.Backend. Marks the daemon as shutting
// down (rejecting new opens), then auto-seals every open session within
// the supplied graceful budget; sessions that exceed the budget are
// force-discarded. Finally signals the lifecycle goroutine to close the
// listener and exit.
func (d *Daemon) DaemonShutdown(ctx context.Context, gracefulTimeoutSeconds int) error {
	d.shuttingDown.Store(true)

	budget := time.Duration(gracefulTimeoutSeconds) * time.Second
	if budget <= 0 {
		budget = d.gracefulTimeout
	}
	deadline := time.Now().Add(budget)

	d.mu.Lock()
	tokens := make([]string, 0, len(d.sessions))
	for tok := range d.sessions {
		tokens = append(tokens, tok)
	}
	d.mu.Unlock()

	for _, tok := range tokens {
		d.mu.Lock()
		se, ok := d.sessions[tok]
		if ok {
			delete(d.sessions, tok)
		}
		d.mu.Unlock()
		if !ok {
			continue
		}

		se.mu.Lock()
		if se.idleTimer != nil {
			se.idleTimer.Stop()
		}
		s := se.session
		name := ""
		if se.entry != nil {
			name = se.entry.Name
		}
		se.mu.Unlock()

		remaining := time.Until(deadline)
		if remaining <= 0 {
			// Out of budget — force discard.
			if s != nil && !s.IsClosed() {
				if err := s.Discard(ctx); err != nil {
					d.logger.WarnContext(ctx, "shutdown discard failed",
						slog.String("vault", name),
						slog.String("error", err.Error()),
					)
				}
			}
			continue
		}

		sealCtx, cancel := context.WithTimeout(ctx, remaining)
		if s != nil && !s.IsClosed() {
			if err := s.AutoSealAndDrop(sealCtx); err != nil {
				d.logger.WarnContext(ctx, "shutdown auto-seal failed",
					slog.String("vault", name),
					slog.String("error", err.Error()),
				)
				if !s.IsClosed() {
					_ = s.Discard(ctx)
				}
			}
		}
		cancel()
	}

	d.shutdownOnce.Do(func() {
		close(d.shutdownCh)
	})
	d.broker.CloseAll()
	return nil
}

// ShutdownCh returns a channel that is closed when DaemonShutdown is
// invoked. Used by the lifecycle goroutine to drive listener teardown.
func (d *Daemon) ShutdownCh() <-chan struct{} {
	return d.shutdownCh
}

// ListSessions implements wire.Backend.
func (d *Daemon) ListSessions(_ context.Context) ([]wire.SessionInfo, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]wire.SessionInfo, 0, len(d.sessions))
	for _, se := range d.sessions {
		out = append(out, d.sessionInfoLocked(se))
	}
	return out, nil
}

// ListSessionTokens implements wire.Backend. Returns the opaque
// session tokens alongside each session's vault name for the local
// CLI auto-bind path. The tokens are NOT exposed via proto messages;
// they travel only in a response header stamped by the wire layer.
func (d *Daemon) ListSessionTokens(_ context.Context) ([]wire.SessionTokenEntry, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]wire.SessionTokenEntry, 0, len(d.sessions))
	for tok, se := range d.sessions {
		name := ""
		if se.entry != nil {
			name = se.entry.Name
		}
		out = append(out, wire.SessionTokenEntry{Token: tok, VaultName: name})
	}
	return out, nil
}

// ===== VaultService =====

// ListVaults implements wire.Backend.
//
// Deduplicates against the legacy single-vault form: if cfg.VaultDir is
// set AND a registry entry already covers the same name (typically
// "default") OR the same physical path, the legacy entry is suppressed.
// This avoids the user seeing two rows for the same vault when their
// config carries both `vault_dir:` and an explicit `vaults:` entry — a
// state that occurs naturally after TOFU first-use writes the registry
// entry without removing the legacy field.
func (d *Daemon) ListVaults(_ context.Context) ([]vault.Entry, string, error) {
	cfg, err := d.loadConfig()
	if err != nil {
		return nil, "", err
	}
	out := mergeVaultEntries(cfg)
	return out, cfg.Default, nil
}

// mergeVaultEntries returns the merged registry+legacy entries with
// duplicates removed. Registry entries (cfg.Vaults) are authoritative;
// the legacy `vault_dir:` synthesizes a "default" entry only when no
// registry entry already covers it.
func mergeVaultEntries(cfg *vault.Config) []vault.Entry {
	out := make([]vault.Entry, 0, len(cfg.Vaults)+1)
	seenNames := make(map[string]struct{}, len(cfg.Vaults)+1)
	seenPaths := make(map[string]struct{}, len(cfg.Vaults)+1)

	for _, e := range cfg.Vaults {
		if _, ok := seenNames[e.Name]; ok {
			continue
		}
		seenNames[e.Name] = struct{}{}
		if e.Path != "" {
			seenPaths[e.Path] = struct{}{}
		}
		out = append(out, e)
	}

	if cfg.VaultDir != "" {
		_, nameTaken := seenNames[vault.LegacyDefaultName]
		_, pathTaken := seenPaths[cfg.VaultDir]
		if !nameTaken && !pathTaken {
			out = append(out, vault.Entry{
				Name:     vault.LegacyDefaultName,
				Path:     cfg.VaultDir,
				Identity: cfg.Identity,
			})
		}
	}

	return out
}

// StatusVaults implements wire.Backend. Returns currently-open sessions
// from the daemon plus any recoverable ephemerals discovered on disk for
// vaults that are NOT currently open.
func (d *Daemon) StatusVaults(_ context.Context) ([]wire.SessionInfo, []wire.ResumeOption, error) {
	cfg, err := d.loadConfig()
	if err != nil {
		return nil, nil, err
	}

	d.mu.RLock()
	open := make([]wire.SessionInfo, 0, len(d.sessions))
	openSet := make(map[string]struct{}, len(d.sessions))
	for _, se := range d.sessions {
		open = append(open, d.sessionInfoLocked(se))
		if se.entry != nil {
			openSet[se.entry.Name] = struct{}{}
		}
	}
	d.mu.RUnlock()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = unknownHostname
	}

	var recoverable []wire.ResumeOption
	for _, entry := range mergeVaultEntries(cfg) {
		if _, ok := openSet[entry.Name]; ok {
			continue
		}
		eph, _ := gpgsmith.FindEphemeralFor(entry.Path, hostname)
		if !isRecoverable(eph) {
			continue
		}
		recoverable = append(recoverable, ephToResumeOption(eph))
	}

	return open, recoverable, nil
}

// isRecoverable reports whether a discovered Ephemeral has enough on-disk
// state to be resumed. An .info sidecar alone is NOT enough: the
// encrypted state file must exist too. Sessions that were started but
// never flushed any mutations (so the state file was never written), or
// that were killed before AutoSealAndDrop could run, leave behind an
// orphan .info that looks like a resume candidate but would crash
// ResumeSession with "ephemeral has no state file on disk". Filtering
// those out here keeps both StatusVaults and OpenVault honest.
func isRecoverable(eph *gpgsmith.Ephemeral) bool {
	return eph != nil && eph.SessionPath != ""
}

func ephToResumeOption(eph *gpgsmith.Ephemeral) wire.ResumeOption {
	return wire.ResumeOption{
		CanonicalBase: eph.CanonicalBase,
		Hostname:      eph.Info.Hostname,
		Source:        eph.Info.Source,
		StartedAt:     eph.Info.StartedAt,
		LastHeartbeat: eph.Info.LastHeartbeat,
		Status:        string(eph.Info.Status),
	}
}

// OpenVault implements wire.Backend. If a recoverable ephemeral exists on
// disk for our hostname the call returns OpenResult{ResumeAvailable: ...}
// without opening — the caller must follow up with ResumeVault.
// Otherwise the latest canonical is opened, TOFU is performed, and the
// new session is recorded in d.sessions.
func (d *Daemon) OpenVault(ctx context.Context, name, passphrase string, source gpgsmith.LockSource) (wire.OpenResult, string, error) {
	if d.shuttingDown.Load() {
		return wire.OpenResult{}, "", ErrShuttingDown
	}

	cfg, err := d.loadConfig()
	if err != nil {
		return wire.OpenResult{}, "", err
	}
	entry, err := cfg.Resolve(name)
	if err != nil {
		return wire.OpenResult{}, "", fmt.Errorf("open vault: %w", err)
	}

	// Multiple independent sessions for the same vault name are allowed.
	// We only consult the on-disk ephemeral state here; any previous
	// in-memory session is unrelated to this new decrypt.
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = unknownHostname
	}

	if eph, _ := gpgsmith.FindEphemeralFor(entry.Path, hostname); isRecoverable(eph) {
		opt := ephToResumeOption(eph)
		opt.Divergent = isDivergent(entry.Path, eph)
		return wire.OpenResult{ResumeAvailable: &opt}, "", nil
	} else if eph != nil {
		// Orphaned .info with no state file — usually a session that was
		// killed before it wrote any mutations to disk. Log and ignore;
		// the new session we are about to start will overwrite this file
		// when it writes its own first heartbeat.
		d.logger.WarnContext(ctx, "ignoring orphan ephemeral .info (no state file on disk)",
			slog.String("vault", entry.Name),
			slog.String("info", eph.InfoPath),
		)
	}

	v, err := vault.NewWithPassphrase(entry.ToConfig(), passphrase, d.logger)
	if err != nil {
		return wire.OpenResult{}, "", fmt.Errorf("open vault: %w", err)
	}

	res, err := gpgsmith.OpenSession(ctx, v, entry, gpgsmith.SessionOpts{
		Source: source,
		Logger: d.logger,
	})
	if err != nil {
		return wire.OpenResult{}, "", err
	}

	if res.TOFUFingerprint != "" {
		// Persist the TOFU first-use into the registry.
		if err := d.persistTOFU(cfg, entry.Name, res.TOFUFingerprint); err != nil {
			d.logger.WarnContext(ctx, "persist TOFU fingerprint failed",
				slog.String("vault", entry.Name),
				slog.String("error", err.Error()),
			)
		}
	}

	se := d.registerSession(entry, res.Session)
	d.publishEvent(entry.Name, wire.EventKindStateChanged, "session opened")

	info := d.sessionInfoLocked(se)
	return wire.OpenResult{Session: &info}, se.token, nil
}

// isDivergent reports whether newer canonical snapshots exist alongside
// the ephemeral.
func isDivergent(vaultDir string, eph *gpgsmith.Ephemeral) bool {
	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		return false
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if len(n) > len(".tar.age") && n[len(n)-len(".tar.age"):] == ".tar.age" {
			names = append(names, n)
		}
	}
	return eph.IsDivergent(names)
}

func (d *Daemon) persistTOFU(cfg *vault.Config, name, fp string) error {
	for i := range cfg.Vaults {
		if cfg.Vaults[i].Name == name {
			cfg.Vaults[i].TrustedMasterFP = fp
			return d.saveConfig(cfg)
		}
	}
	// Legacy single-vault: synthesize a registry entry rather than
	// touching the legacy fields.
	cfg.Vaults = append(cfg.Vaults, vault.Entry{
		Name:            name,
		Path:            cfg.VaultDir,
		TrustedMasterFP: fp,
	})
	return d.saveConfig(cfg)
}

func (d *Daemon) registerSession(entry *vault.Entry, s *gpgsmith.Session) *sessionEntry {
	now := time.Now().UTC()
	se := &sessionEntry{
		token:        newSessionToken(),
		session:      s,
		entry:        entry,
		startedAt:    now,
		lastActiveAt: now,
	}
	d.mu.Lock()
	d.sessions[se.token] = se
	d.mu.Unlock()
	d.startIdleTimer(se)
	return se
}

// ResumeVault implements wire.Backend.
func (d *Daemon) ResumeVault(ctx context.Context, name, passphrase string, source gpgsmith.LockSource, resume bool) (wire.SessionInfo, string, error) {
	if d.shuttingDown.Load() {
		return wire.SessionInfo{}, "", ErrShuttingDown
	}

	cfg, err := d.loadConfig()
	if err != nil {
		return wire.SessionInfo{}, "", err
	}
	entry, err := cfg.Resolve(name)
	if err != nil {
		return wire.SessionInfo{}, "", fmt.Errorf("resume vault: %w", err)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = unknownHostname
	}

	v, err := vault.NewWithPassphrase(entry.ToConfig(), passphrase, d.logger)
	if err != nil {
		return wire.SessionInfo{}, "", fmt.Errorf("resume vault: %w", err)
	}

	eph, _ := gpgsmith.FindEphemeralFor(entry.Path, hostname)

	if !resume {
		// Caller chose to discard the ephemeral and start fresh from
		// the latest canonical.
		if eph != nil {
			_ = gpgsmith.DeleteEphemeralFiles(eph.SessionPath, eph.InfoPath)
		}
		res, openErr := gpgsmith.OpenSession(ctx, v, entry, gpgsmith.SessionOpts{
			Source: source,
			Logger: d.logger,
		})
		if openErr != nil {
			return wire.SessionInfo{}, "", openErr
		}
		if res.TOFUFingerprint != "" {
			if persistErr := d.persistTOFU(cfg, entry.Name, res.TOFUFingerprint); persistErr != nil {
				d.logger.WarnContext(ctx, "persist TOFU fingerprint failed",
					slog.String("vault", entry.Name),
					slog.String("error", persistErr.Error()),
				)
			}
		}
		se := d.registerSession(entry, res.Session)
		d.publishEvent(entry.Name, wire.EventKindStateChanged, "session opened")
		return d.sessionInfoLocked(se), se.token, nil
	}

	if eph == nil {
		return wire.SessionInfo{}, "", fmt.Errorf("resume vault: no ephemeral to resume for %q", entry.Name)
	}

	res, err := gpgsmith.ResumeSession(ctx, v, entry, eph, gpgsmith.SessionOpts{
		Source: source,
		Logger: d.logger,
	})
	if err != nil {
		return wire.SessionInfo{}, "", err
	}
	if res.TOFUFingerprint != "" {
		if persistErr := d.persistTOFU(cfg, entry.Name, res.TOFUFingerprint); persistErr != nil {
			d.logger.WarnContext(ctx, "persist TOFU fingerprint failed",
				slog.String("vault", entry.Name),
				slog.String("error", persistErr.Error()),
			)
		}
	}
	se := d.registerSession(entry, res.Session)
	d.publishEvent(entry.Name, wire.EventKindStateChanged, "session resumed")
	return d.sessionInfoLocked(se), se.token, nil
}

// SealVault implements wire.Backend.
func (d *Daemon) SealVault(ctx context.Context, token, message string) (vault.Snapshot, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return vault.Snapshot{}, err
	}

	se.mu.Lock()
	if se.idleTimer != nil {
		se.idleTimer.Stop()
	}
	s := se.session
	name := ""
	if se.entry != nil {
		name = se.entry.Name
	}
	se.mu.Unlock()

	d.mu.Lock()
	delete(d.sessions, token)
	d.mu.Unlock()

	snap, err := s.Seal(ctx, message)
	if err != nil {
		return vault.Snapshot{}, err
	}
	d.publishEvent(name, wire.EventKindSessionEnded, "sealed")
	return *snap, nil
}

// DiscardVault implements wire.Backend.
func (d *Daemon) DiscardVault(ctx context.Context, token string) error {
	se, err := d.lookupSession(token)
	if err != nil {
		return err
	}

	se.mu.Lock()
	if se.idleTimer != nil {
		se.idleTimer.Stop()
	}
	s := se.session
	name := ""
	if se.entry != nil {
		name = se.entry.Name
	}
	se.mu.Unlock()

	d.mu.Lock()
	delete(d.sessions, token)
	d.mu.Unlock()

	if err := s.Discard(ctx); err != nil {
		return err
	}
	d.publishEvent(name, wire.EventKindSessionEnded, "discarded")
	return nil
}

// Snapshots implements wire.Backend.
func (d *Daemon) Snapshots(ctx context.Context, name string) ([]vault.Snapshot, error) {
	// Snapshots is a stateless directory listing — no session needed.
	// If a session happens to be open for this vault, we still don't
	// touch it; we just resolve the entry from config and read the
	// vault directory directly. This lets the user see what canonical
	// snapshots exist without having to enter their passphrase.
	cfg, err := d.loadConfig()
	if err != nil {
		return nil, err
	}
	entry, err := cfg.Resolve(name)
	if err != nil {
		return nil, fmt.Errorf("snapshots: resolve vault: %w", err)
	}

	// Build a Vault without a passphrase or identity. List() only reads
	// directory entries and parses filenames; it never decrypts.
	v, err := vault.New(entry.ToConfig(), d.logger)
	if err != nil {
		return nil, fmt.Errorf("snapshots: %w", err)
	}
	return v.List(ctx)
}

// ImportVault implements wire.Backend.
func (d *Daemon) ImportVault(ctx context.Context, sourcePath, passphrase, targetName string) (vault.Snapshot, error) {
	cfg, err := d.loadConfig()
	if err != nil {
		// New install: start from empty config.
		cfg = &vault.Config{}
	}
	entry, resErr := cfg.Resolve(targetName)
	if resErr != nil {
		return vault.Snapshot{}, fmt.Errorf("import vault: %w", resErr)
	}
	v, err := vault.NewWithPassphrase(entry.ToConfig(), passphrase, d.logger)
	if err != nil {
		return vault.Snapshot{}, fmt.Errorf("import vault: %w", err)
	}
	snap, err := v.Import(ctx, sourcePath)
	if err != nil {
		return vault.Snapshot{}, err
	}
	return snap, nil
}

// CreateVault implements wire.Backend. Initializes a brand-new vault
// registry entry, writes an empty snapshot to disk, opens it, and
// registers a session for follow-up key generation via KeyService.Create.
func (d *Daemon) CreateVault(ctx context.Context, name, path, passphrase string) (vault.Snapshot, wire.SessionInfo, string, error) {
	if d.shuttingDown.Load() {
		return vault.Snapshot{}, wire.SessionInfo{}, "", ErrShuttingDown
	}
	if name == "" {
		return vault.Snapshot{}, wire.SessionInfo{}, "", fmt.Errorf("create vault: name is required")
	}
	if path == "" {
		return vault.Snapshot{}, wire.SessionInfo{}, "", fmt.Errorf("create vault: path is required")
	}
	if passphrase == "" {
		return vault.Snapshot{}, wire.SessionInfo{}, "", fmt.Errorf("create vault: passphrase is required")
	}

	cfg, err := d.loadConfig()
	if err != nil {
		// Fresh install: start from empty config.
		cfg = &vault.Config{}
	}

	// Detect existing entry by name — fail to avoid clobbering.
	for i := range cfg.Vaults {
		if cfg.Vaults[i].Name == name {
			return vault.Snapshot{}, wire.SessionInfo{}, "", fmt.Errorf("create vault: %q already exists in registry", name)
		}
	}

	entry := vault.Entry{Name: name, Path: path}
	if addErr := cfg.AddVault(entry); addErr != nil {
		return vault.Snapshot{}, wire.SessionInfo{}, "", fmt.Errorf("create vault: %w", addErr)
	}
	if err := d.saveConfig(cfg); err != nil {
		return vault.Snapshot{}, wire.SessionInfo{}, "", err
	}

	v, err := vault.NewWithPassphrase(entry.ToConfig(), passphrase, d.logger)
	if err != nil {
		return vault.Snapshot{}, wire.SessionInfo{}, "", fmt.Errorf("create vault: %w", err)
	}
	if err := v.Create(ctx); err != nil {
		return vault.Snapshot{}, wire.SessionInfo{}, "", fmt.Errorf("create vault: %w", err)
	}

	// Build an empty workdir and seal it as the first canonical so that
	// OpenSession has something to decrypt.
	emptyDir, err := vault.SecureTmpDir()
	if err != nil {
		return vault.Snapshot{}, wire.SessionInfo{}, "", fmt.Errorf("create vault: empty workdir: %w", err)
	}
	defer func() { _ = os.RemoveAll(emptyDir) }()

	snap, err := v.Import(ctx, emptyDir)
	if err != nil {
		return vault.Snapshot{}, wire.SessionInfo{}, "", fmt.Errorf("create vault: initial seal: %w", err)
	}

	// Now open it as a proper session.
	res, err := gpgsmith.OpenSession(ctx, v, &entry, gpgsmith.SessionOpts{
		Source: gpgsmith.LockSourceCLI,
		Logger: d.logger,
	})
	if err != nil {
		return vault.Snapshot{}, wire.SessionInfo{}, "", fmt.Errorf("create vault: open session: %w", err)
	}

	se := d.registerSession(&entry, res.Session)
	d.publishEvent(entry.Name, wire.EventKindStateChanged, "vault created")

	info := d.sessionInfoLocked(se)
	return snap, info, se.token, nil
}

// ExportVault implements wire.Backend. Decrypts the latest canonical of
// the named vault and copies its contents into targetDir. This is an
// offline, one-shot operation: no session is created, no daemon-side
// state is touched.
func (d *Daemon) ExportVault(ctx context.Context, name, passphrase, targetDir string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("export vault: name is required")
	}
	if targetDir == "" {
		return "", fmt.Errorf("export vault: target dir is required")
	}
	if passphrase == "" {
		return "", fmt.Errorf("export vault: passphrase is required")
	}

	cfg, err := d.loadConfig()
	if err != nil {
		return "", err
	}
	entry, err := cfg.Resolve(name)
	if err != nil {
		return "", fmt.Errorf("export vault: %w", err)
	}

	v, err := vault.NewWithPassphrase(entry.ToConfig(), passphrase, d.logger)
	if err != nil {
		return "", fmt.Errorf("export vault: %w", err)
	}

	workdir, snap, err := v.Open(ctx)
	if err != nil {
		return "", fmt.Errorf("export vault: %w", err)
	}
	defer func() { _ = v.Discard(ctx, workdir) }()

	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		return "", fmt.Errorf("export vault: create target dir: %w", err)
	}

	if err := copyTree(workdir, targetDir); err != nil {
		return "", fmt.Errorf("export vault: copy: %w", err)
	}

	return filepath.Base(snap.Path), nil
}

// copyTree recursively copies every file and subdirectory from src into
// dst. Used by ExportVault to move the decrypted workdir into the
// user-supplied target directory.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(src, path)
		if relErr != nil {
			return relErr
		}
		target := filepath.Join(dst, rel)
		if de.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		in, openErr := os.Open(path) //nolint:gosec // path is our freshly-decrypted workdir
		if openErr != nil {
			return openErr
		}
		defer func() { _ = in.Close() }()
		out, createErr := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // target dir supplied by caller
		if createErr != nil {
			return createErr
		}
		if _, copyErr := io.Copy(out, in); copyErr != nil {
			_ = out.Close()
			return copyErr
		}
		return out.Close()
	})
}

// TrustVault implements wire.Backend.
func (d *Daemon) TrustVault(_ context.Context, name, fingerprint string) error {
	if err := gpg.ValidateFingerprint(fingerprint); err != nil {
		return fmt.Errorf("trust vault: %w", err)
	}
	cfg, err := d.loadConfig()
	if err != nil {
		return err
	}
	for i := range cfg.Vaults {
		if cfg.Vaults[i].Name == name {
			cfg.Vaults[i].TrustedMasterFP = fingerprint
			return d.saveConfig(cfg)
		}
	}
	if cfg.VaultDir != "" && (name == "" || name == vault.LegacyDefaultName) {
		cfg.Vaults = append(cfg.Vaults, vault.Entry{
			Name:            vault.LegacyDefaultName,
			Path:            cfg.VaultDir,
			TrustedMasterFP: fingerprint,
		})
		return d.saveConfig(cfg)
	}
	return fmt.Errorf("trust vault: unknown vault %q", name)
}

// ===== KeyService =====

// CreateMasterKey implements wire.Backend.
func (d *Daemon) CreateMasterKey(ctx context.Context, token string, opts wire.CreateKeyOpts) (string, []gpg.SubKey, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return "", nil, err
	}
	vaultName := se.entry.Name
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	fp, err := client.GenerateMasterKey(ctx, gpg.MasterKeyOpts{
		NameReal:  opts.Name,
		NameEmail: opts.Email,
		Algo:      opts.Algo,
		Expiry:    opts.Expiry,
	})
	if err != nil {
		return "", nil, err
	}

	subkeyAlgo := opts.SubkeyAlgo
	if subkeyAlgo == "" {
		subkeyAlgo = opts.Algo
	}
	subkeyExpiry := opts.SubkeyExpiry
	if subkeyExpiry == "" {
		subkeyExpiry = "2y"
	}

	cfg := &gpg.Config{
		MasterFP:     fp,
		SubkeyAlgo:   subkeyAlgo,
		SubkeyExpiry: subkeyExpiry,
	}
	if err := client.SaveConfig(cfg); err != nil {
		return "", nil, fmt.Errorf("create master key: save config: %w", err)
	}

	if err := client.GenerateSubkeys(ctx, gpg.SubkeyOpts{
		MasterFP: fp,
		Algo:     subkeyAlgo,
		Expiry:   subkeyExpiry,
	}); err != nil {
		return "", nil, fmt.Errorf("create master key: generate subkeys: %w", err)
	}

	se.session.MarkChanged()

	keys, _ := client.ListSecretKeys(ctx)

	_ = audit.Append(client.HomeDir(), audit.Entry{
		Action:  "create-key",
		Details: fmt.Sprintf("master %s + S/E/A %s expires %s", fp, subkeyAlgo, subkeyExpiry),
		Metadata: map[string]string{
			"master_fp": fp,
			"uid":       fmt.Sprintf("%s <%s>", opts.Name, opts.Email),
		},
	})

	d.touchLocked(se)
	d.publishEvent(vaultName, wire.EventKindStateChanged, "master key created")
	return fp, keys, nil
}

// touchLocked is the touch helper assuming caller already holds se.mu.
func (d *Daemon) touchLocked(se *sessionEntry) {
	se.lastActiveAt = time.Now().UTC()
	if se.idleTimer != nil {
		se.idleTimer.Reset(d.idleTimeout)
	}
}

// GenerateSubkeys implements wire.Backend.
func (d *Daemon) GenerateSubkeys(ctx context.Context, token string) ([]gpg.SubKey, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return nil, err
	}
	vaultName := se.entry.Name
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	cfg, err := client.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("generate subkeys: load config: %w", err)
	}
	if err := client.GenerateSubkeys(ctx, gpg.SubkeyOpts{
		MasterFP: cfg.MasterFP,
		Algo:     cfg.SubkeyAlgo,
		Expiry:   cfg.SubkeyExpiry,
	}); err != nil {
		return nil, err
	}
	se.session.MarkChanged()

	_ = audit.Append(client.HomeDir(), audit.Entry{
		Action:  "generate-subkeys",
		Details: fmt.Sprintf("S/E/A %s expires %s", cfg.SubkeyAlgo, cfg.SubkeyExpiry),
	})

	keys, _ := client.ListSecretKeys(ctx)
	d.touchLocked(se)
	d.publishEvent(vaultName, wire.EventKindStateChanged, "subkeys generated")
	return keys, nil
}

// ListKeys implements wire.Backend.
func (d *Daemon) ListKeys(ctx context.Context, token string) ([]gpg.SubKey, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return nil, err
	}
	se.mu.Lock()
	defer se.mu.Unlock()
	d.touchLocked(se)
	return se.session.GPG.ListSecretKeys(ctx)
}

// RevokeSubkey implements wire.Backend.
func (d *Daemon) RevokeSubkey(ctx context.Context, token, keyID string) error {
	se, err := d.lookupSession(token)
	if err != nil {
		return err
	}
	vaultName := se.entry.Name
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	cfg, err := client.LoadConfig()
	if err != nil {
		return fmt.Errorf("revoke subkey: load config: %w", err)
	}
	if err := client.Revoke(ctx, cfg.MasterFP, keyID); err != nil {
		return err
	}
	se.session.MarkChanged()
	_ = audit.Append(client.HomeDir(), audit.Entry{
		Action:  "revoke-subkey",
		Details: fmt.Sprintf("revoked subkey %s", keyID),
		Metadata: map[string]string{
			"key_id": keyID,
		},
	})
	d.touchLocked(se)
	d.publishEvent(vaultName, wire.EventKindStateChanged, "subkey revoked")
	return nil
}

// ExportKey implements wire.Backend.
func (d *Daemon) ExportKey(ctx context.Context, token string) (string, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return "", err
	}
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	cfg, err := client.LoadConfig()
	if err != nil {
		return "", fmt.Errorf("export key: load config: %w", err)
	}
	if err := client.ExportPubKeyToLocal(ctx, cfg.MasterFP); err != nil {
		return "", err
	}
	d.touchLocked(se)
	return cfg.MasterFP, nil
}

// SSHPubKey implements wire.Backend.
func (d *Daemon) SSHPubKey(ctx context.Context, token string) (string, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return "", err
	}
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	cfg, err := client.LoadConfig()
	if err != nil {
		return "", fmt.Errorf("ssh pubkey: load config: %w", err)
	}
	d.touchLocked(se)
	return client.ExportSSHPubKey(ctx, cfg.MasterFP)
}

// KeyStatus implements wire.Backend.
func (d *Daemon) KeyStatus(ctx context.Context, token string) ([]gpg.SubKey, *gpg.CardInfo, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return nil, nil, err
	}
	se.mu.Lock()
	defer se.mu.Unlock()
	d.touchLocked(se)

	client := se.session.GPG
	keys, err := client.ListKeys(ctx)
	if err != nil {
		return nil, nil, err
	}
	// Live card status is optional — if scdaemon can't acquire the
	// card (e.g. another gpg-agent holds it despite our retry), we
	// return the keys anyway so the caller can still render them.
	// The failure is logged so operators can diagnose "no card
	// detected" showing up unexpectedly.
	info, cardErr := client.CardStatus(ctx)
	if cardErr != nil {
		d.logger.DebugContext(ctx, "key status: live card-status call failed (keys list still returned)",
			slog.String("error", cardErr.Error()),
		)
	}
	return keys, info, nil
}

// ===== IdentityService =====

// ListIdentities implements wire.Backend.
func (d *Daemon) ListIdentities(ctx context.Context, token string) ([]gpg.UID, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return nil, err
	}
	se.mu.Lock()
	defer se.mu.Unlock()
	d.touchLocked(se)

	client := se.session.GPG
	cfg, err := client.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("list identities: load config: %w", err)
	}
	return client.ListUIDs(ctx, cfg.MasterFP)
}

// AddIdentity implements wire.Backend.
func (d *Daemon) AddIdentity(ctx context.Context, token, uid string) error {
	se, err := d.lookupSession(token)
	if err != nil {
		return err
	}
	vaultName := se.entry.Name
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	cfg, err := client.LoadConfig()
	if err != nil {
		return fmt.Errorf("add identity: load config: %w", err)
	}
	if err := client.AddUID(ctx, cfg.MasterFP, uid); err != nil {
		return err
	}
	se.session.MarkChanged()
	d.republish(ctx, client, cfg.MasterFP)
	_ = audit.Append(client.HomeDir(), audit.Entry{
		Action:   "add-identity",
		Details:  fmt.Sprintf("added identity %q", uid),
		Metadata: map[string]string{"identity": uid},
	})
	d.touchLocked(se)
	d.publishEvent(vaultName, wire.EventKindStateChanged, "identity added")
	return nil
}

// RevokeIdentity implements wire.Backend.
func (d *Daemon) RevokeIdentity(ctx context.Context, token, uid string) error {
	se, err := d.lookupSession(token)
	if err != nil {
		return err
	}
	vaultName := se.entry.Name
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	cfg, err := client.LoadConfig()
	if err != nil {
		return fmt.Errorf("revoke identity: load config: %w", err)
	}
	if err := client.RevokeUID(ctx, cfg.MasterFP, uid); err != nil {
		return err
	}
	se.session.MarkChanged()
	d.republish(ctx, client, cfg.MasterFP)
	_ = audit.Append(client.HomeDir(), audit.Entry{
		Action:   "revoke-identity",
		Details:  fmt.Sprintf("revoked identity %q", uid),
		Metadata: map[string]string{"identity": uid},
	})
	d.touchLocked(se)
	d.publishEvent(vaultName, wire.EventKindStateChanged, "identity revoked")
	return nil
}

// PrimaryIdentity implements wire.Backend.
func (d *Daemon) PrimaryIdentity(ctx context.Context, token, uid string) error {
	se, err := d.lookupSession(token)
	if err != nil {
		return err
	}
	vaultName := se.entry.Name
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	cfg, err := client.LoadConfig()
	if err != nil {
		return fmt.Errorf("primary identity: load config: %w", err)
	}
	if err := client.SetPrimaryUID(ctx, cfg.MasterFP, uid); err != nil {
		return err
	}
	se.session.MarkChanged()
	d.republish(ctx, client, cfg.MasterFP)
	_ = audit.Append(client.HomeDir(), audit.Entry{
		Action:   "set-primary-identity",
		Details:  fmt.Sprintf("set primary identity %q", uid),
		Metadata: map[string]string{"identity": uid},
	})
	d.touchLocked(se)
	d.publishEvent(vaultName, wire.EventKindStateChanged, "primary identity set")
	return nil
}

// republish best-effort republishes the master key to all enabled
// servers. Failures are logged but never returned.
func (d *Daemon) republish(ctx context.Context, client *gpg.Client, masterFP string) {
	reg, err := client.LoadServerRegistry()
	if err != nil {
		return
	}
	targets := gpg.ToPublishTargets(reg.EnabledServers())
	if len(targets) == 0 {
		return
	}
	results := client.Publish(ctx, masterFP, targets)
	for i := range results {
		if results[i].Err != nil {
			d.logger.WarnContext(ctx, "republish failed",
				slog.String("target", results[i].Target.Type),
				slog.String("error", results[i].Err.Error()),
			)
		}
	}
}

// ===== CardService =====

// ProvisionCard implements wire.Backend.
func (d *Daemon) ProvisionCard(ctx context.Context, token string, opts wire.ProvisionCardOpts) (gpg.YubiKeyEntry, string, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return gpg.YubiKeyEntry{}, "", err
	}
	vaultName := se.entry.Name
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	cfg, err := client.LoadConfig()
	if err != nil {
		return gpg.YubiKeyEntry{}, "", fmt.Errorf("provision card: load config: %w", err)
	}

	if err := client.GenerateSubkeys(ctx, gpg.SubkeyOpts{
		MasterFP: cfg.MasterFP,
		Algo:     cfg.SubkeyAlgo,
		Expiry:   cfg.SubkeyExpiry,
	}); err != nil {
		return gpg.YubiKeyEntry{}, "", fmt.Errorf("provision card: generate subkeys: %w", err)
	}

	keys, err := client.ListSecretKeys(ctx)
	if err != nil {
		return gpg.YubiKeyEntry{}, "", fmt.Errorf("provision card: list keys: %w", err)
	}
	keyIDs := gpg.LatestSubkeyIDs(keys)
	if len(keyIDs) == 0 {
		return gpg.YubiKeyEntry{}, "", fmt.Errorf("provision card: no S/E/A subkeys")
	}
	if err := client.MoveToCard(ctx, cfg.MasterFP, keyIDs); err != nil {
		return gpg.YubiKeyEntry{}, "", fmt.Errorf("provision card: %w", err)
	}

	d.republish(ctx, client, cfg.MasterFP)
	sshPath, _ := client.ExportSSHPubKey(ctx, cfg.MasterFP)

	info, cardErr := client.CardStatus(ctx)
	if cardErr != nil {
		return gpg.YubiKeyEntry{}, "", fmt.Errorf("provision card: card status: %w", cardErr)
	}

	mode := "same-keys"
	if opts.UniqueKeys {
		mode = "unique-keys"
	}

	moved := make(map[string]struct{}, len(keyIDs))
	for _, id := range keyIDs {
		moved[id] = struct{}{}
	}
	var subkeys []gpg.SubKeyRef
	for i := range keys {
		if _, ok := moved[keys[i].KeyID]; !ok {
			continue
		}
		subkeys = append(subkeys, gpg.SubKeyRef{
			KeyID:   keys[i].KeyID,
			Usage:   gpg.UsageLabel(keys[i].Usage),
			Created: keys[i].Created,
			Expires: keys[i].Expires,
		})
	}

	entry := gpg.YubiKeyEntry{
		Serial:        info.Serial,
		Label:         opts.Label,
		Model:         info.Model,
		Description:   opts.Description,
		Provisioning:  mode,
		Subkeys:       subkeys,
		ProvisionedAt: time.Now().UTC(),
		Status:        "active",
	}
	inv, _ := client.LoadInventory()
	if inv == nil {
		inv = &gpg.Inventory{}
	}
	inv.YubiKeys = append(inv.YubiKeys, entry)
	if err := client.SaveInventory(inv); err != nil {
		return gpg.YubiKeyEntry{}, "", fmt.Errorf("provision card: save inventory: %w", err)
	}

	se.session.MarkChanged()
	_ = audit.Append(client.HomeDir(), audit.Entry{
		Action:   "provision-card",
		Details:  fmt.Sprintf("provisioned %s as %q", info.Serial, opts.Label),
		Metadata: map[string]string{"serial": info.Serial, "label": opts.Label, "mode": mode},
	})

	d.touchLocked(se)
	d.publishEvent(vaultName, wire.EventKindStateChanged, "card provisioned")
	return entry, sshPath, nil
}

// RotateCard implements wire.Backend.
func (d *Daemon) RotateCard(ctx context.Context, token, label string) (gpg.YubiKeyEntry, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return gpg.YubiKeyEntry{}, err
	}
	vaultName := se.entry.Name
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	cfg, err := client.LoadConfig()
	if err != nil {
		return gpg.YubiKeyEntry{}, fmt.Errorf("rotate card: load config: %w", err)
	}
	inv, err := client.LoadInventory()
	if err != nil {
		return gpg.YubiKeyEntry{}, fmt.Errorf("rotate card: load inventory: %w", err)
	}
	entry := inv.FindByLabel(label)
	if entry == nil {
		return gpg.YubiKeyEntry{}, fmt.Errorf("rotate card: %q not found", label)
	}

	for i := range entry.Subkeys {
		if err := client.Revoke(ctx, cfg.MasterFP, entry.Subkeys[i].KeyID); err != nil {
			return gpg.YubiKeyEntry{}, fmt.Errorf("rotate card: revoke %s: %w", entry.Subkeys[i].KeyID, err)
		}
	}
	if err := client.GenerateSubkeys(ctx, gpg.SubkeyOpts{
		MasterFP: cfg.MasterFP,
		Algo:     cfg.SubkeyAlgo,
		Expiry:   cfg.SubkeyExpiry,
	}); err != nil {
		return gpg.YubiKeyEntry{}, fmt.Errorf("rotate card: generate: %w", err)
	}
	keys, err := client.ListSecretKeys(ctx)
	if err != nil {
		return gpg.YubiKeyEntry{}, fmt.Errorf("rotate card: list keys: %w", err)
	}
	keyIDs := gpg.LatestSubkeyIDs(keys)
	if len(keyIDs) == 0 {
		return gpg.YubiKeyEntry{}, fmt.Errorf("rotate card: no S/E/A subkeys")
	}
	if err := client.MoveToCard(ctx, cfg.MasterFP, keyIDs); err != nil {
		return gpg.YubiKeyEntry{}, fmt.Errorf("rotate card: to-card: %w", err)
	}

	d.republish(ctx, client, cfg.MasterFP)
	_, _ = client.ExportSSHPubKey(ctx, cfg.MasterFP)

	moved := make(map[string]struct{}, len(keyIDs))
	for _, id := range keyIDs {
		moved[id] = struct{}{}
	}
	var newSubs []gpg.SubKeyRef
	for i := range keys {
		if _, ok := moved[keys[i].KeyID]; !ok {
			continue
		}
		newSubs = append(newSubs, gpg.SubKeyRef{
			KeyID:   keys[i].KeyID,
			Usage:   gpg.UsageLabel(keys[i].Usage),
			Created: keys[i].Created,
			Expires: keys[i].Expires,
		})
	}
	entry.Subkeys = newSubs
	if err := client.SaveInventory(inv); err != nil {
		return gpg.YubiKeyEntry{}, fmt.Errorf("rotate card: save inventory: %w", err)
	}

	se.session.MarkChanged()
	_ = audit.Append(client.HomeDir(), audit.Entry{
		Action:   "rotate-card",
		Details:  fmt.Sprintf("rotated %q (%s)", label, entry.Serial),
		Metadata: map[string]string{"serial": entry.Serial, "label": label},
	})

	d.touchLocked(se)
	d.publishEvent(vaultName, wire.EventKindStateChanged, "card rotated")
	return *entry, nil
}

// RevokeCard implements wire.Backend.
func (d *Daemon) RevokeCard(ctx context.Context, token, label string) error {
	se, err := d.lookupSession(token)
	if err != nil {
		return err
	}
	vaultName := se.entry.Name
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	cfg, err := client.LoadConfig()
	if err != nil {
		return fmt.Errorf("revoke card: load config: %w", err)
	}
	inv, err := client.LoadInventory()
	if err != nil {
		return fmt.Errorf("revoke card: load inventory: %w", err)
	}
	entry := inv.FindByLabel(label)
	if entry == nil {
		return fmt.Errorf("revoke card: %q not found", label)
	}
	for i := range entry.Subkeys {
		if err := client.Revoke(ctx, cfg.MasterFP, entry.Subkeys[i].KeyID); err != nil {
			return fmt.Errorf("revoke card: revoke %s: %w", entry.Subkeys[i].KeyID, err)
		}
	}
	entry.Status = "revoked"
	if err := client.SaveInventory(inv); err != nil {
		return fmt.Errorf("revoke card: save inventory: %w", err)
	}
	d.republish(ctx, client, cfg.MasterFP)

	se.session.MarkChanged()
	_ = audit.Append(client.HomeDir(), audit.Entry{
		Action:   "revoke-card",
		Details:  fmt.Sprintf("revoked %q (%s)", label, entry.Serial),
		Metadata: map[string]string{"serial": entry.Serial, "label": label},
	})
	d.touchLocked(se)
	d.publishEvent(vaultName, wire.EventKindStateChanged, "card revoked")
	return nil
}

// CardInventory implements wire.Backend.
func (d *Daemon) CardInventory(_ context.Context, token string) ([]gpg.YubiKeyEntry, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return nil, err
	}
	se.mu.Lock()
	defer se.mu.Unlock()
	d.touchLocked(se)

	inv, err := se.session.GPG.LoadInventory()
	if err != nil {
		return nil, err
	}
	return inv.YubiKeys, nil
}

// DiscoverCard implements wire.Backend.
func (d *Daemon) DiscoverCard(ctx context.Context, token, label, description string) (gpg.YubiKeyEntry, bool, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return gpg.YubiKeyEntry{}, false, err
	}
	vaultName := se.entry.Name
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	entry, err := client.DiscoverCard(ctx)
	if err != nil {
		return gpg.YubiKeyEntry{}, false, err
	}
	inv, err := client.LoadInventory()
	if err != nil {
		return gpg.YubiKeyEntry{}, false, fmt.Errorf("discover card: load inventory: %w", err)
	}
	if existing := inv.FindByLabel(entry.Serial); existing != nil {
		existing.Subkeys = entry.Subkeys
		if entry.Model != "" && existing.Model == "" {
			existing.Model = entry.Model
		}
		if err := client.SaveInventory(inv); err != nil {
			return gpg.YubiKeyEntry{}, true, fmt.Errorf("discover card: save inventory: %w", err)
		}
		d.touchLocked(se)
		return *existing, true, nil
	}
	if label != "" {
		entry.Label = label
	}
	if description != "" {
		entry.Description = description
	}
	inv.YubiKeys = append(inv.YubiKeys, *entry)
	if err := client.SaveInventory(inv); err != nil {
		return gpg.YubiKeyEntry{}, false, fmt.Errorf("discover card: save inventory: %w", err)
	}
	se.session.MarkChanged()
	d.touchLocked(se)
	d.publishEvent(vaultName, wire.EventKindStateChanged, "card discovered")
	return *entry, false, nil
}

// ===== ServerService =====

// ListPublishServers implements wire.Backend.
func (d *Daemon) ListPublishServers(_ context.Context, token string) ([]gpg.ServerEntry, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return nil, err
	}
	se.mu.Lock()
	defer se.mu.Unlock()
	d.touchLocked(se)
	reg, err := se.session.GPG.LoadServerRegistry()
	if err != nil {
		return nil, err
	}
	return reg.Servers, nil
}

// AddPublishServer implements wire.Backend.
func (d *Daemon) AddPublishServer(_ context.Context, token, alias, url string) error {
	se, err := d.lookupSession(token)
	if err != nil {
		return err
	}
	if err := gpg.ValidateServerAlias(alias); err != nil {
		return err
	}
	se.mu.Lock()
	defer se.mu.Unlock()
	client := se.session.GPG
	reg, err := client.LoadServerRegistry()
	if err != nil {
		return err
	}
	if reg.FindByAlias(alias) != nil {
		return fmt.Errorf("server %q already exists", alias)
	}
	reg.Servers = append(reg.Servers, gpg.ServerEntry{
		Alias:   alias,
		Type:    gpg.TargetTypeKeyserver,
		URL:     url,
		Enabled: true,
	})
	if err := client.SaveServerRegistry(reg); err != nil {
		return err
	}
	se.session.MarkChanged()
	d.touchLocked(se)
	return nil
}

// RemovePublishServer implements wire.Backend.
func (d *Daemon) RemovePublishServer(_ context.Context, token, alias string) error {
	se, err := d.lookupSession(token)
	if err != nil {
		return err
	}
	se.mu.Lock()
	defer se.mu.Unlock()
	client := se.session.GPG
	reg, err := client.LoadServerRegistry()
	if err != nil {
		return err
	}
	out := reg.Servers[:0]
	found := false
	for i := range reg.Servers {
		if reg.Servers[i].Alias == alias {
			found = true
			continue
		}
		out = append(out, reg.Servers[i])
	}
	if !found {
		return fmt.Errorf("server %q not found", alias)
	}
	reg.Servers = out
	if err := client.SaveServerRegistry(reg); err != nil {
		return err
	}
	se.session.MarkChanged()
	d.touchLocked(se)
	return nil
}

// EnablePublishServer implements wire.Backend.
func (d *Daemon) EnablePublishServer(_ context.Context, token, alias string) error {
	return d.setPublishEnabled(token, alias, true)
}

// DisablePublishServer implements wire.Backend.
func (d *Daemon) DisablePublishServer(_ context.Context, token, alias string) error {
	return d.setPublishEnabled(token, alias, false)
}

func (d *Daemon) setPublishEnabled(token, alias string, enabled bool) error {
	se, err := d.lookupSession(token)
	if err != nil {
		return err
	}
	se.mu.Lock()
	defer se.mu.Unlock()
	client := se.session.GPG
	reg, err := client.LoadServerRegistry()
	if err != nil {
		return err
	}
	entry := reg.FindByAlias(alias)
	if entry == nil {
		return fmt.Errorf("server %q not found", alias)
	}
	entry.Enabled = enabled
	if err := client.SaveServerRegistry(reg); err != nil {
		return err
	}
	se.session.MarkChanged()
	d.touchLocked(se)
	return nil
}

// Publish implements wire.Backend.
func (d *Daemon) Publish(ctx context.Context, token string, aliases []string) ([]wire.PublishResult, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return nil, err
	}
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	cfg, err := client.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("publish: load config: %w", err)
	}
	reg, err := client.LoadServerRegistry()
	if err != nil {
		return nil, err
	}

	var servers []gpg.ServerEntry
	if len(aliases) > 0 {
		for _, alias := range aliases {
			entry := reg.FindByAlias(alias)
			if entry == nil {
				return nil, fmt.Errorf("publish: unknown server %q", alias)
			}
			servers = append(servers, *entry)
		}
	} else {
		servers = reg.EnabledServers()
	}

	targets := gpg.ToPublishTargets(servers)
	results := client.Publish(ctx, cfg.MasterFP, targets)

	out := make([]wire.PublishResult, len(results))
	var published []string
	for i := range results {
		out[i] = wire.PublishResult{
			Alias:   servers[i].Alias,
			Success: results[i].Err == nil,
		}
		if results[i].Err != nil {
			out[i].Error = results[i].Err.Error()
		} else {
			published = append(published, servers[i].Alias)
		}
	}
	if len(published) > 0 {
		_ = audit.Append(client.HomeDir(), audit.Entry{
			Action:  "publish",
			Details: fmt.Sprintf("published to %d servers", len(published)),
		})
	}
	d.touchLocked(se)
	return out, nil
}

// LookupPublished implements wire.Backend.
func (d *Daemon) LookupPublished(ctx context.Context, token string) ([]wire.LookupResult, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return nil, err
	}
	se.mu.Lock()
	defer se.mu.Unlock()

	client := se.session.GPG
	cfg, err := client.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("lookup: load config: %w", err)
	}
	reg, err := client.LoadServerRegistry()
	if err != nil {
		return nil, err
	}
	urls := reg.AllServerURLs()
	results := client.LookupKeyservers(ctx, cfg.MasterFP, urls)
	out := make([]wire.LookupResult, 0, len(results))
	for i := range results {
		status := "found"
		if !results[i].Found {
			status = "not found"
		}
		out = append(out, wire.LookupResult{
			URL:    results[i].URL,
			Status: status,
		})
	}
	d.touchLocked(se)
	return out, nil
}

// ===== AuditService =====

// ShowAudit implements wire.Backend.
func (d *Daemon) ShowAudit(_ context.Context, token string, last int) ([]audit.Entry, error) {
	se, err := d.lookupSession(token)
	if err != nil {
		return nil, err
	}
	se.mu.Lock()
	defer se.mu.Unlock()
	d.touchLocked(se)
	entries, err := audit.Load(se.session.GPG.HomeDir())
	if err != nil {
		return nil, err
	}
	if last > 0 && last < len(entries) {
		entries = entries[len(entries)-last:]
	}
	return entries, nil
}

// ===== EventService =====

// SubscribeEvents implements wire.Backend. Returns a channel that
// receives events. If token names an open session the channel is
// filtered to that vault; if token is empty the subscriber sees all
// events. The channel is closed when ctx is canceled or the daemon is
// shutting down.
func (d *Daemon) SubscribeEvents(ctx context.Context, token string) (<-chan wire.Event, error) {
	topic := "*"
	if vaultName := d.vaultNameFromToken(token); vaultName != "" {
		topic = "vault:" + vaultName
	}
	const subBuf = 32
	_, ptrCh, unsubscribe := d.broker.Subscribe(topic, subBuf)

	out := make(chan wire.Event, subBuf)
	go func() {
		defer close(out)
		defer unsubscribe()
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-ptrCh:
				if !ok {
					return
				}
				if evt == nil {
					continue
				}
				select {
				case out <- *evt:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}
