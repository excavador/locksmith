package gpgsmith

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/excavador/locksmith/pkg/gpg"
	"github.com/excavador/locksmith/pkg/vault"
)

type (
	// Session is the in-memory representation of an open vault. It owns the
	// decrypted GNUPGHOME workdir, an authenticated GPG client, the
	// heartbeat goroutine that keeps the on-disk liveness sidecar fresh,
	// and a mutation generation counter that drives periodic re-flush of
	// the encrypted .session-<host> ephemeral state file.
	//
	// A Session is created via OpenSession (open the latest canonical) or
	// ResumeSession (resume from an existing .session-<host> ephemeral).
	// It is ended via Seal (write a new canonical) or Discard (throw away
	// the work). Both end-paths stop the heartbeat goroutine, delete the
	// on-disk ephemeral pair, and remove the workdir from /dev/shm.
	//
	// AutoSealAndDrop is a third end-path triggered by an idle timeout. It
	// flushes the workdir to the encrypted ephemeral file, drops the
	// in-memory state, and stops heartbeating — but leaves the
	// .session-<host> and .info files on disk so the next OpenSession on
	// the same vault can offer to resume.
	//
	// Session is safe for concurrent use by multiple goroutines: mutation
	// counters are atomic, the heartbeat goroutine never reads or writes
	// the workdir on its own, and Seal/Discard are protected by an
	// internal mutex.
	Session struct {
		Vault    *vault.Vault
		Entry    *vault.Entry
		Source   LockSource
		Hostname string
		Logger   *slog.Logger

		Workdir       string
		GPG           *gpg.Client
		SourceSnap    *vault.Snapshot // the canonical the session was opened from
		StartedAt     time.Time
		CanonicalBase string // base filename of SourceSnap; used to derive ephemeral paths

		// TOFU result. ConfiguredMasterFP is the master_fp read from the
		// decrypted gpgsmith.yaml inside the workdir, or "" if no key has
		// been generated yet.
		ConfiguredMasterFP string

		ephemeralStatePath string
		ephemeralInfoPath  string

		generation    atomic.Uint64
		lastFlushed   atomic.Uint64
		heartbeatStop chan struct{}
		heartbeatDone chan struct{}

		mu     sync.Mutex
		closed bool
	}

	// SessionOpts configures how a session is opened.
	SessionOpts struct {
		// Source identifies which frontend is opening this session.
		Source LockSource

		// Logger receives kernel-level structured logs. Defaults to
		// slog.Default().
		Logger *slog.Logger

		// HeartbeatInterval overrides the default heartbeat tick. Mainly
		// for tests; production callers should leave this zero (uses
		// DefaultHeartbeatInterval).
		HeartbeatInterval time.Duration
	}

	// OpenSessionResult is returned by OpenSession. It carries the Session
	// and side-channel information about TOFU first-use, which the caller
	// is responsible for persisting back to the vault registry config.
	OpenSessionResult struct {
		Session *Session

		// TOFUFingerprint is non-empty when this is the first time we've
		// seen a master fingerprint for this vault and the caller should
		// persist it into the vault registry's TrustedMasterFP field. It
		// is empty when:
		//   - The Entry already had a TrustedMasterFP and it matched.
		//   - The decrypted vault has no gpgsmith.yaml yet (no master key
		//     generated; nothing to TOFU on).
		TOFUFingerprint string
	}

	// MasterKeyMismatchError is returned by OpenSession (and ResumeSession)
	// when the master fingerprint embedded in the decrypted vault does not
	// match the trusted fingerprint recorded in the vault registry. This is
	// the loud security signal: either an attacker substituted the snapshot
	// or the user rotated their master key without updating the trust
	// anchor.
	MasterKeyMismatchError struct {
		VaultName string
		Expected  string // from vault.Entry.TrustedMasterFP
		Found     string // from gpgsmith.yaml inside the decrypted snapshot
		Snapshot  string // basename of the snapshot the embedded fp was read from
	}
)

// Error implements the error interface.
func (e *MasterKeyMismatchError) Error() string {
	return fmt.Sprintf(
		"vault %q: master key mismatch — expected %s, found %s in %s\n"+
			"This snapshot was either replaced by an attacker with write access "+
			"to the vault directory, or generated from a fresh setup that "+
			"overwrote your real vault.\n"+
			"If you legitimately rotated your master key, update the trust "+
			"anchor with: gpgsmith vault trust %s %s",
		e.VaultName, e.Expected, e.Found, e.Snapshot,
		e.VaultName, e.Found,
	)
}

// IsMasterKeyMismatch reports whether err is a MasterKeyMismatchError.
func IsMasterKeyMismatch(err error) bool {
	var m *MasterKeyMismatchError
	return errors.As(err, &m)
}

const (
	// DefaultHeartbeatInterval is the production tick rate for the .info
	// liveness sidecar. Tests pass a smaller value via SessionOpts.
	DefaultHeartbeatInterval = HeartbeatInterval

	// flushTimeout caps how long a single heartbeat tick may take to
	// re-flush the encrypted ephemeral state to disk.
	flushTimeout = 30 * time.Second
)

// OpenSession decrypts the latest canonical snapshot of the resolved vault
// entry and prepares an in-memory Session ready for operations. It:
//
//  1. Calls v.Open(ctx) to decrypt the latest snapshot into a tmpfs workdir
//  2. Writes gpg.conf and gpg-agent.conf into the workdir for loopback
//     pinentry mode
//  3. Constructs a gpg.Client wired to the workdir and the vault passphrase
//  4. Reads the embedded gpgsmith.yaml and performs TOFU on master_fp:
//     - If entry.TrustedMasterFP is empty, populate it (returned in
//     OpenSessionResult.TOFUFingerprint)
//     - If non-empty and matches, OK
//     - If non-empty and mismatches, refuse with MasterKeyMismatchError
//  5. Computes the ephemeral file paths from the source canonical filename
//     and the local hostname
//  6. Writes the initial .info sidecar with status=active and the current
//     heartbeat timestamp
//  7. Starts the heartbeat goroutine
//
// On any failure after the workdir is decrypted, the workdir is removed
// and any partially-written ephemeral files are cleaned up.
func OpenSession(
	ctx context.Context,
	v *vault.Vault,
	entry *vault.Entry,
	opts SessionOpts,
) (*OpenSessionResult, error) {
	if v == nil {
		return nil, fmt.Errorf("open session: vault is required")
	}
	if entry == nil {
		return nil, fmt.Errorf("open session: entry is required")
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	workdir, snap, err := v.Open(ctx)
	if err != nil {
		return nil, fmt.Errorf("open session: %w", err)
	}

	// From here on, any error must clean up the workdir.
	cleanup := func() {
		if discardErr := v.Discard(ctx, workdir); discardErr != nil {
			logger.WarnContext(ctx, "open session: cleanup workdir failed",
				slog.String("workdir", workdir),
				slog.String("error", discardErr.Error()),
			)
		}
	}

	if err := gpg.WriteAgentConfig(workdir); err != nil {
		cleanup()
		return nil, fmt.Errorf("open session: configure gpg agent: %w", err)
	}

	client, err := gpg.New(gpg.Options{
		HomeDir:    workdir,
		Logger:     logger,
		Passphrase: v.Passphrase(),
	})
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("open session: gpg client: %w", err)
	}

	configuredFP, err := readMasterFP(workdir)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("open session: read master fp: %w", err)
	}

	// TOFU check.
	var tofuFP string
	switch {
	case entry.TrustedMasterFP == "" && configuredFP != "":
		// First-use: trust the fingerprint, return it for the caller to persist.
		tofuFP = configuredFP
		logger.InfoContext(ctx, "vault TOFU first-use",
			slog.String("vault", entry.Name),
			slog.String("master_fp", configuredFP),
		)
	case entry.TrustedMasterFP != "" && configuredFP != "" && entry.TrustedMasterFP != configuredFP:
		// Mismatch: refuse loudly.
		cleanup()
		return nil, &MasterKeyMismatchError{
			VaultName: entry.Name,
			Expected:  entry.TrustedMasterFP,
			Found:     configuredFP,
			Snapshot:  filepath.Base(snap.Path),
		}
	}

	canonicalBase := filepath.Base(snap.Path)
	statePath, infoPath := SessionFilenamesFor(canonicalBase, hostname)

	s := &Session{
		Vault:              v,
		Entry:              entry,
		Source:             opts.Source,
		Hostname:           hostname,
		Logger:             logger,
		Workdir:            workdir,
		GPG:                client,
		SourceSnap:         &snap,
		StartedAt:          time.Now().UTC(),
		CanonicalBase:      canonicalBase,
		ConfiguredMasterFP: configuredFP,
		ephemeralStatePath: filepath.Join(entry.Path, statePath),
		ephemeralInfoPath:  filepath.Join(entry.Path, infoPath),
		heartbeatStop:      make(chan struct{}),
		heartbeatDone:      make(chan struct{}),
	}

	// Write the initial .info immediately so other gpgsmith processes (and
	// other hosts via Dropbox sync) see "session in progress" the moment we
	// open. The .session-<host> encrypted state file is NOT written yet —
	// the workdir hasn't been mutated, so there's nothing to flush.
	if err := s.writeInfo(EphemeralStatusActive); err != nil {
		cleanup()
		return nil, fmt.Errorf("open session: write initial info: %w", err)
	}

	interval := opts.HeartbeatInterval
	if interval == 0 {
		interval = DefaultHeartbeatInterval
	}
	go s.heartbeatLoop(interval)

	logger.InfoContext(ctx, "session opened",
		slog.String("vault", entry.Name),
		slog.String("workdir", workdir),
		slog.String("opened_by", string(opts.Source)),
	)

	return &OpenSessionResult{
		Session:         s,
		TOFUFingerprint: tofuFP,
	}, nil
}

// MarkChanged increments the mutation generation counter. The next heartbeat
// tick will detect the change and re-flush the workdir to the encrypted
// .session-<host> ephemeral file. Mutation operations on the kernel API
// (key generation, identity add, etc.) call this after a successful change.
//
// Safe to call from any goroutine.
func (s *Session) MarkChanged() {
	s.generation.Add(1)
}

// Generation returns the current mutation generation. Useful for tests.
func (s *Session) Generation() uint64 {
	return s.generation.Load()
}

// Seal explicitly writes the workdir as a new canonical snapshot, deletes
// the ephemeral file pair, stops the heartbeat goroutine, and frees all
// in-memory state. After Seal returns, the Session is unusable.
func (s *Session) Seal(ctx context.Context, message string) (*vault.Snapshot, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("session: already ended")
	}
	s.closed = true
	s.mu.Unlock()

	s.stopHeartbeat()

	snap, err := s.Vault.Seal(ctx, s.Workdir, message)
	if err != nil {
		return nil, fmt.Errorf("seal session: %w", err)
	}

	if cleanupErr := DeleteEphemeralFiles(s.ephemeralStatePath, s.ephemeralInfoPath); cleanupErr != nil {
		s.Logger.WarnContext(ctx, "seal session: ephemeral cleanup failed",
			slog.String("error", cleanupErr.Error()),
		)
	}

	s.Logger.InfoContext(ctx, "session sealed",
		slog.String("vault", s.Entry.Name),
		slog.String("snapshot", filepath.Base(snap.Path)),
	)

	return &snap, nil
}

// Discard explicitly throws away the workdir and the ephemeral file pair
// without writing a new canonical snapshot. After Discard returns, the
// Session is unusable.
func (s *Session) Discard(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("session: already ended")
	}
	s.closed = true
	s.mu.Unlock()

	s.stopHeartbeat()

	if cleanupErr := DeleteEphemeralFiles(s.ephemeralStatePath, s.ephemeralInfoPath); cleanupErr != nil {
		s.Logger.WarnContext(ctx, "discard session: ephemeral cleanup failed",
			slog.String("error", cleanupErr.Error()),
		)
	}

	if err := s.Vault.Discard(ctx, s.Workdir); err != nil {
		return fmt.Errorf("discard session: %w", err)
	}

	s.Logger.InfoContext(ctx, "session discarded",
		slog.String("vault", s.Entry.Name),
	)

	return nil
}

// AutoSealAndDrop is the idle-timeout end-path. It does NOT write a new
// canonical snapshot — the work-in-progress remains in the encrypted
// .session-<host> ephemeral file on disk, ready for the next OpenSession
// on this vault to offer as a resume option.
//
// Specifically, AutoSealAndDrop:
//  1. Forces a final flush of the workdir to the encrypted ephemeral file
//  2. Marks the .info sidecar status as idle-sealed
//  3. Stops the heartbeat goroutine
//  4. Removes the workdir from tmpfs
//  5. Marks the Session as closed (any further method call returns an error)
//
// The .session-<host> and .info files remain on disk. The next attempt to
// open the vault will detect them and prompt to resume.
func (s *Session) AutoSealAndDrop(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("session: already ended")
	}
	s.closed = true
	s.mu.Unlock()

	// Force a final flush even if generation is unchanged — we want the
	// .session-<host> file to exist on disk for the resume path.
	if err := s.flushEphemeralState(ctx); err != nil {
		return fmt.Errorf("auto seal: flush state: %w", err)
	}
	if err := s.writeInfo(EphemeralStatusIdleSealed); err != nil {
		return fmt.Errorf("auto seal: mark info: %w", err)
	}

	s.stopHeartbeat()

	// Remove the in-memory workdir; the encrypted state lives on disk now.
	if err := s.Vault.Discard(ctx, s.Workdir); err != nil {
		return fmt.Errorf("auto seal: drop workdir: %w", err)
	}

	s.Logger.InfoContext(ctx, "session auto-sealed and dropped",
		slog.String("vault", s.Entry.Name),
		slog.String("ephemeral", filepath.Base(s.ephemeralStatePath)),
	)
	return nil
}

// IsClosed reports whether the Session has been ended via Seal, Discard,
// or AutoSealAndDrop.
func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// stopHeartbeat signals the heartbeat goroutine to exit and waits for it.
// Safe to call multiple times.
func (s *Session) stopHeartbeat() {
	select {
	case <-s.heartbeatStop:
		// Already stopped.
	default:
		close(s.heartbeatStop)
	}
	<-s.heartbeatDone
}

// heartbeatLoop runs as a goroutine for the lifetime of the Session, ticking
// every interval. On each tick it updates the .info sidecar with a fresh
// last_heartbeat timestamp, and if the mutation generation has advanced
// since the last flush, it re-encrypts the workdir to the .session-<host>
// ephemeral state file.
func (s *Session) heartbeatLoop(interval time.Duration) {
	defer close(s.heartbeatDone)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.heartbeatStop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
			if err := s.heartbeatTick(ctx); err != nil {
				s.Logger.WarnContext(ctx, "session heartbeat tick failed",
					slog.String("error", err.Error()),
				)
			}
			cancel()
		}
	}
}

// heartbeatTick performs one heartbeat: refresh .info, and if the mutation
// generation has changed, re-flush the encrypted ephemeral state. Internal.
func (s *Session) heartbeatTick(ctx context.Context) error {
	currentGen := s.generation.Load()
	if currentGen != s.lastFlushed.Load() {
		if err := s.flushEphemeralState(ctx); err != nil {
			return fmt.Errorf("heartbeat: flush state: %w", err)
		}
	}
	if err := s.writeInfo(EphemeralStatusActive); err != nil {
		return fmt.Errorf("heartbeat: write info: %w", err)
	}
	return nil
}

// flushEphemeralState tars and encrypts the current workdir into the
// .session-<host> file alongside the canonical snapshots. The vault.Vault
// is reused for this — the encryption identity is the same as for canonical
// snapshots, so the on-disk format and key are identical.
func (s *Session) flushEphemeralState(ctx context.Context) error {
	gen := s.generation.Load()
	if err := s.Vault.SealEphemeral(ctx, s.Workdir, s.ephemeralStatePath); err != nil {
		return fmt.Errorf("flush ephemeral: %w", err)
	}
	s.lastFlushed.Store(gen)
	return nil
}

// writeInfo updates the .info sidecar with the current heartbeat timestamp,
// generation counter, and the supplied status.
func (s *Session) writeInfo(status EphemeralStatus) error {
	info := &EphemeralInfo{
		Hostname:      s.Hostname,
		Source:        s.Source,
		StartedAt:     s.StartedAt,
		LastHeartbeat: time.Now().UTC(),
		Generation:    s.generation.Load(),
		Status:        status,
	}
	return WriteEphemeralInfo(s.ephemeralInfoPath, info)
}

// readMasterFP reads workdir/gpgsmith.yaml and returns the master_fp field.
// Returns ("", nil) if the file does not exist (no key generated yet).
func readMasterFP(workdir string) (string, error) {
	cfgPath := filepath.Join(workdir, "gpgsmith.yaml")
	if _, err := os.Stat(cfgPath); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	// We use the gpg package's Config loader for parsing.
	client, err := gpg.New(gpg.Options{HomeDir: workdir})
	if err != nil {
		return "", err
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return "", err
	}
	return cfg.MasterFP, nil
}
