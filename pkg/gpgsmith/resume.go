package gpgsmith

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/excavador/locksmith/pkg/gpg"
	"github.com/excavador/locksmith/pkg/vault"
)

// ResumeSession is the resume-from-ephemeral counterpart to OpenSession.
//
// Where OpenSession decrypts the latest canonical snapshot, ResumeSession
// decrypts the previously-flushed .session-<host> ephemeral state file
// pointed to by eph and uses that as the workdir. This recovers an
// in-progress session that was put to rest by AutoSealAndDrop or by an
// earlier crash, restoring the exact mutation state that was on disk at
// the time of the last heartbeat-flush.
//
// On success the on-disk ephemeral file pair is deleted (the new in-memory
// session takes over ownership of those bytes), the .info sidecar is
// rewritten in active state, and the heartbeat goroutine is started.
//
// On failure no ephemeral files are touched, so a subsequent attempt can
// retry the resume.
func ResumeSession(
	ctx context.Context,
	v *vault.Vault,
	entry *vault.Entry,
	eph *Ephemeral,
	opts SessionOpts,
) (*OpenSessionResult, error) {
	if v == nil {
		return nil, fmt.Errorf("resume session: vault is required")
	}
	if entry == nil {
		return nil, fmt.Errorf("resume session: entry is required")
	}
	if eph == nil {
		return nil, fmt.Errorf("resume session: ephemeral is required")
	}
	if eph.SessionPath == "" {
		return nil, fmt.Errorf(
			"resume session: nothing to resume — the .info sidecar for %q exists but no encrypted state file is on disk. "+
				"This usually means a prior session was killed before it flushed any mutations. "+
				"Discard the orphan .info (or retry `vault open` to overwrite it with a fresh session)",
			filepath.Base(eph.InfoPath),
		)
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	workdir, err := v.DecryptFile(ctx, eph.SessionPath)
	if err != nil {
		return nil, fmt.Errorf("resume session: decrypt ephemeral: %w", err)
	}

	cleanup := func() {
		if discardErr := v.Discard(ctx, workdir); discardErr != nil {
			logger.WarnContext(ctx, "resume session: cleanup workdir failed",
				slog.String("workdir", workdir),
				slog.String("error", discardErr.Error()),
			)
		}
	}

	if err := gpg.WriteAgentConfig(workdir); err != nil {
		cleanup()
		return nil, fmt.Errorf("resume session: configure gpg agent: %w", err)
	}

	client, err := gpg.New(gpg.Options{
		HomeDir:    workdir,
		Logger:     logger,
		Passphrase: v.Passphrase(),
	})
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("resume session: gpg client: %w", err)
	}

	configuredFP, err := readMasterFP(workdir)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("resume session: read master fp: %w", err)
	}

	var tofuFP string
	switch {
	case entry.TrustedMasterFP == "" && configuredFP != "":
		tofuFP = configuredFP
		logger.InfoContext(ctx, "vault TOFU first-use on resume",
			slog.String("vault", entry.Name),
			slog.String("master_fp", configuredFP),
		)
	case entry.TrustedMasterFP != "" && configuredFP != "" && entry.TrustedMasterFP != configuredFP:
		cleanup()
		return nil, &MasterKeyMismatchError{
			VaultName: entry.Name,
			Expected:  entry.TrustedMasterFP,
			Found:     configuredFP,
			Snapshot:  filepath.Base(eph.SessionPath),
		}
	}

	statePath, infoPath := SessionFilenamesFor(eph.CanonicalBase, hostname)

	s := &Session{
		Vault:              v,
		Entry:              entry,
		Source:             opts.Source,
		Hostname:           hostname,
		Logger:             logger,
		Workdir:            workdir,
		GPG:                client,
		StartedAt:          time.Now().UTC(),
		CanonicalBase:      eph.CanonicalBase,
		ConfiguredMasterFP: configuredFP,
		ephemeralStatePath: filepath.Join(entry.Path, statePath),
		ephemeralInfoPath:  filepath.Join(entry.Path, infoPath),
		heartbeatStop:      make(chan struct{}),
		heartbeatDone:      make(chan struct{}),
	}

	// Best-effort: remove old ephemeral pair on disk now that we've taken
	// ownership in memory. The new heartbeat goroutine will recreate them.
	if cleanupErr := DeleteEphemeralFiles(eph.SessionPath, eph.InfoPath); cleanupErr != nil {
		logger.WarnContext(ctx, "resume session: removing prior ephemeral failed",
			slog.String("error", cleanupErr.Error()),
		)
	}

	if err := s.writeInfo(EphemeralStatusActive); err != nil {
		cleanup()
		return nil, fmt.Errorf("resume session: write info: %w", err)
	}

	interval := opts.HeartbeatInterval
	if interval == 0 {
		interval = DefaultHeartbeatInterval
	}
	go s.heartbeatLoop(interval)

	logger.InfoContext(ctx, "session resumed",
		slog.String("vault", entry.Name),
		slog.String("workdir", workdir),
		slog.String("opened_by", string(opts.Source)),
	)

	return &OpenSessionResult{
		Session:         s,
		TOFUFingerprint: tofuFP,
	}, nil
}
