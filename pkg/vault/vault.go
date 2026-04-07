package vault

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"filippo.io/age"
)

type (
	// Snapshot represents a single encrypted vault snapshot.
	Snapshot struct {
		Path      string
		Timestamp time.Time
		Message   string
	}

	// Vault manages encrypted, append-only snapshots.
	Vault struct {
		dir        string
		identity   age.Identity
		passphrase string // non-empty when using passphrase-based encryption
		logger     *slog.Logger
	}
)

var (
	// snapshotFilenameRe matches filenames like 20260101T000000Z_some-message.tar.age
	snapshotFilenameRe = regexp.MustCompile(
		`^(\d{4}\d{2}\d{2}T\d{6}Z)_(.+)\.tar\.age$`,
	)
)

const (
	snapshotTimeFormat = "20060102T150405Z"
)

// New creates a new Vault instance from the given configuration.
// If cfg.Identity is set, it reads the age key file; otherwise the caller
// must provide a passphrase-based identity via NewWithPassphrase.
func New(cfg *Config, logger *slog.Logger) (*Vault, error) {
	if cfg.VaultDir == "" {
		return nil, fmt.Errorf("vault dir is required")
	}

	v := &Vault{
		dir:    cfg.VaultDir,
		logger: logger,
	}

	if cfg.Identity != "" {
		id, err := loadIdentityFromFile(cfg.Identity)
		if err != nil {
			return nil, fmt.Errorf("load identity: %w", err)
		}
		v.identity = id
	}

	return v, nil
}

// NewWithPassphrase creates a new Vault that uses a passphrase for encryption.
func NewWithPassphrase(cfg *Config, passphrase string, logger *slog.Logger) (*Vault, error) {
	if cfg.VaultDir == "" {
		return nil, fmt.Errorf("vault dir is required")
	}

	id, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("create scrypt identity: %w", err)
	}

	return &Vault{
		dir:        cfg.VaultDir,
		identity:   id,
		passphrase: passphrase,
		logger:     logger,
	}, nil
}

// Passphrase returns the passphrase used for encryption, or empty if key-file mode.
func (v *Vault) Passphrase() string {
	return v.passphrase
}

// Create creates the vault directory if it does not already exist.
func (v *Vault) Create(ctx context.Context) error {
	if err := os.MkdirAll(v.dir, 0o700); err != nil {
		return fmt.Errorf("vault create: %w", err)
	}
	v.logger.InfoContext(ctx, "vault created",
		slog.String("dir", v.dir),
	)
	return nil
}

// Import takes an existing directory, tars and encrypts it as the first snapshot.
func (v *Vault) Import(ctx context.Context, sourcePath string) (Snapshot, error) {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return Snapshot{}, fmt.Errorf("vault import: stat source: %w", err)
	}
	if !info.IsDir() {
		return Snapshot{}, fmt.Errorf("vault import: source is not a directory: %s", sourcePath)
	}

	if err := os.MkdirAll(v.dir, 0o700); err != nil {
		return Snapshot{}, fmt.Errorf("vault import: create vault dir: %w", err)
	}
	v.logger.InfoContext(ctx, "vault dir ensured",
		slog.String("dir", v.dir),
	)

	return v.sealDir(ctx, sourcePath, "initial-import")
}

// Open decrypts the latest snapshot into a secure temporary directory.
func (v *Vault) Open(ctx context.Context) (string, Snapshot, error) {
	snapshots, err := v.List(ctx)
	if err != nil {
		return "", Snapshot{}, fmt.Errorf("vault open: %w", err)
	}
	if len(snapshots) == 0 {
		return "", Snapshot{}, fmt.Errorf("vault open: no snapshots found in %s", v.dir)
	}

	latest := snapshots[len(snapshots)-1]
	workdir, err := v.decryptSnapshot(latest.Path)
	if err != nil {
		return "", Snapshot{}, fmt.Errorf("vault open: %w", err)
	}

	v.logger.InfoContext(ctx, "vault opened",
		slog.String("snapshot", filepath.Base(latest.Path)),
		slog.String("workdir", workdir),
	)

	return workdir, latest, nil
}

// Seal tars and encrypts the workdir as a new snapshot, then removes the workdir.
func (v *Vault) Seal(ctx context.Context, workdir string, message string) (Snapshot, error) {
	if err := validateWorkdir(workdir); err != nil {
		return Snapshot{}, fmt.Errorf("vault seal: %w", err)
	}

	snap, err := v.sealDir(ctx, workdir, message)
	if err != nil {
		return Snapshot{}, err
	}

	if err := os.RemoveAll(workdir); err != nil {
		v.logger.WarnContext(ctx, "failed to clean up workdir",
			slog.String("workdir", workdir),
			slog.String("error", err.Error()),
		)
	}

	v.logger.InfoContext(ctx, "vault sealed",
		slog.String("snapshot", filepath.Base(snap.Path)),
	)

	return snap, nil
}

// Discard removes the working directory without saving a new snapshot.
func (v *Vault) Discard(ctx context.Context, workdir string) error {
	if err := validateWorkdir(workdir); err != nil {
		return fmt.Errorf("vault discard: %w", err)
	}

	if err := os.RemoveAll(workdir); err != nil {
		return fmt.Errorf("vault discard: %w", err)
	}
	v.logger.InfoContext(ctx, "vault discarded",
		slog.String("workdir", workdir),
	)
	return nil
}

// validateWorkdir checks that a workdir path looks like a locksmith-created tmpdir.
// This is a defense-in-depth measure to prevent accidental deletion of unrelated paths.
func validateWorkdir(workdir string) error {
	if workdir == "" {
		return fmt.Errorf("workdir path is empty")
	}
	base := filepath.Base(workdir)
	if !strings.HasPrefix(base, "locksmith-") {
		return fmt.Errorf("workdir %q does not look like a locksmith tmpdir (expected locksmith-* prefix)", workdir)
	}
	return nil
}

// List scans the vault directory for .tar.age files and returns them sorted by timestamp.
func (v *Vault) List(ctx context.Context) ([]Snapshot, error) {
	entries, err := os.ReadDir(v.dir)
	if err != nil {
		return nil, fmt.Errorf("vault list: read dir: %w", err)
	}

	var snapshots []Snapshot
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.age") {
			continue
		}
		snap, parseErr := parseSnapshotFilename(e.Name())
		if parseErr != nil {
			v.logger.WarnContext(ctx, "skipping unrecognized file",
				slog.String("file", e.Name()),
				slog.String("error", parseErr.Error()),
			)
			continue
		}
		snap.Path = filepath.Join(v.dir, e.Name())
		snapshots = append(snapshots, snap)
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Timestamp.Before(snapshots[j].Timestamp)
	})

	return snapshots, nil
}

// Restore decrypts a specific snapshot (by filename or prefix) into a secure tmpdir.
func (v *Vault) Restore(ctx context.Context, ref string) (string, error) {
	snapshots, err := v.List(ctx)
	if err != nil {
		return "", fmt.Errorf("vault restore: %w", err)
	}

	var match *Snapshot
	for i := range snapshots {
		base := filepath.Base(snapshots[i].Path)
		if base == ref || strings.HasPrefix(base, ref) {
			match = &snapshots[i]
			break
		}
	}
	if match == nil {
		return "", fmt.Errorf("vault restore: no snapshot matching %q", ref)
	}

	workdir, err := v.decryptSnapshot(match.Path)
	if err != nil {
		return "", fmt.Errorf("vault restore: %w", err)
	}

	v.logger.InfoContext(ctx, "vault restored",
		slog.String("snapshot", filepath.Base(match.Path)),
		slog.String("workdir", workdir),
	)

	return workdir, nil
}

// sealDir tars and encrypts a directory, writing a new timestamped .tar.age file.
func (v *Vault) sealDir(ctx context.Context, dir string, message string) (Snapshot, error) {
	_ = ctx // reserved for future cancellation support

	now := time.Now().UTC()
	filename := formatSnapshotFilename(now, message)
	outPath := filepath.Join(v.dir, filename)

	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600) //nolint:gosec // path built from vault dir + generated filename
	if err != nil {
		return Snapshot{}, fmt.Errorf("vault seal: create file: %w", err)
	}

	closeFile := true
	defer func() {
		if closeFile {
			_ = outFile.Close()
		}
	}()

	recipient, err := v.recipient()
	if err != nil {
		_ = os.Remove(outPath)
		return Snapshot{}, fmt.Errorf("vault seal: %w", err)
	}

	ageWriter, err := age.Encrypt(outFile, recipient)
	if err != nil {
		_ = os.Remove(outPath)
		return Snapshot{}, fmt.Errorf("vault seal: age encrypt: %w", err)
	}

	if err := tarDir(dir, ageWriter); err != nil {
		_ = ageWriter.Close()
		_ = os.Remove(outPath)
		return Snapshot{}, fmt.Errorf("vault seal: tar: %w", err)
	}

	if err := ageWriter.Close(); err != nil {
		_ = os.Remove(outPath)
		return Snapshot{}, fmt.Errorf("vault seal: close age writer: %w", err)
	}

	closeFile = false
	if err := outFile.Close(); err != nil {
		return Snapshot{}, fmt.Errorf("vault seal: close file: %w", err)
	}

	return Snapshot{
		Path:      outPath,
		Timestamp: now,
		Message:   message,
	}, nil
}

// decryptSnapshot decrypts a .tar.age file into a secure tmpdir.
func (v *Vault) decryptSnapshot(path string) (string, error) {
	if v.identity == nil {
		return "", fmt.Errorf("no identity configured")
	}

	inFile, err := os.Open(path) //nolint:gosec // path comes from vault directory listing
	if err != nil {
		return "", fmt.Errorf("open snapshot: %w", err)
	}
	defer func() { _ = inFile.Close() }()

	reader, err := age.Decrypt(inFile, v.identity)
	if err != nil {
		return "", fmt.Errorf("age decrypt: %w", err)
	}

	workdir, err := SecureTmpDir()
	if err != nil {
		return "", fmt.Errorf("create tmpdir: %w", err)
	}

	if err := untarToDir(reader, workdir); err != nil {
		_ = os.RemoveAll(workdir)
		return "", fmt.Errorf("untar: %w", err)
	}

	return workdir, nil
}

// recipient returns the age.Recipient corresponding to the vault's identity.
func (v *Vault) recipient() (age.Recipient, error) {
	if v.identity == nil {
		return nil, fmt.Errorf("no identity configured")
	}

	if v.passphrase != "" {
		r, err := age.NewScryptRecipient(v.passphrase)
		if err != nil {
			return nil, fmt.Errorf("create scrypt recipient: %w", err)
		}
		return r, nil
	}

	if id, ok := v.identity.(*age.X25519Identity); ok {
		return id.Recipient(), nil
	}

	return nil, fmt.Errorf("unsupported identity type: %T", v.identity)
}

// loadIdentityFromFile reads an age identity (private key) from a file.
func loadIdentityFromFile(path string) (age.Identity, error) {
	f, err := os.Open(path) //nolint:gosec // path from user config
	if err != nil {
		return nil, fmt.Errorf("open identity file: %w", err)
	}
	defer func() { _ = f.Close() }()

	identities, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("no identities found in %s", path)
	}

	return identities[0], nil
}

// shouldSkipFile returns true if the file should be excluded from tar archives.
// These are GPG runtime files that shouldn't be in snapshots.
func shouldSkipFile(name string) bool {
	switch {
	case strings.HasPrefix(name, ".#lk"):
		return true
	case name == "random_seed":
		return true
	case name == ".gpg-connect-history":
		return true
	case strings.HasPrefix(name, "S.gpg-agent"):
		return true
	default:
		return false
	}
}

// tarDir writes the contents of dir as a tar archive to w.
// File paths inside the archive are relative to dir.
func tarDir(dir string, w io.Writer) error {
	tw := tar.NewWriter(w)

	walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("relative path: %w", err)
		}
		if rel == "." {
			return nil
		}

		if shouldSkipFile(filepath.Base(path)) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("file info header for %s: %w", rel, err)
		}
		header.Name = rel

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("write header for %s: %w", rel, err)
		}

		if info.IsDir() {
			return nil
		}

		f, err := os.Open(path) //nolint:gosec // path from filepath.Walk within vault-controlled dir
		if err != nil {
			return fmt.Errorf("open %s: %w", rel, err)
		}

		_, copyErr := io.Copy(tw, f)
		closeErr := f.Close()

		if copyErr != nil {
			return fmt.Errorf("copy %s: %w", rel, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close %s: %w", rel, closeErr)
		}

		return nil
	})

	if walkErr != nil {
		_ = tw.Close()
		return walkErr
	}

	return tw.Close()
}

// untarToDir extracts a tar archive from r into dir.
func untarToDir(r io.Reader, dir string) error {
	tr := tar.NewReader(r)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}

		target := filepath.Join(dir, header.Name) //nolint:gosec // paths are created by us, traversal check follows
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dir)+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry escapes target dir: %s", header.Name)
		}

		mode := os.FileMode(header.Mode & 0o777)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, mode); err != nil { //nolint:gosec // target sanitized by path.Clean above
				return fmt.Errorf("create dir %s: %w", header.Name, err)
			}
		case tar.TypeReg:
			if err := extractFile(target, tr, mode, header.Name); err != nil {
				return err
			}
		}
	}

	return nil
}

func extractFile(target string, r io.Reader, mode os.FileMode, name string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil { //nolint:gosec // target sanitized by caller
		return fmt.Errorf("create parent dir for %s: %w", name, err)
	}

	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode) //nolint:gosec // target validated by caller
	if err != nil {
		return fmt.Errorf("create file %s: %w", name, err)
	}

	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return fmt.Errorf("write file %s: %w", name, err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close file %s: %w", name, err)
	}

	return nil
}

// parseSnapshotFilename extracts the timestamp and message from a snapshot filename.
func parseSnapshotFilename(name string) (Snapshot, error) {
	matches := snapshotFilenameRe.FindStringSubmatch(name)
	if matches == nil {
		return Snapshot{}, fmt.Errorf("invalid snapshot filename: %s", name)
	}

	t, err := time.Parse(snapshotTimeFormat, matches[1])
	if err != nil {
		return Snapshot{}, fmt.Errorf("parse timestamp in %s: %w", name, err)
	}

	return Snapshot{
		Timestamp: t,
		Message:   matches[2],
	}, nil
}

// formatSnapshotFilename creates a snapshot filename from a timestamp and message.
func formatSnapshotFilename(t time.Time, message string) string {
	return t.Format(snapshotTimeFormat) + "_" + slugify(message) + ".tar.age"
}

// slugify converts a message to a URL-safe slug for use in filenames.
func slugify(s string) string {
	var b strings.Builder
	prevDash := false

	for _, r := range strings.ToLower(s) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			prevDash = false
		case !prevDash && b.Len() > 0:
			b.WriteRune('-')
			prevDash = true
		}
	}

	result := b.String()
	return strings.TrimRight(result, "-")
}
