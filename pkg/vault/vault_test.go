package vault

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"initial import", "initial-import"},
		{"rotated subkeys 2026", "rotated-subkeys-2026"},
		{"  hello  world  ", "hello-world"},
		{"UPPER Case", "upper-case"},
		{"special!@#chars", "special-chars"},
		{"already-slugified", "already-slugified"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := slugify(tt.input)
			if got != tt.want {
				t.Errorf("slugify(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatAndParseSnapshotFilename(t *testing.T) {
	ts := time.Date(2026, 4, 1, 15, 30, 0, 0, time.UTC)
	msg := "rotated subkeys"

	filename := formatSnapshotFilename(ts, msg)
	want := "20260401T153000Z_rotated-subkeys.tar.age"
	if filename != want {
		t.Fatalf("formatSnapshotFilename() = %q, want %q", filename, want)
	}

	snap, err := parseSnapshotFilename(filename)
	if err != nil {
		t.Fatalf("parseSnapshotFilename() error: %v", err)
	}
	if !snap.Timestamp.Equal(ts) {
		t.Errorf("timestamp = %v, want %v", snap.Timestamp, ts)
	}
	if snap.Message != "rotated-subkeys" {
		t.Errorf("message = %q, want %q", snap.Message, "rotated-subkeys")
	}
}

func TestParseSnapshotFilenameInvalid(t *testing.T) {
	tests := []string{
		"not-a-snapshot.txt",
		"random.tar.age",
		"20260401T153000Z.tar.age",
		"bad_20260401T153000Z_msg.tar.age",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parseSnapshotFilename(name)
			if err == nil {
				t.Errorf("parseSnapshotFilename(%q) should have failed", name)
			}
		})
	}
}

func TestConfigSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	cfg := &Config{
		VaultDir:  "/tmp/vault",
		Identity:  "/tmp/key.txt",
		GPGBinary: "gpg2",
	}

	if err := SaveConfig(path, cfg); err != nil {
		t.Fatalf("SaveConfig() error: %v", err)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}

	if loaded.VaultDir != cfg.VaultDir {
		t.Errorf("VaultDir = %q, want %q", loaded.VaultDir, cfg.VaultDir)
	}
	if loaded.Identity != cfg.Identity {
		t.Errorf("Identity = %q, want %q", loaded.Identity, cfg.Identity)
	}
	if loaded.GPGBinary != cfg.GPGBinary {
		t.Errorf("GPGBinary = %q, want %q", loaded.GPGBinary, cfg.GPGBinary)
	}
}

func TestVaultCreateAndList(t *testing.T) {
	ctx := context.Background()
	vaultDir := t.TempDir()
	logger := testLogger()

	cfg := &Config{VaultDir: vaultDir}
	v, err := NewWithPassphrase(cfg, "test-passphrase", logger)
	if err != nil {
		t.Fatalf("NewWithPassphrase() error: %v", err)
	}

	if err := v.Create(ctx); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	snapshots, err := v.List(ctx)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(snapshots) != 0 {
		t.Errorf("expected 0 snapshots, got %d", len(snapshots))
	}
}

func TestVaultImportOpenSealDiscard(t *testing.T) {
	ctx := context.Background()
	vaultDir := t.TempDir()
	sourceDir := t.TempDir()
	logger := testLogger()

	// Create test files in source
	if err := os.WriteFile(filepath.Join(sourceDir, "test.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sourceDir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "subdir", "nested.txt"), []byte("world"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{VaultDir: vaultDir}
	v, err := NewWithPassphrase(cfg, "test-passphrase", logger)
	if err != nil {
		t.Fatalf("NewWithPassphrase() error: %v", err)
	}

	// Import
	snap, err := v.Import(ctx, sourceDir)
	if err != nil {
		t.Fatalf("Import() error: %v", err)
	}
	if snap.Message != "initial-import" {
		t.Errorf("Import message = %q, want %q", snap.Message, "initial-import")
	}

	// List should show 1 snapshot
	snapshots, err := v.List(ctx)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snapshots))
	}

	// Open
	workdir, openSnap, err := v.Open(ctx)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	defer os.RemoveAll(workdir)

	if openSnap.Path != snapshots[0].Path {
		t.Errorf("Open snapshot path = %q, want %q", openSnap.Path, snapshots[0].Path)
	}

	// Verify contents
	data, err := os.ReadFile(filepath.Join(workdir, "test.txt"))
	if err != nil {
		t.Fatalf("read test.txt: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("test.txt content = %q, want %q", string(data), "hello")
	}

	data, err = os.ReadFile(filepath.Join(workdir, "subdir", "nested.txt"))
	if err != nil {
		t.Fatalf("read subdir/nested.txt: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("subdir/nested.txt content = %q, want %q", string(data), "world")
	}

	// Modify and seal
	if err := os.WriteFile(filepath.Join(workdir, "new.txt"), []byte("new file"), 0o600); err != nil {
		t.Fatal(err)
	}

	sealSnap, err := v.Seal(ctx, workdir, "added new file")
	if err != nil {
		t.Fatalf("Seal() error: %v", err)
	}

	// Workdir should be cleaned up after seal
	if _, err := os.Stat(workdir); !os.IsNotExist(err) {
		t.Errorf("workdir should be removed after Seal")
	}

	// List should show 2 snapshots
	snapshots, err = v.List(ctx)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	// Restore the sealed snapshot by name and verify it has the new file
	workdir2, err := v.Restore(ctx, filepath.Base(sealSnap.Path))
	if err != nil {
		t.Fatalf("Restore() error: %v", err)
	}
	defer os.RemoveAll(workdir2)

	data, err = os.ReadFile(filepath.Join(workdir2, "new.txt"))
	if err != nil {
		t.Fatalf("read new.txt: %v", err)
	}
	if string(data) != "new file" {
		t.Errorf("new.txt content = %q, want %q", string(data), "new file")
	}

	// Discard
	if err := v.Discard(ctx, workdir2); err != nil {
		t.Fatalf("Discard() error: %v", err)
	}
	if _, err := os.Stat(workdir2); !os.IsNotExist(err) {
		t.Errorf("workdir should be removed after Discard")
	}
}

func TestVaultOpenNoSnapshots(t *testing.T) {
	ctx := context.Background()
	vaultDir := t.TempDir()
	logger := testLogger()

	cfg := &Config{VaultDir: vaultDir}
	v, err := NewWithPassphrase(cfg, "test-passphrase", logger)
	if err != nil {
		t.Fatalf("NewWithPassphrase() error: %v", err)
	}

	_, _, err = v.Open(ctx)
	if err == nil {
		t.Fatal("Open() should fail with no snapshots")
	}
}

func TestVaultRestoreNotFound(t *testing.T) {
	ctx := context.Background()
	vaultDir := t.TempDir()
	logger := testLogger()

	cfg := &Config{VaultDir: vaultDir}
	v, err := NewWithPassphrase(cfg, "test-passphrase", logger)
	if err != nil {
		t.Fatalf("NewWithPassphrase() error: %v", err)
	}

	_, err = v.Restore(ctx, "nonexistent")
	if err == nil {
		t.Fatal("Restore() should fail for nonexistent snapshot")
	}
}

func TestNewVaultDirRequired(t *testing.T) {
	logger := testLogger()

	_, err := New(&Config{}, logger)
	if err == nil {
		t.Fatal("New() should fail without vault dir")
	}

	_, err = NewWithPassphrase(&Config{}, "pass", logger)
	if err == nil {
		t.Fatal("NewWithPassphrase() should fail without vault dir")
	}
}

func TestVaultImportNotDirectory(t *testing.T) {
	ctx := context.Background()
	vaultDir := t.TempDir()
	logger := testLogger()

	cfg := &Config{VaultDir: vaultDir}
	v, err := NewWithPassphrase(cfg, "test-passphrase", logger)
	if err != nil {
		t.Fatal(err)
	}

	tmpFile := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(tmpFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = v.Import(ctx, tmpFile)
	if err == nil {
		t.Fatal("Import() should fail for non-directory")
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}

	tests := []struct {
		input string
		want  string
	}{
		{"~/foo", filepath.Join(home, "foo")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := expandHome(tt.input)
			if got != tt.want {
				t.Errorf("expandHome(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSecureTmpDir(t *testing.T) {
	dir, err := SecureTmpDir()
	if err != nil {
		t.Fatalf("SecureTmpDir() error: %v", err)
	}
	defer os.RemoveAll(dir)

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat tmpdir: %v", err)
	}
	if !info.IsDir() {
		t.Error("tmpdir is not a directory")
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("tmpdir permissions = %o, want 0700", info.Mode().Perm())
	}
}

func TestVaultWithIdentityFile(t *testing.T) {
	ctx := context.Background()
	vaultDir := t.TempDir()
	keyDir := t.TempDir()
	logger := testLogger()

	// Generate a key
	keyPath := filepath.Join(keyDir, "age-key.txt")
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(identity.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		VaultDir: vaultDir,
		Identity: keyPath,
	}
	v, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Create source dir
	sourceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceDir, "data.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Import
	_, err = v.Import(ctx, sourceDir)
	if err != nil {
		t.Fatalf("Import() error: %v", err)
	}

	// Open and verify
	workdir, _, err := v.Open(ctx)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	defer os.RemoveAll(workdir)

	data, err := os.ReadFile(filepath.Join(workdir, "data.txt"))
	if err != nil {
		t.Fatalf("read data.txt: %v", err)
	}
	if string(data) != "secret" {
		t.Errorf("data.txt = %q, want %q", string(data), "secret")
	}
}

func TestValidateWorkdir(t *testing.T) {
	tests := []struct {
		name    string
		workdir string
		wantErr bool
	}{
		{"valid locksmith dir", "/dev/shm/locksmith-abc123", false},
		{"valid tmp locksmith dir", "/tmp/locksmith-xyz789", false},
		{"empty path", "", true},
		{"root path", "/", true},
		{"home dir", "/home/user", true},
		{"vault dir", "/home/user/vault", true},
		{"no locksmith prefix", "/tmp/something-else", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWorkdir(tt.workdir)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateWorkdir(%q) error = %v, wantErr %v", tt.workdir, err, tt.wantErr)
			}
		})
	}
}

func TestShouldSkipFile(t *testing.T) {
	tests := []struct {
		name string
		skip bool
	}{
		{".#lk0x00007f1234567890.hostname.12345", true},
		{".#lk0x1234", true},
		{"random_seed", true},
		{".gpg-connect-history", true},
		{"S.gpg-agent", true},
		{"S.gpg-agent.browser", true},
		{"S.gpg-agent.ssh", true},
		{"pubring.kbx", false},
		{"trustdb.gpg", false},
		{"private-keys-v1.d", false},
		{"gpg.conf", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldSkipFile(tt.name)
			if got != tt.skip {
				t.Errorf("shouldSkipFile(%q) = %v, want %v", tt.name, got, tt.skip)
			}
		})
	}
}

func TestTarDirSkipsRuntimeFiles(t *testing.T) {
	sourceDir := t.TempDir()

	// Create legitimate files.
	if err := os.WriteFile(filepath.Join(sourceDir, "pubring.kbx"), []byte("keyring"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "trustdb.gpg"), []byte("trust"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create runtime files that should be skipped.
	skipFiles := []string{
		".#lk0x00007f1234567890.hostname.12345",
		"random_seed",
		".gpg-connect-history",
		"S.gpg-agent",
		"S.gpg-agent.browser",
		"S.gpg-agent.ssh",
	}
	for _, name := range skipFiles {
		if err := os.WriteFile(filepath.Join(sourceDir, name), []byte("skip"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Tar the directory.
	var buf bytes.Buffer
	if err := tarDir(sourceDir, &buf); err != nil {
		t.Fatalf("tarDir() error: %v", err)
	}

	// Read back and check which files are in the archive.
	tr := tar.NewReader(&buf)
	found := make(map[string]bool)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		found[header.Name] = true
	}

	// Legitimate files should be present.
	for _, name := range []string{"pubring.kbx", "trustdb.gpg"} {
		if !found[name] {
			t.Errorf("expected %q in archive", name)
		}
	}

	// Runtime files should be absent.
	for _, name := range skipFiles {
		if found[name] {
			t.Errorf("runtime file %q should not be in archive", name)
		}
	}
}

func TestSealRejectsInvalidWorkdir(t *testing.T) {
	ctx := context.Background()
	vaultDir := t.TempDir()
	logger := testLogger()

	cfg := &Config{VaultDir: vaultDir}
	v, err := NewWithPassphrase(cfg, "test-passphrase", logger)
	if err != nil {
		t.Fatal(err)
	}

	_, err = v.Seal(ctx, "/tmp/not-a-locksmith-dir", "test")
	if err == nil {
		t.Fatal("Seal() should reject non-locksmith workdir")
	}
}

func TestVaultWrongPassphraseRejected(t *testing.T) {
	ctx := context.Background()
	vaultDir := t.TempDir()
	sourceDir := t.TempDir()
	logger := testLogger()

	if err := os.WriteFile(filepath.Join(sourceDir, "secret.txt"), []byte("top secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create vault and import with passphrase A.
	cfg := &Config{VaultDir: vaultDir}
	v, err := NewWithPassphrase(cfg, "correct-passphrase", logger)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Import(ctx, sourceDir); err != nil {
		t.Fatalf("Import() error: %v", err)
	}

	// Try to open with passphrase B -- should fail.
	v2, err := NewWithPassphrase(cfg, "wrong-passphrase", logger)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = v2.Open(ctx)
	if err == nil {
		t.Fatal("Open() with wrong passphrase should fail")
	}
}

func TestVaultMultipleSealCycles(t *testing.T) {
	ctx := context.Background()
	vaultDir := t.TempDir()
	sourceDir := t.TempDir()
	logger := testLogger()

	if err := os.WriteFile(filepath.Join(sourceDir, "v1.txt"), []byte("version 1"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{VaultDir: vaultDir}
	v, err := NewWithPassphrase(cfg, "test-pass", logger)
	if err != nil {
		t.Fatal(err)
	}

	// Import as first snapshot.
	_, err = v.Import(ctx, sourceDir)
	if err != nil {
		t.Fatalf("Import() error: %v", err)
	}

	// Open, modify, seal.
	workdir, _, err := v.Open(ctx)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "v2.txt"), []byte("version 2"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = v.Seal(ctx, workdir, "second version")
	if err != nil {
		t.Fatalf("Seal() error: %v", err)
	}

	// Open again (should get latest), modify, seal.
	workdir2, _, err := v.Open(ctx)
	if err != nil {
		t.Fatalf("second Open() error: %v", err)
	}
	// Verify v2.txt is present from previous seal.
	data, err := os.ReadFile(filepath.Join(workdir2, "v2.txt"))
	if err != nil {
		t.Fatalf("v2.txt missing after second open: %v", err)
	}
	if string(data) != "version 2" {
		t.Errorf("v2.txt = %q, want %q", string(data), "version 2")
	}
	if err := os.WriteFile(filepath.Join(workdir2, "v3.txt"), []byte("version 3"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = v.Seal(ctx, workdir2, "third version")
	if err != nil {
		t.Fatalf("second Seal() error: %v", err)
	}

	// Should have 3 snapshots total.
	snapshots, err := v.List(ctx)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(snapshots) != 3 {
		t.Errorf("expected 3 snapshots, got %d", len(snapshots))
	}

	// Restore first snapshot -- should only have v1.txt.
	first, err := v.Restore(ctx, filepath.Base(snapshots[0].Path))
	if err != nil {
		t.Fatalf("Restore() error: %v", err)
	}
	defer os.RemoveAll(first)
	if _, err := os.Stat(filepath.Join(first, "v1.txt")); err != nil {
		t.Error("v1.txt should exist in first snapshot")
	}
	if _, err := os.Stat(filepath.Join(first, "v2.txt")); !os.IsNotExist(err) {
		t.Error("v2.txt should NOT exist in first snapshot")
	}
}

func TestDiscardRejectsInvalidWorkdir(t *testing.T) {
	ctx := context.Background()
	vaultDir := t.TempDir()
	logger := testLogger()

	cfg := &Config{VaultDir: vaultDir}
	v, err := NewWithPassphrase(cfg, "test-passphrase", logger)
	if err != nil {
		t.Fatal(err)
	}

	err = v.Discard(ctx, "/tmp/not-a-locksmith-dir")
	if err == nil {
		t.Fatal("Discard() should reject non-locksmith workdir")
	}
}

func TestVaultImportCreatesVaultDir(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	// Create a source dir with a dummy file.
	sourceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceDir, "dummy.txt"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Point vault dir to a non-existent subdirectory within a temp dir.
	parentDir := t.TempDir()
	vaultDir := filepath.Join(parentDir, "new-vault")

	// Confirm it doesn't exist yet.
	if _, err := os.Stat(vaultDir); !os.IsNotExist(err) {
		t.Fatalf("vault dir should not exist yet, got err: %v", err)
	}

	cfg := &Config{VaultDir: vaultDir}
	v, err := NewWithPassphrase(cfg, "test-passphrase", logger)
	if err != nil {
		t.Fatalf("NewWithPassphrase() error: %v", err)
	}

	// Import should succeed and create the vault dir.
	snap, err := v.Import(ctx, sourceDir)
	if err != nil {
		t.Fatalf("Import() error: %v", err)
	}
	if snap.Message != "initial-import" {
		t.Errorf("Import message = %q, want %q", snap.Message, "initial-import")
	}

	// Verify the vault dir was created with correct permissions (0700).
	info, err := os.Stat(vaultDir)
	if err != nil {
		t.Fatalf("vault dir should exist after Import: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("vault dir should be a directory")
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("vault dir permissions = %o, want 0700", info.Mode().Perm())
	}

	// Verify the snapshot can be opened (round-trip).
	workdir, _, err := v.Open(ctx)
	if err != nil {
		t.Fatalf("Open() after Import to new dir: %v", err)
	}
	defer os.RemoveAll(workdir)

	data, err := os.ReadFile(filepath.Join(workdir, "dummy.txt"))
	if err != nil {
		t.Fatalf("read dummy.txt: %v", err)
	}
	if string(data) != "data" {
		t.Errorf("dummy.txt content = %q, want %q", string(data), "data")
	}
}
